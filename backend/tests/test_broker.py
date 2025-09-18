"""Integration tests for the execution broker.

These tests use the real policy engine, the real sandbox and the real audit
trail.  Only the AI provider is mocked.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.container import Container
from app.db.models import AgentSession, User


async def _invoke(container: Container, db: Session, user: User, tool: str, arguments: dict, **kwargs):
    return await container.broker.execute(db, tool_name=tool, arguments=arguments, user=user, **kwargs)


async def test_allowed_read_is_completed(container: Container, db: Session, analyst_user: User) -> None:
    result = await _invoke(container, db, analyst_user, "read_file", {"path": "documents/report.md"})
    assert result.status == "completed"
    assert result.decision.allowed
    assert "Latency" in result.execution.output


async def test_protected_read_is_denied(container: Container, db: Session, analyst_user: User) -> None:
    result = await _invoke(container, db, analyst_user, "read_file", {"path": "protected/secret.txt"})
    assert result.status == "denied"
    assert not result.decision.allowed
    assert result.decision.rule_id == "deny-protected-workspace-paths"


async def test_traversal_is_denied(container: Container, db: Session, analyst_user: User) -> None:
    result = await _invoke(container, db, analyst_user, "read_file", {"path": "../../etc/passwd"})
    assert result.status == "denied"
    assert result.decision.source == "guard"


async def test_symlink_escape_is_denied(container: Container, db: Session, analyst_user: User) -> None:
    result = await _invoke(container, db, analyst_user, "read_file", {"path": "escape-link.txt"})
    assert result.status == "denied"


async def test_symlink_to_protected_file_is_denied(
    container: Container, db: Session, analyst_user: User
) -> None:
    result = await _invoke(container, db, analyst_user, "read_file", {"path": "link-to-secret.txt"})
    assert result.status == "denied"
    assert result.decision.rule_id == "deny-protected-workspace-paths"


async def test_unknown_tool_is_denied(container: Container, db: Session, analyst_user: User) -> None:
    result = await _invoke(container, db, analyst_user, "rm_rf", {"path": "/"})
    assert result.status == "denied"
    assert result.decision.rule_id == "tool:unknown"


async def test_unknown_argument_is_rejected(container: Container, db: Session, analyst_user: User) -> None:
    result = await _invoke(
        container,
        db,
        analyst_user,
        "read_file",
        {"path": "documents/report.md", "sudo": True},
    )
    assert result.status == "denied"
    assert result.decision.rule_id == "guard:tool_invalid_arguments"


async def test_command_requires_approval(container: Container, db: Session, analyst_user: User) -> None:
    result = await _invoke(
        container, db, analyst_user, "execute_approved_command", {"command": "ls documents"}
    )
    assert result.status == "awaiting_approval"
    assert result.approval_required
    assert result.approval_id


async def test_approved_command_runs(
    container: Container, db: Session, analyst_user: User, approver_user: User
) -> None:
    first = await _invoke(
        container, db, analyst_user, "execute_approved_command", {"command": "ls documents"}
    )
    assert first.status == "awaiting_approval"

    approval = container.approvals.get(db, first.approval_id)
    assert approval is not None
    container.approvals.decide(
        db, approval=approval, decision="allow_once", approver=approver_user, note="ok"
    )

    second = await _invoke(
        container,
        db,
        analyst_user,
        "execute_approved_command",
        {"command": "ls documents"},
        approval_id=approval.id,
    )
    assert second.status == "completed", second.error
    assert second.execution.exit_code == 0
    assert second.execution.sandbox_backend in {"docker", "local-simulated"}


async def test_approval_scope_cannot_be_widened(
    container: Container, db: Session, analyst_user: User, approver_user: User
) -> None:
    first = await _invoke(
        container, db, analyst_user, "execute_approved_command", {"command": "ls documents"}
    )
    approval = container.approvals.get(db, first.approval_id)
    container.approvals.decide(
        db, approval=approval, decision="allow_once", approver=approver_user, note="ok"
    )

    widened = await _invoke(
        container,
        db,
        analyst_user,
        "execute_approved_command",
        {"command": "ls protected"},
        approval_id=approval.id,
    )
    assert widened.status == "denied"
    assert "different arguments" in (widened.decision.reason or "")


async def test_session_grant_allows_repeat(
    container: Container, db: Session, analyst_user: User, approver_user: User
) -> None:
    session = AgentSession(title="grant test", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    first = await _invoke(
        container,
        db,
        analyst_user,
        "execute_approved_command",
        {"command": "ls documents"},
        agent_session=session,
    )
    approval = container.approvals.get(db, first.approval_id)
    container.approvals.decide(
        db, approval=approval, decision="allow_for_session", approver=approver_user, note="ok"
    )

    second = await _invoke(
        container,
        db,
        analyst_user,
        "execute_approved_command",
        {"command": "ls documents"},
        agent_session=session,
    )
    assert second.status == "completed", second.error
    assert second.decision.source == "grant"


async def test_revoked_grant_blocks_execution(
    container: Container, db: Session, analyst_user: User, approver_user: User
) -> None:
    session = AgentSession(title="revoke test", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    first = await _invoke(
        container,
        db,
        analyst_user,
        "execute_approved_command",
        {"command": "ls documents"},
        agent_session=session,
    )
    approval = container.approvals.get(db, first.approval_id)
    container.approvals.decide(
        db, approval=approval, decision="allow_for_session", approver=approver_user, note="ok"
    )
    container.approvals.revoke_grants(db, session.id)

    third = await _invoke(
        container,
        db,
        analyst_user,
        "execute_approved_command",
        {"command": "ls documents"},
        agent_session=session,
    )
    assert third.status == "awaiting_approval"


async def test_audit_event_is_written(container: Container, db: Session, analyst_user: User) -> None:
    from sqlalchemy import select

    from app.db.models import AuditEvent

    await _invoke(container, db, analyst_user, "read_file", {"path": "documents/report.md"})
    events = list(db.execute(select(AuditEvent)).scalars())
    assert events
    event = events[-1]
    assert event.tool_name == "read_file"
    assert event.outcome == "completed"
    assert event.event_hash


async def test_protected_file_is_unchanged_after_denial(
    container: Container, db: Session, analyst_user: User
) -> None:
    protected = Path(container.settings.workspace_root) / "protected" / "secret.txt"
    before = hashlib.sha256(protected.read_bytes()).hexdigest()

    await _invoke(container, db, analyst_user, "read_file", {"path": "protected/secret.txt"})
    await _invoke(
        container,
        db,
        analyst_user,
        "create_artifact",
        {"name": "stolen.txt", "content": protected.read_text()},
    )

    after = hashlib.sha256(protected.read_bytes()).hexdigest()
    assert before == after


async def test_sandboxed_python_runs_in_isolation(
    container: Container, db: Session, analyst_user: User, approver_user: User
) -> None:
    first = await _invoke(
        container,
        db,
        analyst_user,
        "run_python_sandboxed",
        {"code": "print('inside-sandbox')"},
    )
    assert first.status == "awaiting_approval"
    approval = container.approvals.get(db, first.approval_id)
    container.approvals.decide(
        db, approval=approval, decision="allow_once", approver=approver_user, note="ok"
    )
    second = await _invoke(
        container,
        db,
        analyst_user,
        "run_python_sandboxed",
        {"code": "print('inside-sandbox')"},
        approval_id=approval.id,
    )
    assert second.status == "completed", second.error
    assert "inside-sandbox" in second.execution.output


async def test_artifact_round_trip(
    container: Container, db: Session, analyst_user: User, approver_user: User
) -> None:
    session = AgentSession(title="artifact", user_id=analyst_user.id)
    db.add(session)
    db.commit()
    db.refresh(session)

    first = await _invoke(
        container,
        db,
        analyst_user,
        "create_artifact",
        {"name": "note.txt", "content": "hello"},
        agent_session=session,
    )
    assert first.status == "awaiting_approval"
    approval = container.approvals.get(db, first.approval_id)
    container.approvals.decide(
        db, approval=approval, decision="allow_once", approver=approver_user, note="ok"
    )
    created = await _invoke(
        container,
        db,
        analyst_user,
        "create_artifact",
        {"name": "note.txt", "content": "hello"},
        agent_session=session,
        approval_id=approval.id,
    )
    assert created.status == "completed", created.error

    read = await _invoke(
        container, db, analyst_user, "read_artifact", {"name": "note.txt"}, agent_session=session
    )
    assert read.status == "completed"
    assert "hello" in read.execution.output
