"""Concurrency, cancellation and lifecycle tests."""

from __future__ import annotations

import asyncio

from sqlalchemy.orm import Session

from app.core.container import Container
from app.db.models import AgentSession, User


async def test_concurrent_executions_are_isolated(
    container: Container, db: Session, analyst_user: User
) -> None:
    results = await asyncio.gather(
        *[
            container.broker.execute(
                db,
                tool_name="read_file",
                arguments={"path": "documents/report.md"},
                user=analyst_user,
            )
            for _ in range(8)
        ]
    )
    assert all(result.status == "completed" for result in results)
    trace_ids = {result.trace_id for result in results}
    assert len(trace_ids) == 8


async def test_concurrent_mixed_operations(container: Container, db: Session, analyst_user: User) -> None:
    """Allowed and denied operations run side by side without interfering."""
    tasks = []
    for index in range(5):
        tasks.append(
            container.broker.execute(
                db,
                tool_name="read_file",
                arguments={"path": "documents/report.md"},
                user=analyst_user,
            )
        )
        tasks.append(
            container.broker.execute(
                db,
                tool_name="read_file",
                arguments={"path": "protected/secret.txt"},
                user=analyst_user,
            )
        )
    results = await asyncio.gather(*tasks)
    statuses = [result.status for result in results]
    assert statuses.count("completed") == 5
    assert statuses.count("denied") == 5


async def test_sessions_are_independent(container: Container, db: Session, analyst_user: User) -> None:
    first = AgentSession(title="one", user_id=analyst_user.id)
    second = AgentSession(title="two", user_id=analyst_user.id)
    db.add_all([first, second])
    db.commit()
    db.refresh(first)
    db.refresh(second)

    await container.broker.execute(
        db,
        tool_name="read_file",
        arguments={"path": "documents/report.md"},
        user=analyst_user,
        agent_session=first,
    )
    await container.broker.execute(
        db,
        tool_name="read_file",
        arguments={"path": "documents/benign.md"},
        user=analyst_user,
        agent_session=second,
    )
    assert first.execution_count() if hasattr(first, "execution_count") else True
    from sqlalchemy import select

    from app.db.models import Execution

    executions = list(
        db.execute(select(Execution).where(Execution.session_id.in_([first.id, second.id]))).scalars()
    )
    assert len(executions) == 2
    assert {execution.session_id for execution in executions} == {first.id, second.id}


async def test_docker_backend_failure_is_not_silently_downgraded(
    container: Container, db: Session, analyst_user: User
) -> None:
    """A broken sandbox must produce a clear error, never a host fallback."""

    class BrokenBackend:
        name = "broken"
        isolated = False

        async def run(self, request):
            from app.sandbox.base import SandboxUnavailableError

            raise SandboxUnavailableError("Docker is not available: connection refused")

        async def status(self):
            from app.sandbox.base import SandboxStatus

            return SandboxStatus(name="broken", available=False, isolated=False, detail="broken")

        async def cleanup(self):
            return None

    container.set_sandbox(BrokenBackend())
    result = await container.broker.execute(
        db,
        tool_name="execute_approved_command",
        arguments={"command": "ls documents"},
        user=analyst_user,
    )
    # The policy still requires an approval first, so the action is parked
    # and never reaches the broken backend.
    assert result.status == "awaiting_approval"

    from app.core.security import hash_password
    from app.db.models import User as UserModel

    approver = UserModel(
        username="approver-for-broken",
        email="approver@test.local",
        hashed_password=hash_password("approver-password-123"),
        role="approver",
        is_active=True,
    )
    db.add(approver)
    db.commit()
    db.refresh(approver)

    parked = await container.broker.execute(
        db,
        tool_name="execute_approved_command",
        arguments={"command": "ls documents"},
        user=analyst_user,
    )
    approval = container.approvals.get(db, parked.approval_id)
    container.approvals.decide(db, approval=approval, decision="allow_once", approver=approver, note="ok")
    result = await container.broker.execute(
        db,
        tool_name="execute_approved_command",
        arguments={"command": "ls documents"},
        user=analyst_user,
        approval_id=approval.id,
    )
    assert result.status == "failed"
    assert "Docker is not available" in (result.error or "")


async def test_job_workspaces_are_cleaned_up(container: Container, db: Session, analyst_user: User) -> None:
    from pathlib import Path

    from app.core.security import hash_password
    from app.db.models import User as UserModel

    approver = UserModel(
        username="approver-cleanup",
        email="approver2@test.local",
        hashed_password=hash_password("approver-password-123"),
        role="approver",
        is_active=True,
    )
    db.add(approver)
    db.commit()
    db.refresh(approver)

    parked = await container.broker.execute(
        db,
        tool_name="execute_approved_command",
        arguments={"command": "ls documents"},
        user=analyst_user,
    )
    approval = container.approvals.get(db, parked.approval_id)
    container.approvals.decide(db, approval=approval, decision="allow_once", approver=approver, note="ok")
    await container.broker.execute(
        db,
        tool_name="execute_approved_command",
        arguments={"command": "ls documents"},
        user=analyst_user,
        approval_id=approval.id,
    )
    job_root = Path(container.settings.job_root)
    leftovers = list(job_root.glob("*")) if job_root.exists() else []
    assert leftovers == [], f"Job workspaces were not cleaned up: {leftovers}"
