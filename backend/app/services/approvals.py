"""Human approval workflow.

An approval authorises **exactly one reviewed action**.  It is bound to a
SHA-256 signature over the canonical tool name and arguments, so changing a
single argument invalidates the approval.  The approval is re-validated
immediately before execution.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.redaction import redact
from ..db.models import AgentSession, Approval, Execution, SessionGrant, User
from ..policy.engine import argument_signature

logger = logging.getLogger(__name__)

#: Valid approval decisions.
DECISIONS = ("allow_once", "allow_for_session", "deny")


class ApprovalService:
    """Create, query and decide approval requests."""

    def __init__(self, settings: Any = None) -> None:
        from ..core.config import get_settings

        self.settings = settings or get_settings()

    # ------------------------------------------------------------- create
    def create(
        self,
        db: Session,
        *,
        session_id: str | None,
        user: User,
        tool_name: str,
        arguments: Mapping[str, Any],
        reason: str,
        risk: str = "medium",
    ) -> Approval:
        """Create a pending approval request."""
        signature = argument_signature(tool_name, arguments)
        approval = Approval(
            session_id=session_id,
            requested_by_user_id=user.id,
            tool_name=tool_name,
            arguments=dict(arguments),
            redacted_arguments=redact(dict(arguments)),
            argument_hash=signature,
            reason=reason,
            risk=risk,
            status="pending",
            scope="once",
            expires_at=datetime.now(UTC) + timedelta(seconds=self.settings.policy_grant_ttl_seconds),
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)
        logger.info("Created approval %s for tool %s", approval.id, tool_name)
        return approval

    # -------------------------------------------------------------- query
    def get(self, db: Session, approval_id: str) -> Approval | None:
        """Fetch a single approval request."""
        if not approval_id:
            return None
        return db.get(Approval, approval_id)

    def find_pending(self, db: Session, session_id: str, tool_name: str, signature: str) -> Approval | None:
        """Find a pending approval for the exact same action."""
        statement = (
            select(Approval)
            .where(
                Approval.session_id == session_id,
                Approval.tool_name == tool_name,
                Approval.argument_hash == signature,
                Approval.status == "pending",
            )
            .order_by(Approval.created_at.desc())
        )
        return db.execute(statement).scalars().first()

    def find_execution(self, db: Session, session_id: str, execution_id: str) -> Execution | None:
        """Find a previous execution of this session."""
        statement = select(Execution).where(Execution.session_id == session_id)
        if execution_id and execution_id != "last":
            statement = statement.where(Execution.id == execution_id)
        statement = statement.order_by(Execution.created_at.desc()).limit(1)
        return db.execute(statement).scalars().first()

    def list_pending(self, db: Session, *, limit: int = 100) -> list[Approval]:
        statement = (
            select(Approval)
            .where(Approval.status == "pending")
            .order_by(Approval.created_at.asc())
            .limit(limit)
        )
        return list(db.execute(statement).scalars())

    def list_all(self, db: Session, *, limit: int = 200, status: str | None = None) -> list[Approval]:
        statement = select(Approval).order_by(Approval.created_at.desc()).limit(limit)
        if status:
            statement = statement.where(Approval.status == status)
        return list(db.execute(statement).scalars())

    # ------------------------------------------------------------- decide
    def decide(
        self,
        db: Session,
        *,
        approval: Approval,
        decision: str,
        approver: User,
        note: str = "",
    ) -> Approval:
        """Record a human decision on an approval request."""
        if decision not in DECISIONS:
            raise ValueError(f"Invalid decision '{decision}'. Expected one of {DECISIONS}.")
        if approval.status != "pending":
            raise ValueError(f"Approval {approval.id} has already been {approval.status}.")

        now = datetime.now(UTC)
        if approval.expires_at is not None:
            expires = approval.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires < now:
                approval.status = "expired"
                approval.decided_by = approver.id
                approval.decided_at = now
                approval.decision_note = note or "The request expired before it was reviewed."
                db.commit()
                raise ValueError(f"Approval {approval.id} has expired.")

        approval.status = "approved" if decision.startswith("allow") else "denied"
        approval.decided_by = approver.id
        approval.decided_at = now
        approval.decision_note = note
        approval.scope = "session" if decision == "allow_for_session" else "once"
        db.commit()
        db.refresh(approval)

        if decision == "allow_for_session" and approval.session_id:
            self._create_session_grant(db, approval, approver)
        logger.info("Approval %s decided by %s: %s", approval.id, approver.username, approval.status)
        return approval

    def _create_session_grant(self, db: Session, approval: Approval, approver: User) -> SessionGrant:
        """Create a session scoped grant bound to the exact reviewed action."""
        existing = (
            db.execute(
                select(SessionGrant).where(
                    SessionGrant.session_id == approval.session_id,
                    SessionGrant.tool_name == approval.tool_name,
                    SessionGrant.argument_hash == approval.argument_hash,
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            existing.expires_at = datetime.now(UTC) + timedelta(
                seconds=self.settings.policy_grant_ttl_seconds
            )
            existing.uses_remaining = -1
            db.commit()
            return existing

        grant = SessionGrant(
            session_id=approval.session_id or "",
            tool_name=approval.tool_name,
            argument_hash=approval.argument_hash,
            granted_by=approver.id,
            expires_at=datetime.now(UTC) + timedelta(seconds=self.settings.policy_grant_ttl_seconds),
            uses_remaining=-1,
        )
        db.add(grant)
        db.commit()
        db.refresh(grant)
        return grant

    # ------------------------------------------------------------- grants
    def session_grants(self, db: Session, session_id: str) -> list[SessionGrant]:
        """Return the active grants of a session."""
        if not session_id:
            return []
        statement = select(SessionGrant).where(SessionGrant.session_id == session_id)
        return list(db.execute(statement).scalars())

    def revoke_grants(self, db: Session, session_id: str) -> int:
        """Revoke every grant of a session."""
        grants = self.session_grants(db, session_id)
        for grant in grants:
            db.delete(grant)
        db.commit()
        return len(grants)

    def revoke_all(self, db: Session) -> int:
        """Revoke every grant in the system (administrator action)."""
        grants = list(db.execute(select(SessionGrant)).scalars())
        for grant in grants:
            db.delete(grant)
        db.commit()
        return len(grants)

    # --------------------------------------------------------------- usage
    def approved_execution_allowed(
        self,
        db: Session,
        *,
        approval: Approval,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> tuple[bool, str]:
        """Re-validate an approval immediately before execution.

        The approval must still be approved, must not have expired and must
        cover exactly the action that is about to run.
        """
        if approval.status != "approved":
            return False, f"Approval {approval.id} is '{approval.status}'."
        if approval.tool_name != tool_name:
            return False, (f"Approval {approval.id} covers '{approval.tool_name}', not '{tool_name}'.")
        if approval.expires_at is not None:
            expires = approval.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires < datetime.now(UTC):
                return False, f"Approval {approval.id} has expired."
        expected = argument_signature(tool_name, arguments)
        if expected != approval.argument_hash:
            return False, (
                f"Approval {approval.id} was granted for different arguments; "
                "an approval never authorises a broader action than the one reviewed."
            )
        return True, "Approval covers this exact action."


def session_summary(session: AgentSession) -> dict[str, Any]:
    """Summarise a session for the dashboard."""
    return {
        "id": session.id,
        "title": session.title,
        "status": session.status,
        "steps": session.step_count,
        "tool_calls": session.tool_call_count,
        "blocked": session.blocked_count,
        "approved": session.approved_count,
        "cost_usd": round(session.total_cost_usd, 6),
        "tokens": session.total_tokens,
    }
