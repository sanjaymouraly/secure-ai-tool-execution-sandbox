"""Approval queue routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...db.models import Approval, User
from ...db.session import get_db
from ..deps import get_container_dep, get_current_user, require_approver

router = APIRouter(prefix="/approvals", tags=["approvals"])


class DecisionRequest(BaseModel):
    decision: str = Field(description="allow_once, allow_for_session or deny.")
    note: str = Field(default="", max_length=2000)


def _serialize(approval: Approval) -> dict[str, Any]:
    return {
        "id": approval.id,
        "session_id": approval.session_id,
        "tool_name": approval.tool_name,
        "arguments": approval.redacted_arguments,
        "argument_hash": approval.argument_hash,
        "reason": approval.reason,
        "risk": approval.risk,
        "status": approval.status,
        "scope": approval.scope,
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at.isoformat() if approval.decided_at else None,
        "decision_note": approval.decision_note,
        "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
        "created_at": approval.created_at.isoformat(),
    }


@router.get("")
async def list_approvals(
    status_filter: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """List approval requests."""
    approvals = container.approvals.list_all(db, limit=min(limit, 500), status=status_filter)
    return {"approvals": [_serialize(approval) for approval in approvals]}


@router.get("/pending")
async def pending_approvals(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """List the pending approval requests."""
    approvals = container.approvals.list_pending(db)
    return {"approvals": [_serialize(approval) for approval in approvals]}


@router.post("/{approval_id}/decision")
async def decide_approval(
    approval_id: str,
    payload: DecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_approver),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Allow once, allow for the session, or deny an approval request."""
    approval = container.approvals.get(db, approval_id)
    if approval is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found.")
    if approval.requested_by_user_id == current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="An approval must be decided by a different user than the one who "
            "requested it (separation of duties).",
        )
    try:
        decided = container.approvals.decide(
            db,
            approval=approval,
            decision=payload.decision,
            approver=current_user,
            note=payload.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    container.audit.record(
        db,
        action="approval.decide",
        actor_id=current_user.id,
        actor_role=current_user.role,
        session_id=decided.session_id,
        tool_name=decided.tool_name,
        outcome=decided.status,
        approval_decision=payload.decision,
        approved_by=current_user.id,
        target=decided.id,
        arguments=decided.arguments,
        result_summary=payload.note or decided.status,
    )
    return _serialize(decided)


@router.post("/grants/revoke")
async def revoke_grants(
    session_id: str = Body(default="", embed=True),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_approver),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Revoke the session grants of a session (or of every session)."""
    if session_id:
        count = container.approvals.revoke_grants(db, session_id)
        scope = session_id
    else:
        count = container.approvals.revoke_all(db)
        scope = "all"
    container.audit.record(
        db,
        action="approval.revoke_grants",
        actor_id=current_user.id,
        actor_role=current_user.role,
        outcome="allowed",
        target=scope,
        result_summary=f"Revoked {count} session grant(s)",
    )
    return {"status": "revoked", "count": count, "scope": scope}
