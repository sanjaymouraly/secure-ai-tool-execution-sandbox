"""Audit event explorer, verification and export."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db.models import AuditEvent, User
from ...db.session import get_db
from ...services.audit import export_events
from ..deps import get_container_dep, get_current_user, require_admin

router = APIRouter(prefix="/audit", tags=["audit"])


def _serialize(event: AuditEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "sequence": event.sequence,
        "created_at": event.created_at.isoformat(),
        "actor_id": event.actor_id,
        "actor_role": event.actor_role,
        "session_id": event.session_id,
        "trace_id": event.trace_id,
        "action": event.action,
        "tool_name": event.tool_name,
        "outcome": event.outcome,
        "policy_version": event.policy_version,
        "policy_rule_id": event.policy_rule_id,
        "target": event.target,
        "arguments": event.redacted_arguments,
        "result_summary": event.result_summary,
        "sandbox_id": event.sandbox_id,
        "approval_decision": event.approval_decision,
        "approved_by": event.approved_by,
        "duration_ms": event.duration_ms,
        "event_hash": event.event_hash,
        "previous_hash": event.previous_hash,
    }


@router.get("/events")
async def list_events(
    action: str | None = None,
    tool_name: str | None = None,
    outcome: str | None = None,
    actor_id: str | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    since_hours: int | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Search the audit trail."""
    statement = select(AuditEvent).order_by(AuditEvent.sequence.desc())
    if action:
        statement = statement.where(AuditEvent.action == action)
    if tool_name:
        statement = statement.where(AuditEvent.tool_name == tool_name)
    if outcome:
        statement = statement.where(AuditEvent.outcome == outcome)
    if actor_id:
        statement = statement.where(AuditEvent.actor_id == actor_id)
    if session_id:
        statement = statement.where(AuditEvent.session_id == session_id)
    if trace_id:
        statement = statement.where(AuditEvent.trace_id == trace_id)
    if since_hours:
        cutoff = datetime.now(UTC) - timedelta(hours=since_hours)
        statement = statement.where(AuditEvent.created_at >= cutoff)

    total = db.execute(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1)).scalars().first()
    events = list(db.execute(statement.offset(offset).limit(limit)).scalars())
    return {
        "events": [_serialize(event) for event in events],
        "count": len(events),
        "offset": offset,
        "limit": limit,
        "latest_sequence": total.sequence if total else 0,
    }


@router.get("/verify")
async def verify_chain(
    db: Session = Depends(get_db),
    container=Depends(get_container_dep),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Verify the integrity chain of the audit trail."""
    return container.audit.verify_chain(db)


@router.get("/export")
async def export_audit(
    fmt: str = Query(default="json", pattern="^(json|csv)$"),
    limit: int = Query(default=1000, ge=1, le=10000),
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> Response:
    """Export the audit trail as JSON or CSV."""
    events = list(db.execute(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(limit)).scalars())
    content, media_type = export_events(events, fmt)
    filename = f"audit-export-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.{fmt}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/retention")
async def apply_retention(
    db: Session = Depends(get_db),
    container=Depends(get_container_dep),
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Apply the configured retention policy to the audit trail."""
    removed = container.audit.purge_expired(db, container.settings.audit_retention_days)
    container.audit.record(
        db,
        action="audit.retention",
        actor_id=current_user.id,
        actor_role=current_user.role,
        outcome="allowed",
        result_summary=f"Removed {removed} expired audit event(s)",
    )
    return {
        "status": "applied",
        "removed": removed,
        "retention_days": container.settings.audit_retention_days,
    }
