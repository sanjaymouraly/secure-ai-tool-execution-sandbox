"""Execution history routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db.models import Execution, User
from ...db.session import get_db
from ..deps import get_current_user

router = APIRouter(prefix="/executions", tags=["executions"])


def _serialize(execution: Execution) -> dict[str, Any]:
    return {
        "id": execution.id,
        "session_id": execution.session_id,
        "trace_id": execution.trace_id,
        "tool_name": execution.tool_name,
        "arguments": execution.redacted_arguments,
        "status": execution.status,
        "decision": execution.decision,
        "reason": execution.decision_reason,
        "policy_rule_id": execution.policy_rule_id,
        "policy_version": execution.policy_version,
        "approval_id": execution.approval_id,
        "approved_by": execution.approved_by,
        "output": execution.output,
        "error": execution.error,
        "exit_code": execution.exit_code,
        "duration_ms": execution.duration_ms,
        "cpu_seconds": execution.cpu_seconds,
        "memory_peak_mb": execution.memory_peak_mb,
        "output_bytes": execution.output_bytes,
        "sandbox_id": execution.sandbox_id,
        "sandbox_backend": execution.sandbox_backend,
        "timed_out": execution.timed_out,
        "truncated": execution.truncated,
        "step_index": execution.step_index,
        "created_at": execution.created_at.isoformat(),
    }


@router.get("")
async def list_executions(
    status_filter: str | None = Query(default=None, alias="status"),
    tool_name: str | None = None,
    session_id: str | None = None,
    decision: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """List the recorded tool executions."""
    statement = select(Execution).order_by(Execution.created_at.desc())
    if status_filter:
        statement = statement.where(Execution.status == status_filter)
    if tool_name:
        statement = statement.where(Execution.tool_name == tool_name)
    if session_id:
        statement = statement.where(Execution.session_id == session_id)
    if decision:
        statement = statement.where(Execution.decision == decision)

    executions = list(db.execute(statement.offset(offset).limit(limit)).scalars())
    return {
        "executions": [_serialize(execution) for execution in executions],
        "count": len(executions),
        "offset": offset,
        "limit": limit,
    }


@router.get("/{execution_id}")
async def get_execution(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Return a single execution with its full output."""
    execution = db.get(Execution, execution_id)
    if execution is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found.")
    return _serialize(execution)
