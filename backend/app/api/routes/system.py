"""System routes: health, readiness, metrics and the dashboard overview."""

from __future__ import annotations

import platform
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...db.models import AuditEvent, Execution, UsageRecord, User
from ...db.session import get_db
from ..deps import get_container_dep, get_current_user

router = APIRouter(tags=["system"])

STARTED_AT = time.time()


@router.get("/health")
async def health(container=Depends(get_container_dep)) -> dict[str, Any]:
    """Liveness probe. Always answers as long as the process is running."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(UTC).isoformat(),
        "service": get_settings().app_name,
        "version": get_settings().app_version,
        "uptime_seconds": round(time.time() - STARTED_AT, 2),
    }


@router.get("/ready")
async def ready(
    response: Response,
    db: Session = Depends(get_db),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Readiness probe: checks the database and the sandbox backend."""
    database_ok = True
    try:
        db.execute(select(func.count()).select_from(Execution)).scalar()
    except Exception:
        database_ok = False
        response.status_code = 503

    sandbox_status = await container.sandbox.status()
    ready_now = database_ok and sandbox_status.available

    return {
        "status": "ready" if ready_now else "degraded",
        "database": "ok" if database_ok else "unavailable",
        "sandbox": sandbox_status.to_dict(),
        "policy_version": container.policy_engine.version,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/system/info")
async def system_info(_: User = Depends(get_current_user)) -> dict[str, Any]:
    """Return static information about the deployment."""
    settings = get_settings()
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "auth_mode": settings.auth_mode,
        "sandbox_backend": settings.sandbox_backend,
        "workspace_root": str(settings.workspace_root),
        "uptime_seconds": round(time.time() - STARTED_AT, 2),
        "api_prefix": settings.api_prefix,
    }


@router.get("/overview")
async def overview(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Return the aggregated metrics for the dashboard."""
    settings = get_settings()
    now = datetime.now(UTC)
    day_ago = now - timedelta(hours=24)

    total_executions = db.execute(select(func.count()).select_from(Execution)).scalar() or 0
    denied = (
        db.execute(select(func.count()).select_from(Execution).where(Execution.status == "denied")).scalar()
        or 0
    )
    completed = (
        db.execute(
            select(func.count()).select_from(Execution).where(Execution.status == "completed")
        ).scalar()
        or 0
    )
    failed = (
        db.execute(select(func.count()).select_from(Execution).where(Execution.status == "failed")).scalar()
        or 0
    )
    awaiting = (
        db.execute(
            select(func.count()).select_from(Execution).where(Execution.status == "awaiting_approval")
        ).scalar()
        or 0
    )
    timed_out = (
        db.execute(select(func.count()).select_from(Execution).where(Execution.timed_out.is_(True))).scalar()
        or 0
    )

    recent = list(db.execute(select(Execution).order_by(Execution.created_at.desc()).limit(15)).scalars())
    tool_usage = {
        row[0]: row[1]
        for row in db.execute(
            select(Execution.tool_name, func.count())
            .group_by(Execution.tool_name)
            .order_by(func.count().desc())
        ).all()
    }
    outcomes = {
        row[0]: row[1]
        for row in db.execute(select(Execution.status, func.count()).group_by(Execution.status)).all()
    }
    total_cost = (
        db.execute(select(func.coalesce(func.sum(UsageRecord.estimated_cost_usd), 0.0))).scalar() or 0.0
    )
    total_tokens = db.execute(select(func.coalesce(func.sum(UsageRecord.total_tokens), 0))).scalar() or 0
    audit_total = db.execute(select(func.count()).select_from(AuditEvent)).scalar() or 0
    last_24h = (
        db.execute(
            select(func.count()).select_from(Execution).where(Execution.created_at >= day_ago)
        ).scalar()
        or 0
    )

    return {
        "generated_at": now.isoformat(),
        "executions": {
            "total": total_executions,
            "completed": completed,
            "denied": denied,
            "failed": failed,
            "awaiting_approval": awaiting,
            "timed_out": timed_out,
            "last_24h": last_24h,
            "by_tool": tool_usage,
            "by_outcome": outcomes,
        },
        "audit": {"total_events": audit_total},
        "usage": {
            "total_cost_usd": round(float(total_cost), 6),
            "total_tokens": int(total_tokens),
            "session_budget_usd": settings.budget_session_usd,
            "daily_budget_usd": settings.budget_daily_usd,
        },
        "policy": {
            "version": container.policy_engine.version,
            "revision": container.policy_engine.revision,
            "rules": len(container.policy_engine.document.rules),
        },
        "provider": {
            "default": settings.default_provider,
            "model": settings.provider_model,
        },
        "recent_executions": [
            {
                "id": execution.id,
                "tool_name": execution.tool_name,
                "status": execution.status,
                "decision": execution.decision,
                "reason": execution.decision_reason,
                "duration_ms": execution.duration_ms,
                "created_at": execution.created_at.isoformat(),
                "trace_id": execution.trace_id,
            }
            for execution in recent
        ],
    }


@router.get("/metrics")
async def metrics(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Expose simple application metrics in JSON form."""
    settings = get_settings()
    if not settings.metrics_enabled:
        return {"enabled": False}
    total = db.execute(select(func.count()).select_from(Execution)).scalar() or 0
    denied = (
        db.execute(select(func.count()).select_from(Execution).where(Execution.status == "denied")).scalar()
        or 0
    )
    return {
        "enabled": True,
        "saxis_executions_total": total,
        "saxis_executions_denied_total": denied,
        "saxis_uptime_seconds": round(time.time() - STARTED_AT, 2),
    }
