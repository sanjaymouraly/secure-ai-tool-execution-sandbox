"""Session and agent routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...db.models import AgentSession, Execution, User
from ...db.models import Message as MessageModel
from ...db.session import get_db
from ...orchestrator.agent import AgentOrchestrator
from ...providers.base import ProviderError
from ..deps import get_container_dep, get_current_user

router = APIRouter(prefix="/sessions", tags=["sessions"])


class CreateSessionRequest(BaseModel):
    title: str = Field(default="New session", max_length=255)
    provider: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    system_prompt: str | None = Field(default=None, max_length=20_000)


class RunRequest(BaseModel):
    message: str = Field(min_length=1, max_length=100_000)
    max_steps: int | None = Field(default=None, ge=1, le=50)
    provider: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)


def _serialize_session(session: AgentSession) -> dict[str, Any]:
    return {
        "id": session.id,
        "title": session.title,
        "status": session.status,
        "provider": session.provider,
        "model": session.model,
        "user_id": session.user_id,
        "project_id": session.project_id,
        "agent_id": session.agent_id,
        "steps": session.step_count,
        "tool_calls": session.tool_call_count,
        "blocked": session.blocked_count,
        "approved": session.approved_count,
        "cost_usd": round(session.total_cost_usd, 8),
        "tokens": session.total_tokens,
        "cancelled": session.cancelled,
        "error": session.error,
        "created_at": session.created_at.isoformat(),
        "updated_at": session.updated_at.isoformat(),
    }


@router.get("")
async def list_sessions(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """List the sessions of the authenticated user."""
    statement = select(AgentSession).order_by(AgentSession.updated_at.desc()).limit(min(limit, 200))
    if not current_user.is_admin:
        statement = statement.where(AgentSession.user_id == current_user.id)
    sessions = list(db.execute(statement).scalars())
    return {"sessions": [_serialize_session(session) for session in sessions]}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_session(
    payload: CreateSessionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Create an agent session."""
    from ...orchestrator.prompts import build_system_prompt

    provider = payload.provider or container.settings.default_provider
    model = payload.model or container.settings.provider_model
    session = AgentSession(
        title=payload.title,
        user_id=current_user.id,
        provider=provider,
        model=model,
        system_prompt=payload.system_prompt or build_system_prompt(),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    container.audit.record(
        db,
        action="session.create",
        actor_id=current_user.id,
        actor_role=current_user.role,
        session_id=session.id,
        outcome="allowed",
        result_summary=f"Session '{session.title}' created",
    )
    return _serialize_session(session)


@router.get("/{session_id}")
async def get_session(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Return a session with its messages and executions."""
    session = db.get(AgentSession, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your session.")

    messages = list(
        db.execute(
            select(MessageModel)
            .where(MessageModel.session_id == session_id)
            .order_by(MessageModel.sequence.asc())
        ).scalars()
    )
    executions = list(
        db.execute(
            select(Execution).where(Execution.session_id == session_id).order_by(Execution.created_at.asc())
        ).scalars()
    )
    return {
        "session": _serialize_session(session),
        "messages": [
            {
                "id": message.id,
                "role": message.role,
                "content": message.content,
                "sequence": message.sequence,
                "tool_calls": message.tool_calls,
                "tool_call_id": message.tool_call_id,
                "name": message.name,
                "is_untrusted": message.is_untrusted,
                "usage": message.usage_json,
                "created_at": message.created_at.isoformat(),
            }
            for message in messages
        ],
        "executions": [
            {
                "id": execution.id,
                "tool_name": execution.tool_name,
                "arguments": execution.redacted_arguments,
                "status": execution.status,
                "decision": execution.decision,
                "reason": execution.decision_reason,
                "policy_rule_id": execution.policy_rule_id,
                "policy_version": execution.policy_version,
                "trace_id": execution.trace_id,
                "exit_code": execution.exit_code,
                "duration_ms": execution.duration_ms,
                "output": execution.output,
                "error": execution.error,
                "sandbox_id": execution.sandbox_id,
                "sandbox_backend": execution.sandbox_backend,
                "timed_out": execution.timed_out,
                "created_at": execution.created_at.isoformat(),
            }
            for execution in executions
        ],
    }


@router.post("/{session_id}/run")
async def run_session(
    session_id: str,
    payload: RunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Run the agent loop for a session."""
    session = db.get(AgentSession, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your session.")
    if session.cancelled:
        session.cancelled = False
        db.commit()

    provider = None
    provider_name = payload.provider or session.provider or container.settings.default_provider
    model = payload.model or session.model or container.settings.provider_model
    try:
        configuration = container.default_provider_configuration()
        configuration.provider_type = provider_name
        configuration.model = model
        if provider_name != container.settings.default_provider:
            configuration.base_url = container.settings.provider_base_url
        provider = container.build_provider(configuration)
    except ProviderError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    orchestrator = AgentOrchestrator(
        provider=provider,
        tool_registry=container.tool_registry,
        broker=container.broker,
        settings=container.settings,
    )
    result = await orchestrator.run(
        db,
        session=session,
        user=current_user,
        user_message=payload.message,
        max_steps=payload.max_steps,
    )
    return result.to_dict()


@router.post("/{session_id}/cancel")
async def cancel_session(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Request cancellation of a running session."""
    session = db.get(AgentSession, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your session.")
    session.cancelled = True
    session.status = "cancelled"
    db.commit()
    return {"status": "cancelled", "session_id": session_id}


@router.delete("/{session_id}")
async def delete_session(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Delete a session and its history."""
    session = db.get(AgentSession, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your session.")
    db.delete(session)
    db.commit()
    return {"status": "deleted", "session_id": session_id}


@router.get("/{session_id}/export")
async def export_session(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Export the full trace of a session for replay."""
    session = db.get(AgentSession, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    if session.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your session.")
    messages = list(
        db.execute(
            select(MessageModel)
            .where(MessageModel.session_id == session_id)
            .order_by(MessageModel.sequence.asc())
        ).scalars()
    )
    executions = list(
        db.execute(
            select(Execution).where(Execution.session_id == session_id).order_by(Execution.created_at.asc())
        ).scalars()
    )
    return {
        "session": _serialize_session(session),
        "messages": [
            {
                "role": message.role,
                "content": message.content,
                "tool_calls": message.tool_calls,
                "tool_call_id": message.tool_call_id,
                "name": message.name,
                "sequence": message.sequence,
            }
            for message in messages
        ],
        "executions": [
            {
                "tool_name": execution.tool_name,
                "arguments": execution.arguments,
                "status": execution.status,
                "decision": execution.decision,
                "reason": execution.decision_reason,
                "policy_rule_id": execution.policy_rule_id,
                "trace_id": execution.trace_id,
                "output": execution.output,
                "error": execution.error,
            }
            for execution in executions
        ],
    }
