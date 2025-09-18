"""Direct tool invocation API.

These endpoints let an operator (or an integration) call a tool directly.
They use exactly the same broker - and therefore exactly the same policy
engine, approval workflow, sandbox and audit trail - as the agent loop.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...db.models import AgentSession, User
from ...db.session import get_db
from ..deps import get_container_dep, get_current_user

router = APIRouter(tags=["tools"])


@router.get("/tools")
async def list_tools(
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Return the manifest of every registered tool."""
    return {"tools": container.tool_registry.manifest()}


@router.post("/tools/{tool_name}/invoke")
async def invoke_tool(
    tool_name: str,
    arguments: dict[str, Any] = Body(default_factory=dict),
    session_id: str | None = Body(default=None, embed=True),
    agent_id: str = Body(default="default", embed=True),
    project_id: str = Body(default="", embed=True),
    approval_id: str | None = Body(default=None, embed=True),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Invoke a tool through the full security pipeline."""
    agent_session = None
    if session_id:
        agent_session = db.get(AgentSession, session_id)
        if agent_session is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
        if agent_session.user_id != current_user.id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="This session belongs to another user."
            )

    result = await container.broker.execute(
        db,
        tool_name=tool_name,
        arguments=arguments,
        user=current_user,
        agent_session=agent_session,
        agent_id=agent_id,
        project_id=project_id,
        approval_id=approval_id,
        source="api",
    )
    return result.to_dict()
