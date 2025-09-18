"""Approved workspace browsing.

The workspace explorer uses the *same* path resolver and the *same* policy
engine as the agent tools, so an operator sees exactly what an agent is
allowed to see.  Files that the policy denies (for example anything under
``protected/``) are reported as denied rather than silently hidden.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ...core.paths import PathError
from ...db.models import User
from ...db.session import get_db
from ..deps import get_container_dep, get_current_user

router = APIRouter(prefix="/workspace", tags=["workspace"])


@router.get("")
async def browse(
    path: str = Query(default=".", max_length=1024),
    recursive: bool = Query(default=False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """List the contents of an approved directory."""
    decision = container.policy_engine.evaluate(
        "list_files",
        {"path": path},
        user_id=current_user.id,
        role=current_user.role,
    )
    if not decision.allowed:
        return {
            "path": path,
            "allowed": False,
            "decision": decision.to_dict(),
            "entries": [],
        }
    try:
        entries = container.workspace.list_directory(
            path, recursive=recursive, max_entries=container.settings.max_list_entries
        )
    except PathError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {
        "path": path,
        "allowed": True,
        "decision": decision.to_dict(),
        "entries": entries,
    }


@router.get("/file")
async def read_workspace_file(
    path: str = Query(min_length=1, max_length=1024),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Read an approved workspace file."""
    decision = container.policy_engine.evaluate(
        "read_file",
        {"path": path},
        user_id=current_user.id,
        role=current_user.role,
    )
    if not decision.allowed:
        return {
            "path": path,
            "allowed": False,
            "decision": decision.to_dict(),
            "content": None,
        }
    try:
        content = container.workspace.read_text(path, max_bytes=container.settings.max_workspace_file_bytes)
    except PathError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {
        "path": path,
        "allowed": True,
        "decision": decision.to_dict(),
        "content": content,
        "bytes": len(content.encode("utf-8")),
    }
