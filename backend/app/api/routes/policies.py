"""Policy document management.

Only administrators may read or modify the policy document, and every change
is versioned and audited.
"""

from __future__ import annotations

import json
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...core.config import get_settings
from ...db.models import PolicyDocument, User
from ...db.session import get_db
from ...policy.engine import PolicyEngine, PolicyLoadError
from ...policy.schema import PolicyDocument as PolicySchema
from ..deps import get_container_dep, get_current_user, require_admin

router = APIRouter(prefix="/policies", tags=["policy"])


class PolicyUpdateRequest(BaseModel):
    """A replacement policy document."""

    content: dict[str, Any] = Field(description="The complete policy document.")
    notes: str = Field(default="", max_length=2000, description="Why the policy was changed.")


@router.get("/current")
async def get_current_policy(
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Return the active policy document and its evaluation order."""
    engine = container.policy_engine
    return {
        "version": engine.version,
        "revision": engine.revision,
        "name": engine.document.name,
        "description": engine.document.description,
        "defaults": engine.document.defaults.model_dump(mode="json"),
        "rules": engine.rules(),
        "tool_risk": engine.document.tool_risk,
        "content": engine.document.model_dump(mode="json"),
    }


@router.get("/history")
async def policy_history(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> dict[str, Any]:
    """Return the stored policy versions."""
    from sqlalchemy import select

    documents = list(
        db.execute(
            select(PolicyDocument).order_by(PolicyDocument.created_at.desc()).limit(min(limit, 200))
        ).scalars()
    )
    return {
        "versions": [
            {
                "id": document.id,
                "version": document.version,
                "revision": document.revision,
                "name": document.name,
                "created_at": document.created_at.isoformat(),
                "created_by": document.created_by,
                "is_active": document.is_active,
                "notes": document.notes,
                "content_hash": document.content_hash,
            }
            for document in documents
        ]
    }


@router.post("/current", status_code=status.HTTP_200_OK)
async def update_policy(
    payload: PolicyUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Replace the active policy document.

    The document is validated against the strict schema before it is stored
    and installed.  An invalid document is rejected and the running policy is
    left untouched.
    """
    settings = get_settings()
    try:
        document = PolicySchema.model_validate(payload.content)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"The policy document failed schema validation: {exc}",
        ) from exc

    try:
        engine = PolicyEngine(
            document,
            path_resolver=container.path_resolver,
            command_allowlist=container.command_allowlist,
        )
    except PolicyLoadError as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    content = document.model_dump(mode="json")
    serialized = yaml.safe_dump(content, sort_keys=False, allow_unicode=True)
    backup = settings.policy_file.with_suffix(".yaml.bak")
    if settings.policy_file.exists():
        backup.write_text(settings.policy_file.read_text(encoding="utf-8"), encoding="utf-8")
    settings.policy_file.parent.mkdir(parents=True, exist_ok=True)
    settings.policy_file.write_text(serialized, encoding="utf-8")

    import hashlib

    content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    for existing in db.query(PolicyDocument).filter(PolicyDocument.is_active.is_(True)).all():
        existing.is_active = False
    db.add(
        PolicyDocument(
            version=document.version,
            revision=document.revision,
            name=document.name,
            content=content,
            content_hash=content_hash,
            is_active=True,
            created_by=current_user.id,
            notes=payload.notes,
        )
    )
    db.commit()

    container.set_policy_engine(engine)
    container.audit.record(
        db,
        action="policy.update",
        actor_id=current_user.id,
        actor_role=current_user.role,
        outcome="allowed",
        policy_version=document.version,
        policy_rule_id=f"revision:{document.revision}",
        target=str(settings.policy_file),
        arguments={"revision": document.revision, "rules": len(document.rules)},
        result_summary=f"Policy updated to version {document.version} revision {document.revision}",
    )

    return {
        "status": "updated",
        "version": document.version,
        "revision": document.revision,
        "rules": len(document.rules),
        "content_hash": content_hash,
    }


@router.post("/reload")
async def reload_policy(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Re-read the policy document from disk."""
    try:
        engine = container.reload_policy()
    except PolicyLoadError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    container.audit.record(
        db,
        action="policy.reload",
        actor_id=current_user.id,
        actor_role=current_user.role,
        outcome="allowed",
        policy_version=engine.version,
        result_summary="Policy reloaded from disk",
    )
    return {"status": "reloaded", "version": engine.version, "revision": engine.revision}


@router.post("/validate")
async def validate_policy(
    payload: PolicyUpdateRequest,
    container=Depends(get_container_dep),
    _: User = Depends(require_admin),
) -> dict[str, Any]:
    """Validate a policy document without installing it."""
    try:
        document = PolicySchema.model_validate(payload.content)
    except Exception as exc:
        return {"valid": False, "error": str(exc)}
    engine = PolicyEngine(
        document,
        path_resolver=container.path_resolver,
        command_allowlist=container.command_allowlist,
    )
    return {
        "valid": True,
        "version": engine.version,
        "revision": engine.revision,
        "rules": len(engine.document.rules),
        "evaluation_order": [rule["id"] for rule in engine.rules()],
    }


@router.get("/export")
async def export_policy(
    container=Depends(get_container_dep), _: User = Depends(require_admin)
) -> dict[str, Any]:
    """Export the active policy document."""
    engine = container.policy_engine
    content = engine.document.model_dump(mode="json")
    return {
        "filename": f"policy-v{engine.version}-r{engine.revision}.yaml",
        "content": yaml.safe_dump(content, sort_keys=False, allow_unicode=True),
        "json": json.dumps(content, indent=2),
    }
