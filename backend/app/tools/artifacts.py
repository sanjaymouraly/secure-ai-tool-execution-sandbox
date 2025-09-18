"""Artifact tools: create and read agent generated outputs."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import ToolContext, ToolInput, ToolResult, pydantic_validate


class CreateArtifactInput(ToolInput):
    name: str = Field(
        min_length=1,
        max_length=128,
        description="Artifact file name. Letters, digits, dot, dash and underscore only.",
    )
    content: str = Field(description="UTF-8 text content of the artifact.")
    content_type: str = Field(default="text/plain", max_length=128, description="MIME type of the artifact.")


class ReadArtifactInput(ToolInput):
    name: str = Field(min_length=1, max_length=128, description="Name of the artifact to read.")


async def create_artifact(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Store a new artifact produced by the agent."""
    payload = pydantic_validate(CreateArtifactInput, arguments)
    try:
        artifact = context.artifact_store.write(
            context.session_id,
            payload.name,
            payload.content,
            content_type=payload.content_type,
        )
    except ValueError as exc:
        return ToolResult(ok=False, error=str(exc), error_code="artifact_rejected")
    return ToolResult(ok=True, output=artifact.to_dict())


async def read_artifact(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Read an artifact that was created earlier in this session."""
    payload = pydantic_validate(ReadArtifactInput, arguments)
    try:
        artifact = context.artifact_store.read(context.session_id, payload.name)
    except FileNotFoundError as exc:
        return ToolResult(ok=False, error=str(exc), error_code="artifact_not_found")
    except ValueError as exc:
        return ToolResult(ok=False, error=str(exc), error_code="artifact_rejected")
    try:
        content = artifact.path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return ToolResult(ok=False, error=str(exc), error_code="artifact_read_failed")
    return ToolResult(
        ok=True,
        output={"name": artifact.name, "content": content, **artifact.to_dict()},
    )
