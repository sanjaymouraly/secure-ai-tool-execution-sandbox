"""Permission and inspection tools.

``request_permission`` is the sanctioned escalation path: the agent may *ask*
for a capability, but the request is only ever turned into a human approval
request - it never grants anything by itself.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import ToolContext, ToolInput, ToolResult, pydantic_validate


class RequestPermissionInput(ToolInput):
    tool: str = Field(
        min_length=1,
        max_length=64,
        description="Name of the tool the agent wants to use.",
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Exact arguments the agent intends to pass to that tool.",
    )
    reason: str = Field(
        default="",
        max_length=1000,
        description="Why the agent believes this action is required.",
    )


class ViewExecutionResultInput(ToolInput):
    execution_id: str = Field(
        max_length=64,
        description="Identifier of a previous execution to inspect. "
        "Use 'last' for the most recent execution of this session.",
    )


async def request_permission(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Ask a human approver for permission to perform an action."""
    payload = pydantic_validate(RequestPermissionInput, arguments)

    registry = context.request_meta.get("tool_registry")
    spec = registry.get(payload.tool) if registry else None
    if spec is None:
        return ToolResult(
            ok=False,
            error=f"Unknown tool '{payload.tool}'",
            error_code="unknown_tool",
        )

    from ..policy.engine import argument_signature

    signature = argument_signature(payload.tool, payload.arguments)
    existing = context.approvals.find_pending(context.session_id, payload.tool, signature)
    if existing is not None:
        return ToolResult(
            ok=True,
            output={
                "approval_id": existing.id,
                "status": existing.status,
                "message": "A matching approval request already exists and is awaiting review.",
            },
        )

    approval = context.approvals.create(
        session_id=context.session_id,
        user=context.user,
        tool_name=payload.tool,
        arguments=payload.arguments,
        reason=payload.reason or "The agent requested additional permission.",
        risk=spec.risk,
    )
    return ToolResult(
        ok=True,
        output={
            "approval_id": approval.id,
            "status": approval.status,
            "message": "Permission request submitted for human review. "
            "The action has NOT been authorised yet.",
        },
    )


async def view_execution_result(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Inspect the outcome of a previous execution in this session."""
    payload = pydantic_validate(ViewExecutionResultInput, arguments)
    execution = context.approvals.find_execution(context.session_id, payload.execution_id)
    if execution is None:
        return ToolResult(
            ok=False,
            error="No matching execution was found for this session.",
            error_code="execution_not_found",
        )
    return ToolResult(
        ok=True,
        output={
            "execution_id": execution.id,
            "tool_name": execution.tool_name,
            "status": execution.status,
            "decision": execution.decision,
            "exit_code": execution.exit_code,
            "duration_ms": execution.duration_ms,
            "output": execution.output[:100_000],
            "error": execution.error,
        },
    )
