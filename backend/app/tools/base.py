"""Tool framework: typed schemas, execution context and the tool registry."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from ..core.paths import SafePathResolver
from ..db.models import AgentSession, User

__all__ = [
    "ToolContext",
    "ToolError",
    "ToolInput",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
]


class ToolError(Exception):
    """Raised when a tool cannot complete because of its own input."""

    def __init__(self, message: str, code: str = "tool_error") -> None:
        super().__init__(message)
        self.code = code


class ToolInput(BaseModel):
    """Base class for tool argument models. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


@dataclass
class ToolResult:
    """The outcome of a tool invocation."""

    ok: bool
    output: Any = None
    error: str | None = None
    error_code: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "output": self.output,
            "error": self.error,
            "error_code": self.error_code,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


@dataclass
class ToolContext:
    """Everything a tool handler needs.

    Tools never receive provider credentials, the Docker socket or the
    database session of another user.
    """

    user: User
    agent_session: AgentSession | None
    path_resolver: SafePathResolver
    artifact_store: Any = None
    sandbox: Any = None
    workspace: Any = None
    approvals: Any = None
    request_meta: dict[str, Any] = field(default_factory=dict)
    db: Any = None

    @property
    def session_id(self) -> str:
        return self.agent_session.id if self.agent_session else ""

    @property
    def user_id(self) -> str:
        return self.user.id


ToolHandler = Callable[[ToolContext, dict[str, Any]], Awaitable[ToolResult]]


@dataclass(frozen=True)
class ToolSpec:
    """The static description of a tool exposed to the model."""

    name: str
    title: str
    description: str
    parameters: Mapping[str, Any]
    handler: ToolHandler
    input_model: type[BaseModel] | None = None
    risk: str = "low"
    requires_approval: bool = False
    category: str = "general"
    mutates_state: bool = False
    version: str = "1.0.0"

    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": dict(self.parameters),
            },
        }


class ToolRegistry:
    """Holds the registered tools and validates incoming tool calls."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> ToolSpec:
        if spec.name in self._tools:
            raise ValueError(f"Tool already registered: {spec.name}")
        self._tools[spec.name] = spec
        return spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[ToolSpec]:
        return [self._tools[name] for name in self.names()]

    def json_schemas(self) -> list[dict[str, Any]]:
        return [spec.json_schema() for spec in self.all()]

    def manifest(self) -> list[dict[str, Any]]:
        """Machine readable tool manifest for the dashboard."""
        return [
            {
                "name": spec.name,
                "title": spec.title,
                "description": spec.description,
                "risk": spec.risk,
                "category": spec.category,
                "requires_approval": spec.requires_approval,
                "mutates_state": spec.mutates_state,
                "version": spec.version,
                "parameters": dict(spec.parameters),
            }
            for spec in self.all()
        ]

    @staticmethod
    def validate_arguments(spec: ToolSpec, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Validate raw arguments against the tool's input model.

        The Pydantic model is the single source of truth and is also used to
        build the JSON schema that the model sees, so an argument that the
        schema rejects can never reach a handler.
        """
        if spec.input_model is not None:
            pydantic_validate(spec.input_model, arguments)
        return dict(arguments)


def pydantic_validate[ModelT: BaseModel](model: type[ModelT], arguments: Mapping[str, Any]) -> ModelT:
    """Validate arguments with a Pydantic model, converting errors to ToolError."""
    try:
        return model.model_validate(dict(arguments))
    except ValidationError as exc:
        messages = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '(root)'}: {error['msg']}"
            for error in exc.errors()
        )
        raise ToolError(f"Invalid arguments: {messages}", "tool_invalid_arguments") from exc
