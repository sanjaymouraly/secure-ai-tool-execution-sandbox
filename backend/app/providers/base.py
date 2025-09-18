"""Provider agnostic AI interfaces.

The orchestrator only ever talks to a :class:`Provider`.  Concrete adapters
translate the internal message format into the wire format of OpenAI,
Anthropic, OpenRouter, Ollama or any other OpenAI-compatible endpoint, and
translate the response back.

No adapter ever receives provider credentials that it does not need, and no
adapter ever sees the policy engine, the sandbox or the audit trail.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "Message",
    "Provider",
    "ProviderConfiguration",
    "ProviderError",
    "ProviderResponse",
    "ToolCall",
    "Usage",
]


class ProviderError(RuntimeError):
    """Raised when a provider call fails.

    ``code`` carries a stable, machine readable classification so the API can
    return a useful HTTP status without leaking provider internals.
    """

    def __init__(self, message: str, code: str = "provider_error", status: int = 502) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass
class ToolCall:
    """A tool invocation proposed by the model."""

    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "arguments": self.arguments}


@dataclass
class Usage:
    """Token accounting for a single provider call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 8),
        }


@dataclass
class Message:
    """An internal conversation message."""

    role: str  # system | user | assistant | tool
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            payload["tool_calls"] = [call.to_dict() for call in self.tool_calls]
        if self.tool_call_id:
            payload["tool_call_id"] = self.tool_call_id
        if self.name:
            payload["name"] = self.name
        return payload


@dataclass
class ProviderResponse:
    """The normalised response of a provider call."""

    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    model: str = ""
    provider: str = ""
    finish_reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "tool_calls": [call.to_dict() for call in self.tool_calls],
            "usage": self.usage.to_dict(),
            "model": self.model,
            "provider": self.provider,
            "finish_reason": self.finish_reason,
        }


@dataclass
class ProviderConfiguration:
    """Everything needed to talk to a provider."""

    provider_type: str
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    timeout_seconds: int = 120
    max_retries: int = 2
    max_tokens: int = 4096
    temperature: float = 0.2
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    options: Mapping[str, Any] = field(default_factory=dict)
    #: Force the prompt based tool calling fallback even when the model
    #: supports native tool calls (useful for testing).
    force_prompt_tools: bool = False

    def public_dict(self) -> dict[str, Any]:
        """A redacted representation that is safe to return to the browser."""
        return {
            "provider_type": self.provider_type,
            "base_url": self.base_url,
            "model": self.model,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "has_api_key": bool(self.api_key),
            "api_key_hint": (self.api_key[:3] + "..." + self.api_key[-3:]) if len(self.api_key) > 8 else "",
            "extra_header_names": sorted(self.extra_headers),
            "options": dict(self.options),
        }


class Provider(abc.ABC):
    """Abstract AI provider."""

    #: Stable provider identifier.
    name: str = "abstract"
    #: True when the provider talks a native tool-calling protocol.
    supports_native_tools: bool = True
    #: True when the provider works without any credentials.
    requires_credentials: bool = True

    def __init__(self, config: ProviderConfiguration) -> None:
        self.config = config

    @abc.abstractmethod
    async def chat(
        self,
        messages: Sequence[Message],
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        stream: bool = False,
    ) -> ProviderResponse:
        """Send a conversation to the model and return the normalised reply."""

    @abc.abstractmethod
    async def list_models(self) -> list[str]:
        """Return the model identifiers the endpoint exposes (best effort)."""

    async def test_connection(self) -> dict[str, Any]:
        """Perform a cheap round trip to verify the configuration."""
        try:
            response = await self.chat(
                [Message(role="user", content="Reply with the single word: ready")],
                tools=(),
            )
            return {
                "ok": True,
                "provider": self.name,
                "model": response.model or self.config.model,
                "message": response.text.strip()[:200] or "connected",
                "usage": response.usage.to_dict(),
            }
        except ProviderError as exc:
            return {
                "ok": False,
                "provider": self.name,
                "model": self.config.model,
                "message": str(exc),
                "error_code": exc.code,
            }
        except Exception as exc:
            return {
                "ok": False,
                "provider": self.name,
                "model": self.config.model,
                "message": f"Unexpected error: {exc}",
                "error_code": "provider_unexpected_error",
            }


def messages_to_dicts(messages: Iterable[Message]) -> list[dict[str, Any]]:
    """Convert internal messages into a plain dictionary list."""
    return [message.to_dict() for message in messages]
