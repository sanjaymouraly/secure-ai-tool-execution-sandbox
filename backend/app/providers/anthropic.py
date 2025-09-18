"""Anthropic Claude provider adapter.

Implements the Anthropic Messages API (``/v1/messages``) including native
tool use.  The API key is only ever sent to the configured Anthropic base
URL; it is never written to the database in clear text, never logged and
never handed to a sandbox worker.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from .base import Message, Provider, ProviderConfiguration, ProviderError, ProviderResponse, ToolCall, Usage

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.anthropic.com"
API_VERSION = "2023-06-01"


class AnthropicProvider(Provider):
    """Adapter for the Anthropic Claude Messages API."""

    name = "anthropic"
    supports_native_tools = True

    def __init__(self, config: ProviderConfiguration) -> None:
        super().__init__(config)
        self.provider_type = "anthropic"
        self.base_url = (config.base_url or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = config.api_key
        if not self.api_key:
            raise ProviderError(
                "The Anthropic provider requires an API key.",
                "provider_missing_credentials",
                status=400,
            )
        self.api_version = str(config.options.get("api_version") or API_VERSION)

    # ------------------------------------------------------------- helpers
    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": self.api_version,
        }
        headers.update(dict(self.config.extra_headers or {}))
        return headers

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    # ---------------------------------------------------------------- chat
    async def chat(
        self,
        messages: Sequence[Message],
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        stream: bool = False,
    ) -> ProviderResponse:
        payload = self._build_payload(messages, tools)
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(self._url("/v1/messages"), headers=self._headers(), json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"Anthropic did not respond within {self.config.timeout_seconds}s.",
                "provider_timeout",
                status=504,
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"Could not reach Anthropic: {exc}", "provider_unreachable", status=502
            ) from exc

        if response.status_code >= 400:
            message = self._extract_error(response)
            code = "provider_http_error"
            if response.status_code in (401, 403):
                code = "provider_unauthorized"
            elif response.status_code == 429:
                code = "provider_rate_limited"
            elif response.status_code == 400:
                code = "provider_bad_request"
            raise ProviderError(
                f"Anthropic returned HTTP {response.status_code}: {message}",
                code,
                status=502 if response.status_code >= 500 else response.status_code,
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderError(
                "Anthropic returned a response that is not valid JSON.",
                "provider_invalid_response",
            ) from exc

        return self._parse_response(data)

    def _build_payload(
        self, messages: Sequence[Message], tools: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        system_parts: list[str] = []
        conversation: list[dict[str, Any]] = []

        for message in messages:
            if message.role == "system":
                system_parts.append(message.content)
                continue
            if message.role == "tool":
                conversation.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": message.tool_call_id or "",
                                "content": message.content,
                            }
                        ],
                    }
                )
                continue
            if message.role == "assistant" and message.tool_calls:
                blocks: list[dict[str, Any]] = []
                if message.content:
                    blocks.append({"type": "text", "text": message.content})
                for call in message.tool_calls:
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": call.id,
                            "name": call.name,
                            "input": call.arguments,
                        }
                    )
                conversation.append({"role": "assistant", "content": blocks})
                continue
            conversation.append({"role": message.role, "content": message.content})

        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": conversation,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if tools:
            payload["tools"] = [
                {
                    "name": tool.get("function", tool).get("name"),
                    "description": tool.get("function", tool).get("description", ""),
                    "input_schema": tool.get("function", tool).get("parameters", {"type": "object"}),
                }
                for tool in tools
            ]
        options = dict(self.config.options or {})
        payload.update({key: value for key, value in options.items() if key not in payload})
        return payload

    def _parse_response(self, data: Mapping[str, Any]) -> ProviderResponse:
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in data.get("content") or []:
            if not isinstance(block, Mapping):
                continue
            kind = block.get("type")
            if kind == "text":
                text_parts.append(str(block.get("text") or ""))
            elif kind == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=str(block.get("id") or ""),
                        name=str(block.get("name") or ""),
                        arguments=dict(block.get("input") or {}),
                    )
                )

        usage_payload = data.get("usage") or {}
        usage = Usage(
            prompt_tokens=int(usage_payload.get("input_tokens") or 0),
            completion_tokens=int(usage_payload.get("output_tokens") or 0),
        )
        usage.total_tokens = usage.prompt_tokens + usage.completion_tokens

        return ProviderResponse(
            text="\n".join(part for part in text_parts if part),
            tool_calls=tool_calls,
            usage=usage,
            model=str(data.get("model") or self.config.model),
            provider="anthropic",
            finish_reason=str(data.get("stop_reason") or ""),
            raw={"id": data.get("id")},
        )

    @staticmethod
    def _extract_error(response: httpx.Response) -> str:
        try:
            data = response.json()
        except ValueError:
            return (response.text or "")[:400]
        if isinstance(data, dict):
            error = data.get("error")
            if isinstance(error, dict):
                return str(error.get("message") or error)[:400]
            if error:
                return str(error)[:400]
        return (response.text or "")[:400]

    # --------------------------------------------------------------- models
    async def list_models(self) -> list[str]:
        """Anthropic does not expose a model listing endpoint."""
        raise ProviderError(
            "The Anthropic API does not provide a model listing endpoint. "
            "Enter the model identifier manually (for example claude-sonnet-4-20250514).",
            "provider_model_discovery_unsupported",
            status=400,
        )
