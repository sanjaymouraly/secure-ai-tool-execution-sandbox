"""OpenAI compatible provider adapter.

This single adapter serves:

* **OpenAI** (``https://api.openai.com/v1``)
* **OpenRouter** (``https://openrouter.ai/api/v1``)
* **Ollama** and any other local runtime (``http://localhost:11434/v1``)
* **Custom** OpenAI-compatible endpoints configured by base URL + API key

The adapter also implements a *prompt based* tool calling fallback for models
whose runtime does not support the native ``tools`` parameter (for example
``gemma2`` on Ollama).  The fallback is explicitly marked in the response so
the dashboard can show that structured tool calls were reconstructed from
text rather than produced natively.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from .base import Message, Provider, ProviderConfiguration, ProviderError, ProviderResponse, ToolCall, Usage

logger = logging.getLogger(__name__)

#: Providers that require an API key.
_KEY_REQUIRED = {"openai", "openrouter", "custom"}

#: Default endpoints for the well known providers.
DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://localhost:11434/v1",
}

#: Ollama does not require a key; a placeholder keeps the header valid.
_OLLAMA_PLACEHOLDER_KEY = "ollama"

#: Extracts a JSON object from a model response that may contain prose.
_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_BARE_JSON = re.compile(r"(\{.*\})", re.DOTALL)


class OpenAICompatProvider(Provider):
    """Adapter for every OpenAI ``/chat/completions`` compatible endpoint."""

    name = "openai-compat"
    supports_native_tools = True

    def __init__(self, config: ProviderConfiguration) -> None:
        super().__init__(config)
        self.provider_type = config.provider_type
        self.base_url = (config.base_url or DEFAULT_BASE_URLS.get(config.provider_type, "")).rstrip("/")
        if not self.base_url:
            raise ProviderError(
                f"No base URL configured for provider '{config.provider_type}'.",
                "provider_missing_base_url",
                status=400,
            )
        self.api_key = config.api_key
        if config.provider_type in _KEY_REQUIRED and not self.api_key:
            raise ProviderError(
                f"Provider '{config.provider_type}' requires an API key.",
                "provider_missing_credentials",
                status=400,
            )
        if config.provider_type == "ollama" and not self.api_key:
            self.api_key = _OLLAMA_PLACEHOLDER_KEY

    # ------------------------------------------------------------- helpers
    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        headers.update(dict(self.config.extra_headers or {}))
        if self.provider_type == "openrouter":
            headers.setdefault("HTTP-Referer", "https://github.com/secure-ai-tool-execution-sandbox")
            headers.setdefault("X-Title", "Secure AI Tool Execution Sandbox")
        return headers

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self.config.timeout_seconds, follow_redirects=False)

    def _post(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=self.config.timeout_seconds, follow_redirects=False) as client:
                response = client.post(
                    self._url(path),
                    headers=self._headers(),
                    json=dict(payload),
                )
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"The provider did not respond within {self.config.timeout_seconds}s.",
                "provider_timeout",
                status=504,
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"Could not reach the provider: {exc}", "provider_unreachable", status=502
            ) from exc

        if response.status_code >= 400:
            message = self._extract_error(response)
            code = "provider_http_error"
            if response.status_code == 401 or response.status_code == 403:
                code = "provider_unauthorized"
            elif response.status_code == 429:
                code = "provider_rate_limited"
            elif response.status_code == 400:
                code = "provider_bad_request"
            raise ProviderError(
                f"{self.provider_type} returned HTTP {response.status_code}: {message}",
                code,
                status=502 if response.status_code >= 500 else response.status_code,
            )

        try:
            return response.json()
        except ValueError as exc:
            raise ProviderError(
                "The provider returned a response that is not valid JSON.",
                "provider_invalid_response",
            ) from exc

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
            if data.get("message"):
                return str(data["message"])[:400]
        return (response.text or "")[:400]

    # ---------------------------------------------------------------- chat
    async def chat(
        self,
        messages: Sequence[Message],
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        stream: bool = False,
    ) -> ProviderResponse:
        payload = self._build_payload(messages, tools, stream)
        last_error: Exception | None = None

        for attempt in range(max(1, self.config.max_retries + 1)):
            try:
                data = await self._post_async("/chat/completions", payload)
                return self._parse_response(data)
            except ProviderError as exc:
                last_error = exc
                if exc.code in {
                    "provider_unauthorized",
                    "provider_bad_request",
                    "provider_missing_credentials",
                }:
                    raise
                if attempt >= self.config.max_retries:
                    break
                await asyncio.sleep(min(2**attempt, 8))
        if last_error is None:  # pragma: no cover - defensive
            raise ProviderError("The provider call failed.", "provider_error")
        raise last_error

    async def _post_async(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            async with self._client() as client:
                response = await client.post(self._url(path), headers=self._headers(), json=dict(payload))
        except httpx.TimeoutException as exc:
            raise ProviderError(
                f"The provider did not respond within {self.config.timeout_seconds}s.",
                "provider_timeout",
                status=504,
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                f"Could not reach the provider: {exc}", "provider_unreachable", status=502
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
                f"{self.provider_type} returned HTTP {response.status_code}: {message}",
                code,
                status=502 if response.status_code >= 500 else response.status_code,
            )
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderError(
                "The provider returned a response that is not valid JSON.",
                "provider_invalid_response",
            ) from exc

    def _build_payload(
        self,
        messages: Sequence[Message],
        tools: Sequence[Mapping[str, Any]],
        stream: bool,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": self._format_messages(messages),
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": bool(stream),
        }
        options = dict(self.config.options or {})
        payload.update({key: value for key, value in options.items() if key not in payload})
        if tools and not self.config.force_prompt_tools:
            payload["tools"] = [dict(tool) for tool in tools]
            payload["tool_choice"] = "auto"
        elif tools:
            payload["messages"] = self._inject_tool_instructions(payload["messages"], tools)
        return payload

    def _format_messages(self, messages: Sequence[Message]) -> list[dict[str, Any]]:
        formatted: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "tool":
                formatted.append(
                    {
                        "role": "tool",
                        "tool_call_id": message.tool_call_id or "",
                        "content": message.content,
                    }
                )
                continue
            entry: dict[str, Any] = {"role": message.role, "content": message.content}
            if message.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": json.dumps(call.arguments, default=str),
                        },
                    }
                    for call in message.tool_calls
                ]
            formatted.append(entry)
        return formatted

    def _inject_tool_instructions(
        self, messages: list[dict[str, Any]], tools: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Add a tool protocol description for models without native tools."""
        catalogue = []
        for tool in tools:
            function = tool.get("function", tool)
            catalogue.append(
                {
                    "name": function.get("name"),
                    "description": function.get("description", ""),
                    "parameters": function.get("parameters", {}),
                }
            )
        instruction = (
            "You can call tools. To call exactly one tool, reply with a single JSON "
            "object and nothing else:\n"
            '{"tool": "<tool_name>", "arguments": {<arguments>}}\n'
            "Available tools:\n"
            + json.dumps(catalogue, indent=2)
            + "\nOnly call a tool that is listed above. If no tool is needed, reply "
            "with plain text."
        )
        system_messages = [item for item in messages if item.get("role") == "system"]
        other = [item for item in messages if item.get("role") != "system"]
        if system_messages:
            system_messages[0] = {
                "role": "system",
                "content": system_messages[0].get("content", "") + "\n\n" + instruction,
            }
            return system_messages + other
        return [{"role": "system", "content": instruction}, *other]

    def _parse_response(self, data: Mapping[str, Any]) -> ProviderResponse:
        choices = data.get("choices") or []
        if not choices:
            raise ProviderError("The provider returned no choices.", "provider_invalid_response")
        choice = choices[0] or {}
        message = choice.get("message") or {}
        text = str(message.get("content") or "")
        finish_reason = str(choice.get("finish_reason") or "")

        tool_calls: list[ToolCall] = []
        for raw_call in message.get("tool_calls") or []:
            function = raw_call.get("function") or {}
            name = str(function.get("name") or "")
            raw_arguments = function.get("arguments")
            if isinstance(raw_arguments, str):
                try:
                    arguments = json.loads(raw_arguments) if raw_arguments.strip() else {}
                except json.JSONDecodeError:
                    arguments = {"_raw": raw_arguments}
            elif isinstance(raw_arguments, dict):
                arguments = raw_arguments
            else:
                arguments = {}
            if not name:
                continue
            tool_calls.append(
                ToolCall(id=str(raw_call.get("id") or uuid.uuid4().hex), name=name, arguments=arguments)
            )

        if not tool_calls and text and self.config.force_prompt_tools:
            tool_calls = self._parse_prompt_tool_call(text)
            if tool_calls:
                text = ""

        usage_payload = data.get("usage") or {}
        usage = Usage(
            prompt_tokens=int(usage_payload.get("prompt_tokens") or 0),
            completion_tokens=int(usage_payload.get("completion_tokens") or 0),
            total_tokens=int(usage_payload.get("total_tokens") or 0),
        )
        if not usage.total_tokens:
            usage.total_tokens = usage.prompt_tokens + usage.completion_tokens

        return ProviderResponse(
            text=text,
            tool_calls=tool_calls,
            usage=usage,
            model=str(data.get("model") or self.config.model),
            provider=self.provider_type,
            finish_reason=finish_reason,
            raw={"id": data.get("id"), "model": data.get("model")},
        )

    @staticmethod
    def _parse_prompt_tool_call(text: str) -> list[ToolCall]:
        """Reconstruct a tool call from a JSON payload in the model text."""
        candidate = ""
        match = _JSON_BLOCK.search(text)
        if match:
            candidate = match.group(1)
        else:
            match = _BARE_JSON.search(text)
            if match:
                candidate = match.group(1)
        if not candidate:
            return []
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []
        name = data.get("tool") or data.get("name") or data.get("function")
        if not name or not isinstance(name, str):
            return []
        arguments = data.get("arguments")
        if arguments is None:
            arguments = data.get("parameters") or data.get("args") or {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {"value": arguments}
        if not isinstance(arguments, dict):
            arguments = {}
        return [ToolCall(id=f"call_{uuid.uuid4().hex[:16]}", name=name, arguments=arguments)]

    # --------------------------------------------------------------- models
    async def list_models(self) -> list[str]:
        try:
            async with self._client() as client:
                response = await client.get(self._url("/models"), headers=self._headers())
            if response.status_code >= 400:
                raise ProviderError(
                    f"Model discovery failed with HTTP {response.status_code}.",
                    "provider_model_discovery_failed",
                )
            data = response.json()
        except httpx.HTTPError as exc:
            raise ProviderError(f"Could not reach the provider: {exc}", "provider_unreachable") from exc
        except ProviderError:
            raise

        models: list[str] = []
        entries = data.get("data") if isinstance(data, dict) else data
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and entry.get("id"):
                    models.append(str(entry["id"]))
                elif isinstance(entry, str):
                    models.append(entry)
        return sorted(set(models))
