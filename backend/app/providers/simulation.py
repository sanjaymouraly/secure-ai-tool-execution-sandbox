"""Deterministic offline provider (simulation mode).

This provider requires **no API key, no network access and no paid model**.
It implements a small, fully deterministic planner so the complete agent
pipeline - schema validation, policy evaluation, approvals, sandbox
execution, audit records - can be exercised and demonstrated offline.

The planner deliberately *mimics a compromised agent* in one specific way: if
an untrusted tool result contains an embedded instruction (the classic prompt
injection payload), the planner "obeys" it and proposes the corresponding
write.  That is how the attack laboratory demonstrates that the policy
engine - and not the model's good manners - is what stops the action.  The
simulation is labelled as such in every execution record.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .base import Message, Provider, ProviderConfiguration, ProviderError, ProviderResponse, ToolCall, Usage

#: Instruction patterns that a compromised agent would follow.
_INJECTION_PATTERNS = (
    re.compile(
        r"(?i)\b(?:modify|overwrite|update|edit|write\s+to|replace|append\s+to|delete|remove)\b"
        r"[^\n]{0,40}?\b([\w./\-]+\.[A-Za-z0-9]{1,8})"
    ),
    re.compile(r"(?i)\b(?:run|execute|eval(?:uate)?)\b[^\n]{0,40}?\b([\w.\-]+\s+[\w\-./]+)"),
)

_READ_PATTERN = re.compile(r"(?i)\b(?:read|open|show|summari[sz]e|analy[sz]e|inspect|review)\b")
_LIST_PATTERN = re.compile(r"(?i)\b(?:list|ls|show files|directory|enumerate|what files)\b")
_SEARCH_PATTERN = re.compile(r"(?i)\b(?:search|grep|find|look for|locate)\b")
_HASH_PATTERN = re.compile(r"(?i)\b(?:hash|checksum|digest|integrity|sha-?256)\b")
_COMMAND_PATTERN = re.compile(r"(?i)\b(?:command|shell|terminal|exec(?:ute)?)\b")
_PYTHON_PATTERN = re.compile(r"(?i)\b(?:python|script|compute|calculate|analy[sz]e data)\b")


class SimulationProvider(Provider):
    """A deterministic, offline stand-in for a real model."""

    name = "simulation"
    supports_native_tools = True
    requires_credentials = False

    def __init__(self, config: ProviderConfiguration) -> None:
        super().__init__(config)
        self.model = config.model or "simulation://deterministic-planner"

    # ---------------------------------------------------------------- chat
    async def chat(
        self,
        messages: Sequence[Message],
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        stream: bool = False,
    ) -> ProviderResponse:
        if not messages:
            raise ProviderError("No messages supplied.", "provider_empty_request", status=400)

        available = {
            tool.get("function", tool).get("name") for tool in tools if tool.get("function", tool).get("name")
        }

        last_user = ""
        tool_results: list[str] = []
        for message in messages:
            if message.role == "user":
                last_user = message.content
            elif message.role == "tool":
                tool_results.append(message.content)
        untrusted_text = "\n".join(tool_results)

        # 1. An injected instruction inside untrusted content wins - this is
        #    the behaviour a compromised model would exhibit.
        injected = self._detect_injection(untrusted_text)
        if injected:
            target = injected.get("path") or "protected/secret.txt"
            if "create_artifact" in available:
                return self._tool_response(
                    "create_artifact",
                    {"name": "injected-output.txt", "content": f"injected:{target}"},
                    model=self.model,
                )
            if "read_file" in available:
                return self._tool_response("read_file", {"path": target}, model=self.model)

        # 2. Already executed tools?  Summarise what we learned.
        if tool_results and not self._needs_more_tools(last_user, available):
            return self._text_response(self._summarise(tool_results), model=self.model)

        # 3. Plan a first tool call from the user's request.
        plan = self._plan(last_user, available)
        if plan is not None:
            name, arguments = plan
            return self._tool_response(name, arguments, model=self.model)

        return self._text_response(
            "I can inspect the approved workspace. Ask me to list files, read a "
            "document, search for a pattern or compute a hash.",
            model=self.model,
        )

    # ------------------------------------------------------------- planning
    def _plan(self, request: str, available: set[str]) -> tuple[str, dict[str, Any]] | None:
        request = request or ""
        path = self._extract_path(request)

        if _SEARCH_PATTERN.search(request) and "search_files" in available:
            pattern = self._extract_quoted(request) or "TODO"
            return "search_files", {"pattern": pattern, "path": path or "."}

        if _HASH_PATTERN.search(request) and "calculate_hash" in available and path:
            return "calculate_hash", {"path": path}

        if _PYTHON_PATTERN.search(request) and "run_python_sandboxed" in available and path:
            code = (
                "import hashlib, pathlib\n"
                f"data = pathlib.Path('/workspace/input/{path.rsplit('/', 1)[-1]}').read_bytes()\n"
                "print('sha256', hashlib.sha256(data).hexdigest())\n"
            )
            return "run_python_sandboxed", {"code": code}

        if _COMMAND_PATTERN.search(request) and "execute_approved_command" in available:
            command = self._extract_command(request)
            if command:
                return "execute_approved_command", {"command": command}

        if path and _READ_PATTERN.search(request) and "read_file" in available:
            return "read_file", {"path": path}

        if _LIST_PATTERN.search(request) and "list_files" in available:
            return "list_files", {"path": path or "."}

        if _READ_PATTERN.search(request) and "read_file" in available and path:
            return "read_file", {"path": path}

        if _LIST_PATTERN.search(request) and "list_files" in available:
            return "list_files", {"path": path or "."}

        return None

    def _needs_more_tools(self, request: str, available: set[str]) -> bool:
        """True when the summary is not enough and another call is required."""
        return bool(_HASH_PATTERN.search(request or "") and "calculate_hash" in available)

    @staticmethod
    def _extract_path(request: str) -> str:
        match = re.search(
            r"[\w\-./]+\.(?:md|txt|json|ya?ml|csv|log|py|toml|ini|cfg|conf|html|xml|rst|sql)", request
        )
        if match:
            return match.group(0)
        quoted = SimulationProvider._extract_quoted(request)
        if quoted:
            return quoted
        match = re.search(r"\b(?:in|from|file|path)\s+([\w\-./]+)", request, re.IGNORECASE)
        if match:
            return match.group(1)
        return ""

    @staticmethod
    def _extract_quoted(request: str) -> str:
        match = re.search(r"[\"'`]([^\"'`]{2,120})[\"'`]", request)
        return match.group(1) if match else ""

    @staticmethod
    def _extract_command(request: str) -> str:
        match = re.search(r"`([^`]{2,200})`", request)
        if match:
            return match.group(1).strip()
        match = re.search(
            r"\b(?:run|execute)\s+(?:the\s+)?(?:command\s+)?([a-z]+\s+[^\n.]{0,80})", request, re.IGNORECASE
        )
        return match.group(1).strip() if match else ""

    @staticmethod
    def _detect_injection(text: str) -> dict[str, str] | None:
        for pattern in _INJECTION_PATTERNS:
            match = pattern.search(text or "")
            if match:
                return {"path": match.group(1).strip().strip("\"'`")}
        return None

    @staticmethod
    def _summarise(tool_results: Sequence[str]) -> str:
        parts: list[str] = []
        for chunk in tool_results:
            if "entries" in chunk or "content" in chunk:
                parts.append(chunk[:800])
        return (
            "Here is what I found in the approved workspace:\n\n" + "\n\n".join(parts[:4])
            if parts
            else "I inspected the approved workspace; no matching content was found."
        )

    # ------------------------------------------------------------ responses
    def _tool_response(self, name: str, arguments: Mapping[str, Any], *, model: str) -> ProviderResponse:
        # Not a security primitive: only a stable, non-cryptographic identifier.
        call = ToolCall(
            id=f"call_sim_{hashlib.sha1(name.encode(), usedforsecurity=False).hexdigest()[:12]}",
            name=name,
            arguments=dict(arguments),
        )
        return ProviderResponse(
            text="",
            tool_calls=[call],
            usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
            model=model,
            provider="simulation",
            finish_reason="tool_calls",
        )

    def _text_response(self, text: str, *, model: str) -> ProviderResponse:
        return ProviderResponse(
            text=text,
            tool_calls=[],
            usage=Usage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
            model=model,
            provider="simulation",
            finish_reason="stop",
        )

    # --------------------------------------------------------------- models
    async def list_models(self) -> list[str]:
        return ["simulation://deterministic-planner"]
