"""Secret redaction helpers.

Every value that may leave the trusted control plane (logs, audit records,
API responses, model prompts) passes through :func:`redact` so that
credentials are never persisted or transmitted inadvertently.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

_MASK = "[REDACTED]"

#: Patterns that are always masked regardless of context.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret)\b"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9_\-\.]{6,})[\"']?"
    ),
    re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[=:]\s*[\"']?([^\s\"',;]{4,})[\"']?"),
    re.compile(r"(?i)\bauthorization\b\s*:\s*(?:bearer\s+)?([^\s\"']+)"),
)

#: Mapping keys whose values are always masked.
_SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "client_secret",
        "cookie",
        "csrf",
        "csrf_token",
        "hashed_password",
        "password",
        "passwd",
        "private_key",
        "pwd",
        "secret",
        "secret_key",
        "session_token",
        "token",
        "access_token",
        "refresh_token",
    }
)

#: Environment variables that must never be forwarded into a sandbox.
BLOCKED_ENV_VARS = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET",
        "GCP_SERVICE_ACCOUNT_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "SAXIS_PROVIDER_API_KEY",
        "SAXIS_SECRET_KEY",
        "SSH_AUTH_SOCK",
        "NPM_TOKEN",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    }
)


def redact_text(value: str) -> str:
    """Mask credential-shaped substrings inside free text."""
    if not value:
        return value
    redacted = value
    for pattern in _PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(lambda m: _substitute_groups(m), redacted)
        else:
            redacted = pattern.sub(_MASK, redacted)
    return redacted


def _substitute_groups(match: re.Match[str]) -> str:
    """Replace only the captured secret portion of a match."""
    masked = list(match.group(0))
    if match.groups():
        start, end = match.span(1)
        for index in range(start, end):
            masked[index] = "*"
    return "".join(masked)


def redact(value: Any, *, extra_keys: Iterable[str] = ()) -> Any:
    """Recursively redact secrets from arbitrary JSON-like structures."""
    sensitive = _SENSITIVE_KEYS | {key.lower() for key in extra_keys}
    return _redact(value, sensitive)


def _redact(value: Any, sensitive: frozenset[str]) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in sensitive:
                result[key] = _MASK
            else:
                result[key] = _redact(item, sensitive)
        return result
    if isinstance(value, (list, tuple)):
        return [_redact(item, sensitive) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Redact sensitive HTTP headers."""
    return {
        key: (_MASK if key.lower() in _SENSITIVE_KEYS else redact_text(val)) for key, val in headers.items()
    }


def scrub_environment(env: Mapping[str, str]) -> dict[str, str]:
    """Return an environment mapping safe to hand to a sandbox worker."""
    return {
        key: value
        for key, value in env.items()
        if key not in BLOCKED_ENV_VARS and key.lower() not in _SENSITIVE_KEYS
    }
