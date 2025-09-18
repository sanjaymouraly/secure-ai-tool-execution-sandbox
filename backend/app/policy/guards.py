"""Hard guards: invariants that no policy rule can relax.

The policy engine is *administrator controlled configuration*.  A mistake (or
a malicious administrator) in a policy file must not be able to grant a
host path, a shell or the network.  The guards below are implemented in code,
evaluated before the policy rules, and therefore always win.

Every guard violation is reported with a stable ``guard:<code>`` identifier so
the dashboard can explain exactly why an action was refused.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..core.commands import CommandAllowlist, CommandRejection
from ..core.paths import PathError, SafePathResolver

__all__ = ["GuardContext", "GuardViolation", "evaluate_guards"]


@dataclass(frozen=True)
class GuardContext:
    """Everything the guards need to make a decision."""

    path_resolver: SafePathResolver
    command_allowlist: CommandAllowlist
    max_argument_bytes: int = 65_536
    max_path_depth: int = 32
    allowed_network_hosts: frozenset[str] = field(default_factory=frozenset)
    network_enabled: bool = False


@dataclass(frozen=True)
class GuardViolation:
    """A single hard-guard violation."""

    code: str
    message: str
    detail: str = ""

    @property
    def rule_id(self) -> str:
        return f"guard:{self.code}"


#: Python constructs that are refused outright in sandboxed scripts.
_DANGEROUS_PYTHON = (
    (re.compile(r"\b__import__\s*\("), "dynamic import"),
    (
        re.compile(r"\bimport\s+(os|subprocess|socket|shutil|ctypes|multiprocessing|pty|pickle)\b"),
        "privileged standard library import",
    ),
    (
        re.compile(r"\bfrom\s+(os|subprocess|socket|shutil|ctypes|multiprocessing|pty|pickle)\b"),
        "privileged standard library import",
    ),
    (
        re.compile(r"\bos\.(system|popen|fork|exec\w*|remove|unlink|rmdir|setuid|chroot)\b"),
        "host operating system call",
    ),
    (re.compile(r"\bsubprocess\.\w+"), "subprocess creation"),
    (re.compile(r"\bsocket\.(socket|create_connection)\b"), "raw socket creation"),
    (re.compile(r"\bopen\s*\(\s*['\"]/"), "absolute path access"),
    (re.compile(r"\bopen\s*\(\s*['\"]\.\./"), "path traversal"),
    (re.compile(r"\b(eval|exec|compile)\s*\("), "dynamic code execution"),
    (re.compile(r"\b__builtins__\b"), "builtins access"),
    (re.compile(r"\bglobals\s*\(\s*\)"), "globals access"),
)

#: Keys that indicate a network destination.
_NETWORK_KEYS = ("url", "host", "hostname", "endpoint", "uri", "address", "port")


def _string_arguments(arguments: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Return all string-valued arguments with their key."""
    result: list[tuple[str, str]] = []
    for key, value in arguments.items():
        if isinstance(value, str):
            result.append((key, value))
        elif isinstance(value, (list, tuple)):
            result.extend((key, item) for item in value if isinstance(item, str))
    return result


def _path_like_arguments(arguments: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Return arguments that plausibly denote a filesystem path."""
    candidates: list[tuple[str, str]] = []
    for key, value in _string_arguments(arguments):
        if key in ("path", "directory", "file", "source", "destination", "target", "root", "cwd"):
            candidates.append((key, value))
    return candidates


def evaluate_guards(
    tool_name: str,
    arguments: Mapping[str, Any],
    context: GuardContext,
) -> list[GuardViolation]:
    """Run every hard guard and return the list of violations (empty == safe)."""
    violations: list[GuardViolation] = []

    # ---------------------------------------------------------- G-SIZE
    try:
        import json

        payload = json.dumps(dict(arguments), default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        payload = str(arguments)
    if len(payload.encode("utf-8")) > context.max_argument_bytes:
        violations.append(
            GuardViolation(
                "argument_too_large",
                f"Tool arguments exceed the maximum permitted size "
                f"({len(payload.encode('utf-8'))} > {context.max_argument_bytes} bytes)",
            )
        )

    # ---------------------------------------------------------- G-PATH
    for key, raw_path in _path_like_arguments(arguments):
        if not raw_path:
            continue
        try:
            resolved = context.path_resolver.resolve(raw_path, must_exist=False)
        except PathError as exc:
            violations.append(
                GuardViolation("path_unsafe", f"Path argument '{key}' rejected: {exc}", exc.code)
            )
            continue
        depth = len(resolved.relative.parts)
        if depth > context.max_path_depth:
            violations.append(
                GuardViolation(
                    "path_too_deep",
                    f"Path argument '{key}' exceeds the maximum permitted depth ({depth})",
                )
            )

    # ------------------------------------------------------- G-COMMAND
    command = arguments.get("command")
    if isinstance(command, str) and command.strip():
        try:
            argv = context.command_allowlist.split(command)
            context.command_allowlist.validate(argv)
        except CommandRejection as exc:
            violations.append(GuardViolation("command_unsafe", f"Command rejected: {exc}", exc.code))

    # ------------------------------------------------------ G-PYTHON
    code = arguments.get("code") or arguments.get("script")
    if isinstance(code, str) and code:
        for pattern, label in _DANGEROUS_PYTHON:
            if pattern.search(code):
                violations.append(
                    GuardViolation(
                        "python_unsafe",
                        f"Sandboxed script rejected: {label} is not permitted",
                    )
                )
                break

    # ------------------------------------------------------ G-NETWORK
    for key, value in _string_arguments(arguments):
        if key.lower() not in _NETWORK_KEYS:
            continue
        if not context.network_enabled:
            violations.append(
                GuardViolation(
                    "network_denied",
                    f"Network destinations are not permitted (argument '{key}')",
                )
            )
            break
        host = value
        if not any(
            host == allowed or host.endswith(f".{allowed}") for allowed in context.allowed_network_hosts
        ):
            violations.append(
                GuardViolation(
                    "network_not_allowlisted",
                    f"Network host '{host}' is not on the administrator allowlist",
                )
            )
            break

    # ------------------------------------------------------ G-ARTIFACT
    artifact_name = arguments.get("name") or arguments.get("artifact_name")
    if isinstance(artifact_name, str) and artifact_name:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact_name):
            violations.append(
                GuardViolation(
                    "artifact_name_invalid",
                    "Artifact names may only contain letters, digits, dot, dash and underscore",
                )
            )
        if ".." in artifact_name:
            violations.append(GuardViolation("artifact_name_invalid", "Artifact names may not contain '..'"))

    return violations
