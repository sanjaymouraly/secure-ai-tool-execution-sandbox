"""Sandbox backend interface.

A *sandbox backend* is the component that actually executes untrusted code.
Only a backend that provides real operating system isolation may be used in
production; the local simulation backend is explicitly flagged as
non-isolating and refuses to run unless an operator opts in.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "SandboxBackend",
    "SandboxRequest",
    "SandboxResult",
    "SandboxStatus",
    "SandboxUnavailableError",
]


class SandboxUnavailableError(RuntimeError):
    """Raised when the configured sandbox backend cannot be used.

    The API surfaces this as a clear setup error; it must never silently
    degrade to unsandboxed host execution.
    """


@dataclass
class SandboxRequest:
    """A request to execute a program inside the sandbox."""

    argv: list[str]
    workspace: Any = None
    cwd: str = "/workspace"
    timeout_seconds: int = 30
    env: dict[str, str] = field(default_factory=dict)
    stdin_data: str | None = None
    extra_mounts: dict[str, str] = field(default_factory=dict)
    network: bool = False
    max_output_bytes: int = 262_144


@dataclass
class SandboxResult:
    """The outcome of a sandboxed execution."""

    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    truncated: bool = False
    sandbox_id: str = ""
    backend: str = ""
    #: True only when the backend provides real OS level isolation.
    isolated: bool = False
    error: str | None = None
    error_code: str = ""
    cpu_seconds: float = 0.0
    memory_peak_mb: float = 0.0
    exit_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "sandbox_id": self.sandbox_id,
            "backend": self.backend,
            "isolated": self.isolated,
            "error": self.error,
            "error_code": self.error_code,
            "cpu_seconds": self.cpu_seconds,
            "memory_peak_mb": self.memory_peak_mb,
            "exit_reason": self.exit_reason,
        }


@dataclass
class SandboxStatus:
    """The health and posture of a sandbox backend."""

    name: str
    available: bool
    isolated: bool
    detail: str = ""
    image: str = ""
    rootless: bool = False
    apparmor: bool = False
    seccomp: bool = False
    user_namespaces: bool = False
    warnings: list[str] = field(default_factory=list)
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "isolated": self.isolated,
            "detail": self.detail,
            "image": self.image,
            "rootless": self.isolated and self.rootless,
            "apparmor": self.apparmor,
            "seccomp": self.seccomp,
            "user_namespaces": self.user_namespaces,
            "warnings": list(self.warnings),
            "version": self.version,
        }


class SandboxBackend(abc.ABC):
    """Abstract sandbox backend."""

    #: Stable identifier used in audit records.
    name: str = "abstract"
    #: True when the backend provides genuine OS level isolation.
    isolated: bool = False

    @abc.abstractmethod
    async def run(self, request: SandboxRequest) -> SandboxResult:
        """Execute ``request`` and return the result."""

    @abc.abstractmethod
    async def status(self) -> SandboxStatus:
        """Return the current health/posture of the backend."""

    async def cleanup(self) -> None:
        """Release any resources held by the backend."""
        return None
