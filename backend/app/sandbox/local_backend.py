"""Local *simulation* sandbox backend.

.. warning::

   This backend does **not** provide operating system isolation.  It runs the
   approved program directly on the host, inside a temporary directory, with a
   scrubbed environment and reduced resource limits.

It exists for two legitimate purposes:

* running the test-suite on a machine without a Docker daemon;
* letting an operator inspect a workflow on a laptop.

Every execution produced by this backend is tagged with ``backend =
"local-simulated"`` and ``isolated = False``.  The API, the audit trail and
the dashboard all surface that distinction, and the backend refuses to start
unless ``SAXIS_SANDBOX_BACKEND=local-simulated`` was set explicitly.  It is
never used as an automatic fallback from the Docker backend.
"""

from __future__ import annotations

import asyncio
import contextlib
import resource
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from ..core.commands import CommandAllowlist
from ..core.config import Settings, get_settings
from ..core.redaction import scrub_environment
from .base import SandboxBackend, SandboxRequest, SandboxResult, SandboxStatus


def _limit_process() -> None:  # pragma: no cover - executed in a child process
    """Apply resource limits to the child process."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))


class LocalSimulatedBackend(SandboxBackend):
    """Run approved programs on the host - *without* isolation."""

    name = "local-simulated"
    isolated = False

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.command_allowlist = CommandAllowlist()

    async def run(self, request: SandboxRequest) -> SandboxResult:
        if not request.argv:
            return SandboxResult(
                exit_code=2,
                stderr="No program specified",
                backend=self.name,
                isolated=False,
                error="No program specified",
                error_code="sandbox_no_argv",
            )

        workspace = request.workspace
        workdir = Path(tempfile.mkdtemp(prefix="saxis-sim-"))
        if workspace is not None:
            for source, target in (
                (Path(workspace.input_dir), workdir / "input"),
                (Path(workspace.output_dir), workdir / "output"),
            ):
                target.mkdir(parents=True, exist_ok=True)
                try:
                    for item in source.iterdir():
                        destination = target / item.name
                        if item.is_file():
                            shutil.copy2(item, destination)
                except OSError:
                    pass

        env = scrub_environment(request.env or {})
        env.update(
            {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(workdir),
                "TMPDIR": str(workdir),
                "LANG": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "SAXIS_SIMULATION": "1",
            }
        )

        started = time.monotonic()
        timed_out = False
        stdout = b""
        stderr = b""
        exit_code = 1
        try:
            process = await asyncio.create_subprocess_exec(
                *request.argv,
                cwd=str(workdir),
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=_limit_process,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=request.timeout_seconds
                )
                exit_code = process.returncode if process.returncode is not None else 1
            except TimeoutError:
                timed_out = True
                process.kill()
                stdout, stderr = await process.communicate()
                exit_code = 124
        except FileNotFoundError as exc:
            stderr = str(exc).encode("utf-8")
            exit_code = 127
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        duration_ms = int((time.monotonic() - started) * 1000)
        limit = request.max_output_bytes or self.settings.sandbox_max_output_bytes
        stdout_text = stdout.decode("utf-8", "replace")
        stderr_text = stderr.decode("utf-8", "replace")
        truncated = False
        if len(stdout_text.encode("utf-8")) > limit:
            stdout_text = stdout_text.encode("utf-8")[:limit].decode("utf-8", "replace")
            truncated = True
        if len(stderr_text.encode("utf-8")) > limit:
            stderr_text = stderr_text.encode("utf-8")[:limit].decode("utf-8", "replace")
            truncated = True

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_ms=duration_ms,
            timed_out=timed_out,
            truncated=truncated,
            sandbox_id=f"sim-{uuid.uuid4().hex[:12]}",
            backend=self.name,
            isolated=False,
            exit_reason="timeout" if timed_out else ("error" if exit_code else "ok"),
            error=None if exit_code == 0 else stderr_text.strip()[:2000] or None,
        )

    async def status(self) -> SandboxStatus:
        return SandboxStatus(
            name=self.name,
            available=True,
            isolated=False,
            detail=(
                "SIMULATION MODE - programs run directly on the host without "
                "operating system isolation. Do not use for untrusted workloads."
            ),
            image="n/a",
            warnings=[
                "This backend provides no isolation. It must never be used to run untrusted code.",
                "Set SAXIS_SANDBOX_BACKEND=docker for real isolation.",
            ],
        )


def build_backend(settings: Settings | None = None) -> SandboxBackend:
    """Return the sandbox backend selected by the configuration."""
    settings = settings or get_settings()
    if settings.sandbox_backend == "docker":
        from .docker_backend import DockerSandboxBackend

        return DockerSandboxBackend(settings)
    if settings.sandbox_backend == "local-simulated":
        return LocalSimulatedBackend(settings)
    raise ValueError(f"Unknown sandbox backend: {settings.sandbox_backend}")


def any_backend_available(settings: Settings | None = None) -> bool:
    """Return True when the configured backend can be used."""
    settings = settings or get_settings()
    if settings.sandbox_backend == "local-simulated":
        return True
    from .docker_backend import docker_binary_available

    return docker_binary_available(settings.sandbox_docker_binary)
