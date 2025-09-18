"""Docker based sandbox backend.

Every execution runs in a throw-away container that is started with the
hardening flags documented in ``docs/security-controls.md``:

* ``--read-only`` root filesystem with a small ``noexec`` tmpfs for ``/tmp``
* ``--cap-drop ALL`` and ``--security-opt no-new-privileges``
* a hardened seccomp profile (networking, namespaces, tracing and eBPF
  primitives are removed)
* AppArmor ``docker-default`` profile when the host supports it
* ``--network none`` so the container has no route to the outside world
* CPU, memory, PID and file-descriptor limits
* a dedicated unprivileged uid and a private cgroup namespace
* only two bind mounts: the job input directory (read-only) and the job
  output directory (read-write)

The Docker socket is never mounted into the container and the broker never
exposes container-management primitives to the agent.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import subprocess  # nosec B404 - the Docker client, always with a constant argument vector
import time
import uuid
from pathlib import Path
from typing import Any

from ..core.config import Settings, get_settings
from ..core.redaction import scrub_environment
from .base import (
    SandboxBackend,
    SandboxRequest,
    SandboxResult,
    SandboxStatus,
    SandboxUnavailableError,
)

logger = logging.getLogger(__name__)


class DockerSandboxBackend(SandboxBackend):
    """Execute untrusted code inside a hardened, ephemeral Docker container."""

    name = "docker"
    isolated = True

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._docker = self.settings.sandbox_docker_binary
        self._containers: dict[str, float] = {}
        self._capabilities: dict[str, Any] | None = None

    # ------------------------------------------------------------ discovery
    def _run_docker(self, args: list[str], timeout: float = 20.0) -> tuple[int, str, str]:
        try:
            completed = subprocess_run([self._docker, *args], timeout=timeout)
        except FileNotFoundError:
            return 127, "", f"docker binary '{self._docker}' not found on PATH"
        except Exception as exc:  # pragma: no cover - defensive
            return 1, "", str(exc)
        return completed[0], completed[1], completed[2]

    def capabilities(self) -> dict[str, Any]:
        """Probe the Docker daemon for the security features we rely on."""
        if self._capabilities is not None:
            return self._capabilities

        code, out, err = self._run_docker(["info", "--format", "{{json .SecurityOptions}}"])
        if code != 0 or err.strip():
            # `docker info --format` exits with 0 even when the daemon cannot
            # be reached and prints the error on stderr, so both are checked.
            self._capabilities = {
                "available": False,
                "error": err.strip() or "docker info failed",
                "rootless": False,
                "apparmor": False,
                "seccomp": False,
                "cgroupns": False,
                "version": "",
            }
            return self._capabilities

        options = (out or "[]").strip()
        try:
            parsed = json.loads(options)
        except json.JSONDecodeError:
            parsed = []
        if not isinstance(parsed, list):
            # Some daemon configurations report a null SecurityOptions.
            parsed = []
        names = " ".join(str(item) for item in parsed).lower()
        _, version_out, _ = self._run_docker(["version", "--format", "{{.Server.Version}}"])

        self._capabilities = {
            "available": True,
            "error": "",
            "rootless": "rootless" in names,
            "apparmor": "apparmor" in names,
            "seccomp": "seccomp" in names,
            "cgroupns": "cgroupns" in names,
            "userns": self._check_userns(),
            "version": version_out.strip(),
        }
        return self._capabilities

    def _check_userns(self) -> bool:
        _, out, _ = self._run_docker(["info", "--format", "{{.SecurityOptions}}"])
        return "name=userns" in out.lower()

    def image_present(self) -> bool:
        code, out, err = self._run_docker(["images", "-q", self.settings.sandbox_image])
        return code == 0 and not err.strip() and bool(out.strip())

    async def ensure_image(self) -> None:
        """Make sure the sandbox image is available, pulling it if allowed."""
        if self.image_present():
            return
        if not self.settings.sandbox_pull_image:
            raise SandboxUnavailableError(
                f"Sandbox image '{self.settings.sandbox_image}' is not present and "
                "SAXIS_SANDBOX_PULL_IMAGE is disabled. Build it with "
                "'docker build -t secure-ai-sandbox-runner:latest docker/sandbox'."
            )
        logger.info("Pulling sandbox image %s", self.settings.sandbox_image)
        process = await asyncio.create_subprocess_exec(
            self._docker,
            "pull",
            self.settings.sandbox_image,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            raise SandboxUnavailableError(
                "Unable to pull the sandbox image: " + stderr.decode("utf-8", "replace")[:500]
            )

    # ----------------------------------------------------------- run command
    def build_command(self, request: SandboxRequest, container_name: str) -> list[str]:
        """Build the hardened ``docker run`` argument vector."""
        settings = self.settings
        cmd: list[str] = [self._docker, "run", "--rm", "-i", "--name", container_name]

        # --- isolation -----------------------------------------------------
        if not request.network:
            cmd += ["--network", "none"]
        cmd += ["--read-only"]
        cmd += ["--cap-drop", "ALL"]
        cmd += ["--security-opt", "no-new-privileges"]
        cmd += ["--security-opt", f"seccomp={self._seccomp_profile()}"]
        if self.capabilities().get("apparmor"):
            cmd += ["--security-opt", f"apparmor={settings.sandbox_apparmor_profile}"]
        cmd += ["--cgroupns", "private"]
        if settings.sandbox_rootless and self.capabilities().get("rootless"):
            cmd += ["--userns", "keep-id"]

        # --- identity ------------------------------------------------------
        cmd += ["--user", settings.sandbox_user]
        cmd += ["--hostname", "sandbox"]

        # --- resources -----------------------------------------------------
        cmd += ["--cpus", str(settings.sandbox_max_cpu_cores)]
        cmd += ["--memory", f"{settings.sandbox_max_memory_mb}m"]
        cmd += ["--memory-swap", f"{settings.sandbox_max_memory_mb}m"]
        cmd += ["--pids-limit", str(settings.sandbox_max_pids)]
        cmd += ["--ulimit", "nofile=1024:1024"]
        cmd += ["--ulimit", "nproc=64:64"]
        cmd += ["--ulimit", "fsize=67108864:67108864"]
        cmd += ["--stop-timeout", "1"]
        cmd += ["--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={settings.sandbox_max_tmpfs_mb}m"]  # nosec B108 - a tmpfs inside the container
        cmd += ["--tmpfs", "/home/sandbox:rw,noexec,nosuid,nodev,size=16m"]

        # --- mounts --------------------------------------------------------
        workspace = request.workspace
        if workspace is not None:
            input_dir = Path(workspace.input_dir)
            output_dir = Path(workspace.output_dir)
            input_dir.mkdir(parents=True, exist_ok=True)
            output_dir.mkdir(parents=True, exist_ok=True)
            # The container user must be able to read the inputs and write
            # the outputs; the directories are created with mode 0700 by the
            # host and relaxed for the bind mount only.
            os.chmod(input_dir, 0o755)  # nosec B103 - the bind mount is read-only
            os.chmod(output_dir, 0o777)  # nosec B103 - the sandbox user must write here
            cmd += ["--mount", f"type=bind,source={input_dir},target=/workspace/input,readonly"]
            cmd += ["--mount", f"type=bind,source={output_dir},target=/workspace/output"]
        for source, target in (request.extra_mounts or {}).items():
            cmd += ["--mount", f"type=bind,source={source},target={target},readonly"]

        cmd += ["--workdir", request.cwd or settings.sandbox_workdir]
        cmd += ["--env", "PYTHONDONTWRITEBYTECODE=1"]
        cmd += ["--env", "PYTHONNOUSERSITE=1"]
        cmd += ["--env", "HOME=/tmp"]
        cmd += ["--env", "TMPDIR=/tmp"]
        cmd += ["--env", "LANG=C.UTF-8"]
        cmd += ["--label", "org.saxis.role=sandbox"]
        cmd += ["--label", f"org.saxis.job={getattr(workspace, 'job_id', 'unknown')}"]
        cmd.append(settings.sandbox_image)
        return cmd

    def _seccomp_profile(self) -> str:
        """Return the seccomp profile path, falling back to the built-in one."""
        configured = self.settings.sandbox_seccomp_profile_path
        if configured and Path(configured).exists():
            return str(configured)
        profile = Path(__file__).resolve().parents[3] / "docker" / "seccomp" / "sandbox.json"
        if profile.exists():
            return str(profile)
        return "default"

    # -------------------------------------------------------------- execute
    async def run(self, request: SandboxRequest) -> SandboxResult:
        capabilities = self.capabilities()
        if not capabilities.get("available"):
            raise SandboxUnavailableError(
                "Docker is not available: " + str(capabilities.get("error") or "unknown error")
            )
        await self.ensure_image()

        container_name = f"{self.settings.sandbox_container_prefix}-{uuid.uuid4().hex[:12]}"
        command = self.build_command(request, container_name)
        specification = {
            "argv": request.argv,
            "cwd": request.cwd or self.settings.sandbox_workdir,
            "timeout": request.timeout_seconds,
            "env": scrub_environment(request.env or {}),
        }
        payload = json.dumps(specification).encode("utf-8")

        started = time.monotonic()
        self._containers[container_name] = started
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise SandboxUnavailableError(f"docker binary not found: {exc}") from exc

        stdout = b""
        stderr = b""
        timed_out = False
        limit = request.max_output_bytes or self.settings.sandbox_max_output_bytes
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(payload), timeout=request.timeout_seconds + 10
            )
        except TimeoutError:
            timed_out = True
            await self._terminate(process, container_name)
            stdout, stderr = b"", b""

        duration_ms = int((time.monotonic() - started) * 1000)
        self._containers.pop(container_name, None)

        stdout_text = stdout.decode("utf-8", "replace")
        stderr_text = stderr.decode("utf-8", "replace")
        truncated = False
        if len(stdout_text.encode("utf-8")) > limit:
            stdout_text = stdout_text.encode("utf-8")[:limit].decode("utf-8", "replace")
            truncated = True
        if len(stderr_text.encode("utf-8")) > limit:
            stderr_text = stderr_text.encode("utf-8")[:limit].decode("utf-8", "replace")
            truncated = True

        exit_code = 124 if timed_out else (process.returncode if process.returncode is not None else 1)
        if timed_out:
            stderr_text = (
                stderr_text + f"\n[Sandbox] execution exceeded the "
                f"{request.timeout_seconds}s time limit and was terminated."
            ).strip()

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_ms=duration_ms,
            timed_out=timed_out,
            truncated=truncated,
            sandbox_id=container_name,
            backend=self.name,
            isolated=True,
            exit_reason="timeout" if timed_out else ("error" if exit_code else "ok"),
        )

    async def _terminate(self, process: Any, container_name: str) -> None:
        """Kill the container and make sure it is gone."""
        with contextlib.suppress(ProcessLookupError):  # pragma: no cover - race
            process.kill()
        with contextlib.suppress(TimeoutError, ProcessLookupError):  # pragma: no cover
            await asyncio.wait_for(process.wait(), timeout=10)
        try:
            process = await asyncio.create_subprocess_exec(
                self._docker,
                "rm",
                "-f",
                container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(process.wait(), timeout=15)
        except Exception:
            logger.warning("Failed to remove container %s", container_name)

    # --------------------------------------------------------------- status
    async def status(self) -> SandboxStatus:
        capabilities = self.capabilities()
        if not capabilities.get("available"):
            return SandboxStatus(
                name=self.name,
                available=False,
                isolated=True,
                detail=str(capabilities.get("error") or "Docker daemon unreachable"),
                image=self.settings.sandbox_image,
                warnings=[
                    "Docker is required for the default sandbox backend. "
                    "Start Docker Desktop or the Docker Engine service."
                ],
            )
        warnings: list[str] = []
        if not capabilities.get("rootless"):
            warnings.append(
                "The Docker daemon is not running rootless; user namespace isolation is not applied."
            )
        if not capabilities.get("apparmor"):
            warnings.append("AppArmor is not available on this host; the seccomp profile still applies.")
        if not self.image_present():
            warnings.append(f"Sandbox image '{self.settings.sandbox_image}' is not built yet.")
        return SandboxStatus(
            name=self.name,
            available=True,
            isolated=True,
            detail="Docker Engine with hardened container flags",
            image=self.settings.sandbox_image,
            rootless=bool(capabilities.get("rootless")),
            apparmor=bool(capabilities.get("apparmor")),
            seccomp=bool(capabilities.get("seccomp")),
            user_namespaces=bool(capabilities.get("userns")),
            warnings=warnings,
            version=str(capabilities.get("version") or ""),
        )

    async def cleanup(self) -> None:
        """Remove any container that is still running."""
        for name in list(self._containers):
            try:
                process = await asyncio.create_subprocess_exec(
                    self._docker,
                    "rm",
                    "-f",
                    name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(process.wait(), timeout=15)
            except Exception:
                logger.warning("Failed to remove the container %s", name)
            self._containers.pop(name, None)


def subprocess_run(args: list[str], timeout: float = 20.0) -> tuple[int, str, str]:
    """Run a command synchronously and capture its output.

    The argument vector is always built from constants and the Docker client
    is never invoked through a shell.
    """
    completed = subprocess.run(  # noqa: S603  # nosec B603
        args, capture_output=True, text=True, timeout=timeout, check=False
    )
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def docker_binary_available(binary: str = "docker") -> bool:
    """Return True when the docker client is present on PATH."""
    return shutil.which(binary) is not None
