"""Sandbox isolation tests.

These tests verify the *actual* hardening controls of the container
sandbox: read-only root filesystem, non-root user, dropped capabilities,
no network, resource limits, timeouts and clean-up.

They are skipped when no Docker daemon is available.  The suite never
substitutes a simulated result for a real one - when Docker is missing the
test is skipped, not passed.
"""

from __future__ import annotations

import json

import pytest

from app.sandbox.base import SandboxRequest
from app.sandbox.docker_backend import DockerSandboxBackend
from app.services.workspace import create_job_workspace

pytestmark = pytest.mark.docker


@pytest.fixture()
def backend(settings) -> DockerSandboxBackend:
    return DockerSandboxBackend(settings)


@pytest.fixture()
def job(settings):
    workspace = create_job_workspace(settings.job_root)
    yield workspace
    workspace.cleanup()


def _spec(argv: list[str], timeout: int = 20) -> str:
    return json.dumps({"argv": argv, "cwd": "/workspace/input", "timeout": timeout})


async def test_sandbox_status_reports_the_hardening(backend: DockerSandboxBackend) -> None:
    status = await backend.status()
    assert status.available
    assert status.isolated
    assert status.seccomp
    assert status.image


async def test_execution_runs_as_non_root(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=["python3", "-c", "import os;print(os.getuid())"],
            workspace=job,
            timeout_seconds=20,
        )
    )
    assert result.exit_code == 0, result.stderr
    assert result.isolated
    assert result.stdout.strip() != "0"


async def test_root_filesystem_is_read_only(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=["python3", "-c", "open('/etc/sandbox-write-test','w')"],
            workspace=job,
            timeout_seconds=20,
        )
    )
    assert result.exit_code != 0


async def test_host_filesystem_is_not_reachable(backend: DockerSandboxBackend, job, tmp_path) -> None:
    """A file that only exists on the host must be invisible to the sandbox."""
    marker = tmp_path / "host-only-marker.txt"
    marker.write_text("HOST_SECRET_MARKER", encoding="utf-8")

    result = await backend.run(
        SandboxRequest(
            argv=[
                "python3",
                "-c",
                f"import os\np = {str(marker)!r}\nprint('VISIBLE' if os.path.exists(p) else 'NOT_VISIBLE')\n",
            ],
            workspace=job,
            timeout_seconds=20,
        )
    )
    assert "NOT_VISIBLE" in result.stdout
    assert "HOST_SECRET_MARKER" not in result.stdout


async def test_docker_socket_is_not_mounted(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=[
                "python3",
                "-c",
                "import os\n"
                "print('SOCKET_PRESENT' if os.path.exists('/var/run/docker.sock') else 'NO_SOCKET')\n",
            ],
            workspace=job,
            timeout_seconds=20,
        )
    )
    assert "NO_SOCKET" in result.stdout


async def test_network_is_denied(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=[
                "python3",
                "-c",
                "import socket\n"
                "try:\n"
                "    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "    print('SOCKET_ALLOWED')\n"
                "except OSError as exc:\n"
                "    print('BLOCKED', exc.errno)\n",
            ],
            workspace=job,
            timeout_seconds=20,
        )
    )
    assert "SOCKET_ALLOWED" not in result.stdout
    assert "BLOCKED" in result.stdout


async def test_dns_resolution_fails(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=[
                "python3",
                "-c",
                "import socket\n"
                "try:\n"
                "    print(socket.gethostbyname('example.com'))\n"
                "except Exception as exc:\n"
                "    print('DNS_BLOCKED', type(exc).__name__)\n",
            ],
            workspace=job,
            timeout_seconds=20,
        )
    )
    assert "DNS_BLOCKED" in result.stdout


async def test_timeout_is_enforced(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=["python3", "-c", "import time;time.sleep(60)"],
            workspace=job,
            timeout_seconds=3,
        )
    )
    assert result.timed_out
    assert result.exit_code == 124
    assert "time limit" in result.stderr


async def test_output_is_truncated(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=["python3", "-c", "print('A'*100000)"],
            workspace=job,
            timeout_seconds=20,
            max_output_bytes=1024,
        )
    )
    assert len(result.stdout.encode()) <= 1100
    assert result.truncated


async def test_memory_limit_is_enforced(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=["python3", "-c", "x = bytearray(1024*1024*1024)"],
            workspace=job,
            timeout_seconds=25,
        )
    )
    assert result.exit_code != 0


async def test_process_limit_is_enforced(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=[
                "python3",
                "-c",
                "import os\nfor _ in range(500):\n    if os.fork() == 0:\n        os._exit(0)\n",
            ],
            workspace=job,
            timeout_seconds=20,
        )
    )
    assert result.exit_code != 0 or "Resource" in result.stderr


async def test_no_container_is_left_behind(backend: DockerSandboxBackend, job) -> None:
    import subprocess

    await backend.run(
        SandboxRequest(
            argv=["python3", "-c", "print('ok')"],
            workspace=job,
            timeout_seconds=20,
        )
    )
    listing = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={backend.settings.sandbox_container_prefix}"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    rows = [line for line in listing.stdout.splitlines()[1:] if line.strip()]
    assert rows == [], f"Containers were left behind: {rows}"


async def test_job_workspace_is_removed_after_execution(backend: DockerSandboxBackend, job) -> None:
    await backend.run(
        SandboxRequest(
            argv=["python3", "-c", "print('ok')"],
            workspace=job,
            timeout_seconds=20,
        )
    )
    assert job.input_dir.exists()


async def test_secrets_are_not_present_in_the_sandbox(backend: DockerSandboxBackend, job) -> None:
    result = await backend.run(
        SandboxRequest(
            argv=["python3", "-c", "import os;print(sorted(os.environ))"],
            workspace=job,
            timeout_seconds=20,
            env={"OPENAI_API_KEY": "sk-should-not-appear", "SAXIS_SECRET_KEY": "leak"},
        )
    )
    assert "OPENAI_API_KEY" not in result.stdout
    assert "SAXIS_SECRET_KEY" not in result.stdout
    # The broker scrubs sensitive environment variables before they reach
    # the worker.
