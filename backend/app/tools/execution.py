"""Execution tools: approved commands and sandboxed Python.

Both tools are *always* mediated by the sandbox broker:

* the command is validated against the allowlist (no shell, no metacharacters,
  no absolute program paths);
* the approved inputs are copied into a disposable per-job directory;
* the program runs inside the hardened sandbox container with CPU, memory,
  PID, time and output limits;
* the result is sanitised and truncated before it is handed back to the model.
"""

from __future__ import annotations

import contextlib
import shutil
from pathlib import Path
from typing import Any

from pydantic import Field

from ..core.commands import CommandRejection
from ..core.paths import PathError
from ..services.workspace import create_job_workspace
from .base import ToolContext, ToolInput, ToolResult, pydantic_validate

#: The maximum number of bytes of a script that may be submitted.
MAX_SCRIPT_BYTES = 64 * 1024


class ExecuteCommandInput(ToolInput):
    command: str = Field(
        min_length=1,
        max_length=4096,
        description="Command to execute. Allowlisted program name plus arguments. "
        "No shell syntax is supported.",
    )
    working_directory: str | None = Field(
        default=None,
        description="Optional workspace-relative working directory.",
    )
    timeout_seconds: int | None = Field(
        default=None, ge=1, le=300, description="Optional per-execution timeout override."
    )


class RunPythonInput(ToolInput):
    code: str = Field(min_length=1, max_length=MAX_SCRIPT_BYTES, description="Python source to run.")
    timeout_seconds: int | None = Field(
        default=None, ge=1, le=300, description="Optional per-execution timeout override."
    )
    arguments: list[str] = Field(
        default_factory=list, max_length=16, description="Optional argv passed to the script."
    )


def _copy_inputs(context: ToolContext, job: Any, paths: list[str]) -> list[str]:
    """Copy approved input files into the job workspace."""
    copied: list[str] = []
    for raw in paths:
        try:
            resolved = context.workspace.resolve(raw)
        except PathError:
            continue
        if not resolved.exists() or not resolved.is_file():
            continue
        try:
            shutil.copy2(resolved, Path(job.input_dir) / resolved.name)
            copied.append(resolved.name)
        except OSError:
            continue
    return copied


def _stage_approved_workspace(context: ToolContext, job: Any) -> list[str]:
    """Copy the policy-approved part of the workspace into the job directory.

    The host filesystem is never mounted into the sandbox.  Instead the
    approved files are *copied* into a disposable per-job directory, and only
    the files that the policy engine would allow the agent to read are
    copied at all.  A file that the policy denies (for example anything under
    ``protected/``) simply never reaches the sandbox.
    """
    engine = context.request_meta.get("policy_engine")
    root = context.request_meta.get("workspace_root")
    if engine is None or root is None:
        return []

    max_bytes = int(context.request_meta.get("max_staged_bytes", 2_097_152))
    max_files = int(context.request_meta.get("max_staged_files", 200))

    staged: list[str] = []
    total = 0
    for path in sorted(Path(root).rglob("*")):
        if len(staged) >= max_files or total >= max_bytes:
            break
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        decision = engine.evaluate(
            "read_file",
            {"path": relative},
            user_id=context.user_id,
            role=context.user.role,
        )
        if not decision.allowed:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if total + size > max_bytes:
            continue
        destination = Path(job.input_dir) / relative
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
        except OSError:
            continue
        total += size
        staged.append(relative)
    return staged


async def execute_approved_command(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Execute an allowlisted command inside the hardened sandbox."""
    payload = pydantic_validate(ExecuteCommandInput, arguments)

    try:
        argv = context.request_meta["command_allowlist"].split(payload.command)
    except CommandRejection as exc:
        return ToolResult(ok=False, error=str(exc), error_code=exc.code)
    try:
        context.request_meta["command_allowlist"].validate(argv)
    except CommandRejection as exc:
        return ToolResult(ok=False, error=str(exc), error_code=exc.code)

    job = create_job_workspace(context.request_meta["job_root"])
    try:
        _stage_approved_workspace(context, job)
        if payload.working_directory:
            try:
                target = context.workspace.resolve(payload.working_directory)
            except PathError as exc:
                return ToolResult(ok=False, error=str(exc), error_code=exc.code)
            if target.is_dir():
                for item in target.iterdir():
                    if item.is_file():
                        try:
                            shutil.copy2(item, Path(job.input_dir) / item.name)
                        except OSError:
                            continue

        result = await context.sandbox.run(
            context.request_meta["sandbox_request"](
                argv=argv,
                workspace=job,
                cwd="/workspace/input",
                timeout_seconds=payload.timeout_seconds or context.request_meta["sandbox_timeout"],
            )
        )
        return ToolResult(
            ok=result.exit_code == 0,
            output={
                "command": payload.command,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration_ms": result.duration_ms,
                "sandbox_id": result.sandbox_id,
                "backend": result.backend,
                "isolated": result.isolated,
                "timed_out": result.timed_out,
                "truncated": result.truncated,
            },
            error=result.error
            or (None if result.exit_code == 0 else result.stderr.strip()[:2000] or "Command failed"),
            error_code="sandbox_error" if result.exit_code != 0 else "",
            metadata={
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "sandbox_id": result.sandbox_id,
                "backend": result.backend,
                "isolated": result.isolated,
                "timed_out": result.timed_out,
            },
        )
    finally:
        job.cleanup()


async def run_python_sandboxed(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Run a Python script inside the hardened sandbox."""
    payload = pydantic_validate(RunPythonInput, arguments)

    if len(payload.code.encode("utf-8")) > MAX_SCRIPT_BYTES:
        return ToolResult(
            ok=False,
            error="Script exceeds the maximum permitted size",
            error_code="script_too_large",
        )

    job = create_job_workspace(context.request_meta["job_root"])
    try:
        _stage_approved_workspace(context, job)
        script_path = Path(job.input_dir) / "script.py"
        script_path.write_text(payload.code, encoding="utf-8")
        with contextlib.suppress(OSError):
            os_chmod(script_path, 0o644)

        argv = ["python3", "-I", "-B", "/workspace/input/script.py", *payload.arguments]
        result = await context.sandbox.run(
            context.request_meta["sandbox_request"](
                argv=argv,
                workspace=job,
                cwd="/workspace/input",
                timeout_seconds=payload.timeout_seconds or context.request_meta["sandbox_timeout"],
            )
        )
        outputs = []
        output_dir = Path(job.output_dir)
        if output_dir.exists():
            for item in sorted(output_dir.iterdir()):
                if item.is_file():
                    try:
                        outputs.append(
                            {
                                "name": item.name,
                                "size": item.stat().st_size,
                                "content": item.read_text(encoding="utf-8", errors="replace")[:200_000],
                            }
                        )
                    except OSError:
                        continue
        return ToolResult(
            ok=result.exit_code == 0,
            output={
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration_ms": result.duration_ms,
                "sandbox_id": result.sandbox_id,
                "backend": result.backend,
                "isolated": result.isolated,
                "timed_out": result.timed_out,
                "artifacts": outputs,
            },
            error=result.error
            or (None if result.exit_code == 0 else result.stderr.strip()[:2000] or "Script failed"),
            error_code="sandbox_error" if result.exit_code != 0 else "",
            metadata={
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "sandbox_id": result.sandbox_id,
                "backend": result.backend,
                "isolated": result.isolated,
            },
        )
    finally:
        job.cleanup()


def os_chmod(path: Any, mode: int) -> None:
    """Small indirection so tests can patch chmod easily."""
    import os

    os.chmod(path, mode)
