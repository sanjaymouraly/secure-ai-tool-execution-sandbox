#!/usr/bin/env python3
"""Entrypoint for the hardened sandbox image.

The broker hands this script a JSON specification on stdin:

    {
      "argv": ["python3", "-I", "-B", "/workspace/input/script.py"],
      "cwd": "/workspace",
      "timeout": 30,
      "env": {"FOO": "bar"}
    }

The specification is executed with ``execvpe`` - there is no shell, no
command substitution and no glob expansion.  Resource limits are applied with
``setrlimit`` before the target program is executed.
"""

from __future__ import annotations

import json
import os
import resource
import signal
import sys

SAFE_PATH = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

#: Wall clock limit; the broker enforces its own timeout as a backstop.
WALL_CLOCK_SECONDS = 30

#: Maximum size of a file the sandbox may create.
MAX_FILE_BYTES = 64 * 1024 * 1024

#: Maximum number of open file descriptors.
MAX_OPEN_FILES = 1024


def _apply_limits() -> None:
    """Lower the resource limits of the sandbox process."""
    limits = (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_NOFILE, MAX_OPEN_FILES),
        (resource.RLIMIT_FSIZE, MAX_FILE_BYTES),
    )
    for which, value in limits:
        try:
            resource.setrlimit(which, (value, value))
        except (ValueError, OSError):
            pass


def _drop_privileges() -> None:
    """Drop supplementary groups and refuse to keep any elevated capability."""
    try:
        os.setgroups([])
    except (OSError, PermissionError):
        pass
    try:
        os.umask(0o077)
    except OSError:
        pass


def _install_alarm(seconds: int) -> None:
    """Terminate the sandbox if the program overruns the wall clock budget."""
    def _handler(_signum, _frame):  # pragma: no cover - signal path
        sys.stderr.write(f"[sandbox] wall clock limit of {seconds}s exceeded\n")
        sys.stderr.flush()
        os._exit(124)

    signal.signal(signal.SIGALRM, _handler)
    signal.alarm(max(1, seconds))


def main() -> int:
    try:
        raw = sys.stdin.read()
    except Exception:  # pragma: no cover - defensive
        raw = ""
    try:
        spec = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"[sandbox] invalid specification: {exc}\n")
        return 2

    argv = spec.get("argv") or []
    if not isinstance(argv, list) or not argv:
        sys.stderr.write("[sandbox] no argv supplied\n")
        return 2
    if any(not isinstance(item, str) for item in argv):
        sys.stderr.write("[sandbox] argv must contain strings only\n")
        return 2

    cwd = spec.get("cwd") or "/workspace"
    timeout = int(spec.get("timeout") or WALL_CLOCK_SECONDS)

    env = {
        "PATH": SAFE_PATH,
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONNOUSERSITE": "1",
    }
    supplied = spec.get("env") or {}
    if isinstance(supplied, dict):
        for key, value in supplied.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            if key.startswith("SANDBOX_") or key.startswith("LD_"):
                continue
            env[key] = value

    _apply_limits()
    _drop_privileges()
    _install_alarm(timeout)

    try:
        os.chdir(cwd)
    except OSError as exc:
        sys.stderr.write(f"[sandbox] cannot enter working directory {cwd}: {exc}\n")
        return 3

    try:
        os.execvpe(argv[0], argv, env)
    except OSError as exc:
        sys.stderr.write(f"[sandbox] cannot execute {argv[0]!r}: {exc}\n")
        return 127
    return 0  # pragma: no cover - execvpe does not return


if __name__ == "__main__":
    sys.exit(main())
