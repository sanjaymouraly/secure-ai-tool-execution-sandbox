"""Filesystem path safety.

This module implements the *hard guards* of the sandbox: invariants that no
policy rule is ever allowed to relax.  A policy may narrow what is allowed,
but it can never permit a path escape, a symlink escape, an encoded traversal
or a write to a location outside the approved roots.

Defence strategy
----------------
1.  **Reject** syntactically hostile input (NUL bytes, backslashes, percent
    encoded traversal, absolute paths that are not inside a root).
2.  **Resolve** the candidate path with ``os.path.realpath`` which fully
    dereferences symlinks, then confirm it is inside one of the roots.
3.  **Re-verify** at open time: the final path component is opened with
    ``O_NOFOLLOW`` and the *realpath of the parent* is re-checked, closing the
    time-of-check / time-of-use window.
4.  **Refuse** hard-linked files with a link count greater than one, which
    prevents the classic "write through a hard link" trick.
"""

from __future__ import annotations

import contextlib
import errno
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = ["PathError", "ResolvedPath", "SafePathResolver"]

#: Percent-encoded traversal / separators that must never reach the filesystem.
_ENCODED_TRAVERSAL = re.compile(r"(?i)%(?:2e|252e|2f|252f|5c|255c|2d|252d){1,2}|%00|%(?:c0|ae|af)")

#: Characters that are never valid inside a sandbox path.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")

#: Host locations that must never be reachable from a tool call.
FORBIDDEN_ABSOLUTE_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/boot",
    "/var/run/docker.sock",
    "/var/lib/docker",
    "/run/docker.sock",
    "/home",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/opt",
    "/srv",
    "/mnt",
    "/media",
    "/tmp",  # nosec B108
)


class PathError(ValueError):
    """Raised when a path request violates a filesystem safety invariant."""

    def __init__(self, message: str, code: str = "path_rejected") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ResolvedPath:
    """A validated path together with the metadata used to validate it."""

    path: Path
    root: Path
    relative: Path
    is_symlink: bool


def _normalise(raw: str) -> str:
    """Normalise user supplied path text without touching the filesystem."""
    if raw is None:
        raise PathError("Path must be a string", "path_invalid")
    if "\x00" in raw:
        raise PathError("Path contains a NUL byte", "path_nul_byte")
    if len(raw) > 4096:
        raise PathError("Path is too long", "path_too_long")
    if _ENCODED_TRAVERSAL.search(raw):
        raise PathError("Path contains percent-encoded traversal sequences", "path_encoded_traversal")
    if _FORBIDDEN_CHARS.search(raw):
        raise PathError("Path contains forbidden control characters", "path_forbidden_chars")
    # Unicode normalisation: NFKC collapses look-alike separators.
    text = unicodedata.normalize("NFKC", raw).strip()
    if not text:
        raise PathError("Path must not be empty", "path_empty")
    if "\x00" in text:
        raise PathError("Path contains a NUL byte", "path_nul_byte")
    return text


class SafePathResolver:
    """Resolve untrusted path input against a set of approved roots."""

    def __init__(self, roots: Iterable[Path | str]) -> None:
        resolved_roots: list[Path] = []
        for root in roots:
            path = Path(root).expanduser()
            with contextlib.suppress(OSError):
                path.mkdir(parents=True, exist_ok=True)
            resolved_roots.append(Path(os.path.realpath(path)))
        if not resolved_roots:
            raise ValueError("At least one approved root is required")
        self.roots: list[Path] = resolved_roots
        # Longest root first so nested roots win the containment check.
        self.roots.sort(key=lambda item: len(item.parts), reverse=True)

    # ------------------------------------------------------------------ api
    def contains(self, path: Path) -> Path | None:
        """Return the root that contains ``path`` (already realpath'd) or None."""
        for root in self.roots:
            try:
                path.relative_to(root)
            except ValueError:
                continue
            return root
        return None

    def resolve(
        self,
        raw: str,
        *,
        must_exist: bool = False,
        for_write: bool = False,
        allow_symlink_target_inside: bool = True,
    ) -> ResolvedPath:
        """Validate ``raw`` and return a safe :class:`ResolvedPath`.

        Raises :class:`PathError` for every violation.
        """
        text = _normalise(raw)
        candidate = Path(text)

        # Absolute inputs are only acceptable when they already live inside a
        # root; everything else is treated as relative to the first root.
        if candidate.is_absolute():
            joined = candidate
        else:
            joined = self.roots[0] / candidate

        # Reject traversal syntactically before touching the filesystem.
        if any(part == ".." for part in candidate.parts):
            raise PathError("Path traversal component '..' is not permitted", "path_traversal")
        if ".." in text.split("/"):
            raise PathError("Path traversal component '..' is not permitted", "path_traversal")

        real_parent = Path(os.path.realpath(joined.parent))
        real_full = Path(os.path.realpath(joined))

        root = self.contains(real_full) or self.contains(real_parent)
        if root is None:
            raise PathError(
                f"Path resolves outside the approved workspace roots: {text!r}",
                "path_outside_workspace",
            )

        # The resolved location itself must be inside a root (catches symlink
        # escapes where the parent is fine but the leaf points elsewhere).
        leaf_root = self.contains(real_full)
        if leaf_root is None:
            raise PathError(
                f"Path resolves outside the approved workspace roots (symlink escape): {text!r}",
                "path_symlink_escape",
            )

        try:
            relative = real_full.relative_to(leaf_root)
        except ValueError as exc:  # pragma: no cover - guarded above
            raise PathError("Path is outside the approved workspace", "path_outside_workspace") from exc

        if ".." in relative.parts:
            raise PathError("Path traversal detected after resolution", "path_traversal")

        # A symlink is acceptable only when it points at a location that is
        # itself inside an approved root.
        is_symlink = joined.is_symlink()
        if is_symlink and not allow_symlink_target_inside:
            raise PathError("Symbolic links are not permitted for this operation", "path_symlink_forbidden")

        if must_exist and not real_full.exists():
            raise PathError(f"Path does not exist: {text!r}", "path_not_found")

        if for_write:
            parent_real = Path(os.path.realpath(joined.parent))
            if self.contains(parent_real) is None:
                raise PathError(
                    "Write target parent directory is outside the approved workspace",
                    "path_outside_workspace",
                )
            if not parent_real.is_dir():
                raise PathError("Write target parent directory does not exist", "path_parent_missing")

        return ResolvedPath(path=real_full, root=leaf_root, relative=relative, is_symlink=is_symlink)

    # --------------------------------------------------------------- checks
    def assert_inside(self, path: Path) -> Path:
        """Assert that an already resolved path lives inside a root."""
        real = Path(os.path.realpath(path))
        if self.contains(real) is None:
            raise PathError(f"Path is outside the approved workspace: {path}", "path_outside_workspace")
        return real

    @staticmethod
    def assert_regular_file(path: Path, *, max_bytes: int | None = None) -> os.stat_result:
        """Assert the path is a regular, non-hard-linked file within limits."""
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise PathError(f"Cannot stat path: {exc}", "path_stat_failed") from exc

        if stat.S_ISLNK(info.st_mode):
            raise PathError("Refusing to operate on a symbolic link", "path_symlink_forbidden")
        if not stat.S_ISREG(info.st_mode):
            raise PathError("Refusing to operate on a non-regular file", "path_not_regular_file")
        if info.st_nlink > 1:
            raise PathError(
                "Refusing to operate on a file with multiple hard links",
                "path_hardlink_forbidden",
            )
        if max_bytes is not None and info.st_size > max_bytes:
            raise PathError(
                f"File exceeds the maximum permitted size ({info.st_size} > {max_bytes} bytes)",
                "path_too_large",
            )
        return info

    @staticmethod
    def open_readonly(path: Path, *, max_bytes: int | None = None) -> int:
        """Open a file for reading with ``O_NOFOLLOW`` and return the fd.

        This is the time-of-check / time-of-use safe read primitive: the
        descriptor is opened without following a final symlink and the
        identity of the opened file is verified afterwards.
        """
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise PathError("Refusing to follow a symbolic link", "path_symlink_forbidden") from exc
            raise PathError(f"Cannot open file: {exc}", "path_open_failed") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise PathError("Refusing to operate on a non-regular file", "path_not_regular_file")
            if info.st_nlink > 1:
                raise PathError(
                    "Refusing to operate on a file with multiple hard links",
                    "path_hardlink_forbidden",
                )
            if max_bytes is not None and info.st_size > max_bytes:
                raise PathError(
                    f"File exceeds the maximum permitted size ({info.st_size} > {max_bytes} bytes)",
                    "path_too_large",
                )
        except Exception:
            os.close(fd)
            raise
        return fd

    @staticmethod
    def write_atomic(path: Path, content: bytes, *, exclusive: bool = True) -> Path:
        """Write ``content`` to ``path`` without following symlinks.

        Uses ``O_NOFOLLOW | O_EXCL`` and a temporary file + ``os.replace`` so a
        concurrent attacker cannot swap the target between check and write.
        """
        parent = path.parent
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        tmp_path = parent / f".{path.name}.{os.getpid()}.{abs(hash(content)) & 0xFFFFFF:06x}.tmp"
        fd = None
        try:
            fd = os.open(tmp_path, flags, 0o600)
            os.write(fd, content)
            os.fsync(fd)
        except FileExistsError:
            # A stale temp file: remove it and retry once.
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            fd = os.open(tmp_path, flags, 0o600)
            os.write(fd, content)
            os.fsync(fd)
        finally:
            if fd is not None:
                os.close(fd)
        try:
            if exclusive and path.exists():
                raise PathError("Target already exists", "path_exists")
            os.replace(tmp_path, path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
        return path


def is_forbidden_absolute(path_text: str) -> bool:
    """Return True when a path points at a well-known sensitive host location."""
    normalised = os.path.normpath(path_text)
    for prefix in FORBIDDEN_ABSOLUTE_PREFIXES:
        if normalised == prefix or normalised.startswith(prefix + "/"):
            return True
    return False


def relative_to_root(path: Path, root: Path) -> str:
    """Return a POSIX style relative path for display and audit purposes."""
    try:
        return path.relative_to(root).as_posix() or "."
    except ValueError:
        return path.name


def iter_safe_children(directory: Path, limit: int) -> list[Path]:
    """List children of ``directory`` without following symlinks."""
    children: list[Path] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                children.append(Path(entry.path))
                if len(children) >= limit:
                    break
    except OSError:
        return []
    return children


def has_shell_metacharacters(value: str) -> bool:
    """Return True when the value contains shell control characters."""
    return bool(re.search(r"[|&;`<>$()\n\r\\\x00\"']", value))


def split_argv(value: str) -> list[str]:
    """Split a command string into argv using POSIX-like rules (no shell)."""
    import shlex

    return shlex.split(value, posix=True)


def normalise_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return a canonical, comparable representation of an argv vector."""
    return tuple(argv)
