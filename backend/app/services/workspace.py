"""Workspace and artifact storage services.

The *workspace* is the single directory tree that agents are allowed to
inspect.  The *artifact store* is where agents may persist outputs; it lives
outside the workspace so that artifacts can never be mistaken for approved
inputs and so that the workspace can be mounted read-only into a sandbox.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core.paths import PathError, SafePathResolver, relative_to_root

__all__ = ["Artifact", "ArtifactStore", "JobWorkspace", "WorkspaceService"]

_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ARTIFACT_SUFFIX = re.compile(r"^[A-Za-z0-9]{1,16}$")


@dataclass(frozen=True)
class Artifact:
    """Metadata describing a stored artifact."""

    name: str
    path: Path
    size: int
    created_at: datetime
    sha256: str
    content_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "created_at": self.created_at.isoformat(),
            "sha256": self.sha256,
            "content_type": self.content_type,
        }


class WorkspaceService:
    """Read-only helpers over the approved workspace tree."""

    def __init__(self, root: Path, resolver: SafePathResolver) -> None:
        self.root = Path(root).resolve()
        self.resolver = resolver

    # ------------------------------------------------------------- reading
    def display_path(self, path: Path) -> str:
        return relative_to_root(Path(path), self.root)

    def resolve(self, raw: str) -> Path:
        """Resolve a workspace-relative path, raising :class:`PathError`."""
        resolved = self.resolver.resolve(raw)
        return resolved.path

    def list_directory(
        self, raw: str, *, recursive: bool = False, max_entries: int = 5000
    ) -> list[dict[str, Any]]:
        """List the entries of an approved directory."""
        target = self.resolve(raw)
        if not target.exists():
            raise PathError(f"Directory not found: {raw}", "path_not_found")
        if not target.is_dir():
            raise PathError(f"Path is not a directory: {raw}", "path_not_a_directory")

        entries: list[dict[str, Any]] = []
        stack: list[Path] = [target]
        while stack and len(entries) < max_entries:
            current = stack.pop(0)
            try:
                with os.scandir(current) as iterator:
                    for entry in sorted(iterator, key=lambda item: item.name):
                        if len(entries) >= max_entries:
                            break
                        is_dir = entry.is_dir(follow_symlinks=False)
                        entries.append(
                            {
                                "name": entry.name,
                                "path": self.display_path(Path(entry.path)),
                                "type": "directory" if is_dir else "file",
                                "size": (entry.stat(follow_symlinks=False).st_size if not is_dir else None),
                                "symlink": entry.is_symlink(),
                            }
                        )
                        if recursive and is_dir:
                            stack.append(Path(entry.path))
            except PermissionError as exc:
                raise PathError(f"Permission denied: {raw}", "path_permission_denied") from exc
            except OSError as exc:
                raise PathError(f"Cannot list directory: {exc}", "path_list_failed") from exc
        return entries

    def read_text(self, raw: str, *, max_bytes: int) -> str:
        """Read an approved file as UTF-8 text."""
        target = self.resolve(raw)
        if not target.exists():
            raise PathError(f"File not found: {raw}", "path_not_found")
        fd = SafePathResolver.open_readonly(target, max_bytes=max_bytes)
        try:
            with os.fdopen(fd, "rb", closefd=True) as handle:
                data = handle.read(max_bytes + 1)
        except PathError:
            raise
        except OSError as exc:
            raise PathError(f"Cannot read file: {exc}", "path_read_failed") from exc
        if len(data) > max_bytes:
            raise PathError(
                f"File exceeds the maximum permitted size ({max_bytes} bytes)",
                "path_too_large",
            )
        return data.decode("utf-8", errors="replace")

    def metadata(self, raw: str) -> dict[str, Any]:
        """Return metadata for an approved path."""
        target = self.resolve(raw)
        if not target.exists():
            raise PathError(f"Path not found: {raw}", "path_not_found")
        info = target.lstat()
        return {
            "path": self.display_path(target),
            "name": target.name,
            "type": "directory" if stat.S_ISDIR(info.st_mode) else "file",
            "size": info.st_size,
            "mode": oct(stat.S_IMODE(info.st_mode)),
            "owner_uid": info.st_uid,
            "owner_gid": info.st_gid,
            "modified_at": datetime.fromtimestamp(info.st_mtime, tz=UTC).isoformat(),
            "created_at": datetime.fromtimestamp(info.st_ctime, tz=UTC).isoformat(),
            "hard_links": info.st_nlink,
            "symlink": stat.S_ISLNK(info.st_mode),
            "real_path": self.display_path(Path(os.path.realpath(target))),
        }

    def hash_file(self, raw: str, algorithm: str = "sha256") -> dict[str, Any]:
        """Hash an approved file."""
        target = self.resolve(raw)
        if not target.exists():
            raise PathError(f"File not found: {raw}", "path_not_found")
        fd = SafePathResolver.open_readonly(target)
        try:
            digest = hashlib.new(algorithm)
            with os.fdopen(fd, "rb", closefd=True) as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
        except ValueError as exc:
            raise ToolErrorAlias(f"Unsupported hash algorithm: {algorithm}", "hash_unsupported") from exc
        except OSError as exc:
            raise PathError(f"Cannot hash file: {exc}", "path_read_failed") from exc
        return {
            "path": self.display_path(target),
            "algorithm": algorithm,
            "digest": digest.hexdigest(),
            "size": target.stat().st_size,
        }

    def search(
        self,
        pattern: str,
        *,
        path: str = ".",
        max_results: int = 200,
        case_sensitive: bool = False,
    ) -> list[dict[str, Any]]:
        """Search file contents for a regular expression."""
        try:
            regex = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as exc:
            raise PathError(f"Invalid search pattern: {exc}", "search_invalid_pattern") from exc
        root = self.resolve(path)
        if not root.exists():
            raise PathError(f"Path not found: {path}", "path_not_found")
        bases = [root] if root.is_dir() else [root.parent]
        results: list[dict[str, Any]] = []
        for base in bases:
            for file_path in self._iter_files(base):
                if len(results) >= max_results:
                    return results
                try:
                    fd = SafePathResolver.open_readonly(file_path, max_bytes=1_048_576)
                    with os.fdopen(fd, "rb", closefd=True) as handle:
                        text = handle.read().decode("utf-8", errors="replace")
                except (PathError, OSError):
                    continue
                for number, line in enumerate(text.splitlines(), start=1):
                    if regex.search(line):
                        results.append(
                            {
                                "path": self.display_path(file_path),
                                "line": number,
                                "text": line[:500],
                            }
                        )
                        if len(results) >= max_results:
                            return results
        return results

    def _iter_files(self, root: Path) -> Iterator[Path]:
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    for entry in iterator:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
            except OSError:
                continue


class ToolErrorAlias(Exception):
    """Local error type used by the workspace helpers."""


class ArtifactStore:
    """Per-session artifact storage with strict naming and size limits."""

    def __init__(self, root: Path, *, max_bytes: int = 262_144, max_per_session: int = 200) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.max_per_session = max_per_session

    def _session_dir(self, session_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_-]", "", session_id or "default")
        path = self.root / safe
        path.mkdir(parents=True, exist_ok=True)
        return path

    def validate_name(self, name: str) -> str:
        """Validate and normalise an artifact name."""
        candidate = (name or "").strip()
        if not _ARTIFACT_NAME.match(candidate):
            raise ValueError(
                "Artifact names must start with a letter or digit and may only contain "
                "letters, digits, dot, dash and underscore"
            )
        if candidate in {".", ".."} or ".." in candidate:
            raise ValueError("Artifact names may not contain '..'")
        suffix = Path(candidate).suffix.lstrip(".").lower()
        if suffix and not _ARTIFACT_SUFFIX.match(suffix):
            raise ValueError("Artifact file extension contains unsupported characters")
        return candidate

    def write(
        self, session_id: str, name: str, content: str, *, content_type: str = "text/plain"
    ) -> Artifact:
        """Store a new artifact."""
        safe_name = self.validate_name(name)
        payload = content.encode("utf-8")
        if len(payload) > self.max_bytes:
            raise ValueError(f"Artifact exceeds the maximum permitted size of {self.max_bytes} bytes")
        directory = self._session_dir(session_id)
        existing = list(directory.iterdir())
        if len(existing) >= self.max_per_session:
            raise ValueError(f"Session already holds the maximum of {self.max_per_session} artifacts")
        target = directory / safe_name
        if target.exists():
            raise ValueError(f"Artifact '{safe_name}' already exists in this session")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        return Artifact(
            name=safe_name,
            path=target,
            size=len(payload),
            created_at=datetime.now(UTC),
            sha256=hashlib.sha256(payload).hexdigest(),
            content_type=content_type,
        )

    def read(self, session_id: str, name: str) -> Artifact:
        """Read a stored artifact."""
        safe_name = self.validate_name(name)
        target = self._session_dir(session_id) / safe_name
        if not target.exists():
            raise FileNotFoundError(f"Artifact not found: {safe_name}")
        info = target.lstat()
        if info.st_nlink > 1:
            raise ValueError("Refusing to read an artifact with multiple hard links")
        data = target.read_bytes()
        return Artifact(
            name=safe_name,
            path=target,
            size=len(data),
            created_at=datetime.fromtimestamp(info.st_mtime, tz=UTC),
            sha256=hashlib.sha256(data).hexdigest(),
            content_type="text/plain",
        )

    def list(self, session_id: str) -> list[Artifact]:
        """List the artifacts of a session."""
        directory = self._session_dir(session_id)
        artifacts: list[Artifact] = []
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            if not entry.is_file():
                continue
            info = entry.stat()
            artifacts.append(
                Artifact(
                    name=entry.name,
                    path=entry,
                    size=info.st_size,
                    created_at=datetime.fromtimestamp(info.st_mtime, tz=UTC),
                    sha256=hashlib.sha256(entry.read_bytes()).hexdigest(),
                    content_type="text/plain",
                )
            )
        return artifacts


@dataclass
class JobWorkspace:
    """A disposable per-execution workspace handed to a sandbox worker."""

    job_id: str
    root: Path
    input_dir: Path
    output_dir: Path

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def to_dict(self) -> dict[str, Any]:
        return {"job_id": self.job_id, "root": str(self.root)}


def create_job_workspace(job_root: Path, job_id: str | None = None) -> JobWorkspace:
    """Create a fresh, isolated workspace for a single execution."""
    identifier = job_id or uuid.uuid4().hex[:12]
    root = Path(job_root) / identifier
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    input_dir = root / "input"
    output_dir = root / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return JobWorkspace(job_id=identifier, root=root, input_dir=input_dir, output_dir=output_dir)
