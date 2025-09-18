"""Read-only filesystem tools.

These tools operate inside the approved workspace.  They never execute
untrusted content and never leave the workspace root: the path resolver
rejects traversal, symlink escapes, absolute escapes, encoded traversal and
hard-linked files before any I/O happens.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ..core.paths import PathError
from .base import ToolContext, ToolInput, ToolResult, pydantic_validate

#: The hard ceiling on the number of entries a single listing may return.
MAX_DIRECTORY_ENTRIES = 5_000


class ListFilesInput(ToolInput):
    path: str = Field(default=".", description="Directory to list, relative to the approved workspace.")
    recursive: bool = Field(default=False, description="Descend into sub directories.")
    max_entries: int = Field(default=500, ge=1, le=5000, description="Maximum number of entries to return.")


class ReadFileInput(ToolInput):
    path: str = Field(description="File to read, relative to the approved workspace.")
    max_bytes: int = Field(
        default=200_000, ge=1, le=1_048_576, description="Maximum number of bytes to read."
    )


class SearchFilesInput(ToolInput):
    pattern: str = Field(min_length=1, max_length=500, description="Regular expression to search for.")
    path: str = Field(default=".", description="Directory or file to search in.")
    max_results: int = Field(default=100, ge=1, le=500, description="Maximum number of matches to return.")
    case_sensitive: bool = Field(default=False, description="Perform a case sensitive search.")


class InspectMetadataInput(ToolInput):
    path: str = Field(description="Path to inspect, relative to the approved workspace.")


class CalculateHashInput(ToolInput):
    path: str = Field(description="File to hash, relative to the approved workspace.")
    algorithm: str = Field(default="sha256", description="Hash algorithm (sha256, sha512, sha1, md5).")


async def list_files(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """List the contents of an approved directory."""
    payload = pydantic_validate(ListFilesInput, arguments)
    try:
        max_entries = min(payload.max_entries, MAX_DIRECTORY_ENTRIES)
        entries = context.workspace.list_directory(
            payload.path,
            recursive=payload.recursive,
            max_entries=max_entries,
        )
    except PathError as exc:
        return ToolResult(ok=False, error=str(exc), error_code=exc.code)
    return ToolResult(
        ok=True,
        output={"path": payload.path, "count": len(entries), "entries": entries},
        metadata={"recursive": payload.recursive},
    )


async def read_file(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Read an approved text file."""
    payload = pydantic_validate(ReadFileInput, arguments)
    try:
        content = context.workspace.read_text(payload.path, max_bytes=payload.max_bytes)
    except PathError as exc:
        return ToolResult(ok=False, error=str(exc), error_code=exc.code)
    return ToolResult(
        ok=True,
        output={
            "path": payload.path,
            "content": content,
            "bytes": len(content.encode("utf-8")),
            "lines": content.count("\n") + 1 if content else 0,
        },
        metadata={"truncated": len(content.encode("utf-8")) >= payload.max_bytes},
    )


async def search_files(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Search approved files for a regular expression."""
    payload = pydantic_validate(SearchFilesInput, arguments)
    try:
        matches = context.workspace.search(
            payload.pattern,
            path=payload.path,
            max_results=payload.max_results,
            case_sensitive=payload.case_sensitive,
        )
    except PathError as exc:
        return ToolResult(ok=False, error=str(exc), error_code=exc.code)
    return ToolResult(
        ok=True,
        output={"pattern": payload.pattern, "count": len(matches), "matches": matches},
    )


async def inspect_metadata(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Return metadata (size, mode, timestamps) for an approved path."""
    payload = pydantic_validate(InspectMetadataInput, arguments)
    try:
        info = context.workspace.metadata(payload.path)
    except PathError as exc:
        return ToolResult(ok=False, error=str(exc), error_code=exc.code)
    return ToolResult(ok=True, output=info)


async def calculate_hash(context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
    """Calculate the cryptographic hash of an approved file."""
    payload = pydantic_validate(CalculateHashInput, arguments)
    try:
        info = context.workspace.hash_file(payload.path, payload.algorithm)
    except PathError as exc:
        return ToolResult(ok=False, error=str(exc), error_code=exc.code)
    except Exception as exc:
        return ToolResult(ok=False, error=str(exc), error_code="hash_failed")
    return ToolResult(ok=True, output=info)
