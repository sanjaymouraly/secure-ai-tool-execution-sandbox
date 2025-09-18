"""Filesystem path safety tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.paths import PathError, SafePathResolver, has_shell_metacharacters, is_forbidden_absolute


@pytest.fixture()
def resolver(tmp_path: Path) -> SafePathResolver:
    root = tmp_path / "workspace"
    (root / "documents").mkdir(parents=True)
    (root / "documents" / "safe.txt").write_text("hello", encoding="utf-8")
    (root / "protected").mkdir()
    (root / "protected" / "secret.txt").write_text("secret", encoding="utf-8")
    return SafePathResolver([root])


@pytest.mark.parametrize(
    "path",
    [
        "../etc/passwd",
        "../../etc/passwd",
        "documents/../../etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252f",
        "documents/../../../../etc/shadow",
    ],
)
def test_traversal_is_rejected(resolver: SafePathResolver, path: str) -> None:
    with pytest.raises(PathError):
        resolver.resolve(path)


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "/proc/self/environ", "/sys/kernel", "/var/run/docker.sock", "/root/.ssh/id_rsa"],
)
def test_absolute_escape_is_rejected(resolver: SafePathResolver, path: str) -> None:
    with pytest.raises(PathError):
        resolver.resolve(path)


def test_nul_byte_is_rejected(resolver: SafePathResolver) -> None:
    with pytest.raises(PathError):
        resolver.resolve("documents/safe\x00.txt")


def test_backslash_is_rejected(resolver: SafePathResolver) -> None:
    with pytest.raises(PathError):
        resolver.resolve("documents\\..\\..\\etc\\passwd")


def test_valid_relative_path_resolves(resolver: SafePathResolver) -> None:
    resolved = resolver.resolve("documents/safe.txt")
    assert resolved.path.name == "safe.txt"
    assert resolved.relative.as_posix() == "documents/safe.txt"


def test_symlink_outside_workspace_is_rejected(resolver: SafePathResolver, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = resolver.roots[0] / "escape.txt"
    link.symlink_to(outside)
    with pytest.raises(PathError) as excinfo:
        resolver.resolve("escape.txt")
    assert excinfo.value.code in {"path_symlink_escape", "path_outside_workspace"}


def test_symlink_inside_workspace_is_resolved(resolver: SafePathResolver) -> None:
    link = resolver.roots[0] / "link.txt"
    link.symlink_to(resolver.roots[0] / "documents" / "safe.txt")
    resolved = resolver.resolve("link.txt")
    assert resolved.path.name == "safe.txt"


def test_hardlink_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    original = root / "a.txt"
    original.write_text("data", encoding="utf-8")
    import os

    os.link(original, root / "b.txt")
    with pytest.raises(PathError) as excinfo:
        SafePathResolver.open_readonly(root / "b.txt")
    assert excinfo.value.code == "path_hardlink_forbidden"


def test_write_atomic_refuses_existing_file(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "a.txt"
    SafePathResolver.write_atomic(target, b"one")
    with pytest.raises(PathError):
        SafePathResolver.write_atomic(target, b"two")


def test_write_atomic_creates_file(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "a.txt"
    SafePathResolver.write_atomic(target, b"content")
    assert target.read_bytes() == b"content"


def test_readonly_open_blocks_symlink(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    real = root / "real.txt"
    real.write_text("x", encoding="utf-8")
    link = root / "link.txt"
    link.symlink_to(real)
    with pytest.raises(PathError):
        SafePathResolver.open_readonly(link)


def test_forbidden_absolute_paths() -> None:
    assert is_forbidden_absolute("/etc/passwd")
    assert is_forbidden_absolute("/proc/self/environ")
    assert not is_forbidden_absolute("documents/report.md")


def test_shell_metacharacter_detection() -> None:
    assert has_shell_metacharacters("ls; rm")
    assert has_shell_metacharacters("ls `id`")
    assert has_shell_metacharacters("ls $(id)")
    assert not has_shell_metacharacters("ls -la documents")
