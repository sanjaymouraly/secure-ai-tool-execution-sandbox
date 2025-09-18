"""Command allowlist tests."""

from __future__ import annotations

import pytest

from app.core.commands import CommandAllowlist, CommandRejection, CommandRule


@pytest.fixture()
def allowlist() -> CommandAllowlist:
    return CommandAllowlist(
        [
            CommandRule(name="ls", description="list", max_args=4),
            CommandRule(name="cat", description="cat", max_args=4),
            CommandRule(name="echo", description="echo", max_args=4),
        ]
    )


@pytest.mark.parametrize(
    "command",
    [
        "ls; rm -rf /",
        "ls && cat /etc/passwd",
        "ls | tee /tmp/x",
        "ls `id`",
        "ls $(id)",
        "ls > /etc/passwd",
        "ls\nid",
    ],
)
def test_shell_metacharacters_are_rejected(allowlist: CommandAllowlist, command: str) -> None:
    with pytest.raises(CommandRejection) as excinfo:
        allowlist.validate(allowlist.split(command))
    assert excinfo.value.code in {"command_shell_metacharacters", "command_unparsable"}


def test_quotes_inside_a_parsed_argument_are_rejected(allowlist: CommandAllowlist) -> None:
    with pytest.raises(CommandRejection) as excinfo:
        allowlist.validate(["echo", "it's"])
    assert excinfo.value.code == "command_argument_metacharacters"


@pytest.mark.parametrize("command", ["rm -rf /", "curl http://x", "bash -c ls", "sudo id", "chmod 777 /"])
def test_non_allowlisted_commands_are_rejected(allowlist: CommandAllowlist, command: str) -> None:
    with pytest.raises(CommandRejection) as excinfo:
        allowlist.validate(allowlist.split(command))
    assert excinfo.value.code == "command_not_allowlisted"


def test_absolute_program_path_is_rejected(allowlist: CommandAllowlist) -> None:
    with pytest.raises(CommandRejection) as excinfo:
        allowlist.validate(["/bin/ls"])
    assert excinfo.value.code == "command_absolute_path"


def test_path_separator_in_program_is_rejected(allowlist: CommandAllowlist) -> None:
    with pytest.raises(CommandRejection) as excinfo:
        allowlist.validate(["./ls"])
    assert excinfo.value.code == "command_path_separator"


def test_too_many_arguments_are_rejected(allowlist: CommandAllowlist) -> None:
    with pytest.raises(CommandRejection) as excinfo:
        allowlist.validate(["ls", "a", "b", "c", "d", "e"])
    assert excinfo.value.code == "command_too_many_args"


def test_valid_command_is_accepted(allowlist: CommandAllowlist) -> None:
    rule = allowlist.validate(["ls", "-la", "documents"])
    assert rule.name == "ls"


def test_flag_smuggling_is_rejected(allowlist: CommandAllowlist) -> None:
    with pytest.raises(CommandRejection) as excinfo:
        allowlist.validate(["ls", "--output=/etc/passwd"])
    assert excinfo.value.code == "command_flag_denied"


def test_argv_pattern_must_match() -> None:
    allowlist = CommandAllowlist(
        [CommandRule(name="grep", argv_pattern=r"^grep\s+-[a-zA-Z]+\s+\S+$", max_args=4)]
    )
    allowlist.validate(["grep", "-i", "needle"])
    with pytest.raises(CommandRejection) as excinfo:
        allowlist.validate(["grep", "-i", "needle", "extra", "args"])
    assert excinfo.value.code in {"command_pattern_mismatch", "command_too_many_args"}


def test_split_handles_quotes_without_shell() -> None:
    allowlist = CommandAllowlist()
    assert allowlist.split("echo 'hello world'") == ["echo", "hello world"]
