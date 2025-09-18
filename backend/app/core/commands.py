"""Command allowlist and argument validation.

Commands are never executed through a shell.  The allowlist operates on an
``argv`` vector, rejects shell metacharacters outright, applies per-command
argument rules and matches the resolved executable against an allowlist of
absolute paths so that a poisoned ``PATH`` cannot be used to smuggle a
different binary into the sandbox.
"""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["CommandAllowlist", "CommandRejection", "CommandRule"]


class CommandRejection(Exception):
    """Raised when a command request violates a command safety invariant."""

    def __init__(self, message: str, code: str = "command_rejected") -> None:
        super().__init__(message)
        self.code = code


#: Characters that enable shell control flow, substitution or redirection.
#: Quotes are excluded here because ``shlex`` consumes them while parsing and
#: the command is never handed to a shell.  They are still rejected inside an
#: individual argument (see ``_DANGEROUS_ARGUMENT_CHARS``).
_SHELL_METACHARACTERS = re.compile(r"[|&;`<>$()\n\r\\\x00]")

#: Characters that are rejected inside a single, already parsed argument.
_DANGEROUS_ARGUMENT_CHARS = re.compile(r"[|&;`<>$()\n\r\\\x00\"']")

#: Flag prefixes that are never acceptable in an allowed command line.
_DANGEROUS_FLAGS = (
    "--exec",
    "--output",
    "-o",
    "--to",
    "--input-file",
    "--file",
    "-f",
    "--source",
    "--preload",
    "-m",
    "--require",
    "-r",
    "--load-plugins",
    "--plugin",
    "--proxy",
    "--config",
)

#: Absolute directories that may contain an allowlisted executable.
_SAFE_BIN_DIRS = (
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/sbin",
    "/sbin",
)


@dataclass(frozen=True)
class CommandRule:
    """A single allowlisted command."""

    name: str
    description: str = ""
    #: Optional regular expression the full argv must match.
    argv_pattern: str | None = None
    #: Max number of positional arguments.
    max_args: int = 16
    #: Flags that may not be used with this command.
    denied_flags: tuple[str, ...] = ()
    #: Flags that must not carry a value.
    denied_flag_values: tuple[str, ...] = ()
    #: Whether the command may be used with a working directory argument.
    allow_cwd: bool = False
    #: Maximum number of characters in a single argument.
    max_arg_length: int = 4096
    #: Optional compiled argv pattern cache.
    _compiled: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def compiled(self) -> re.Pattern[str] | None:
        if self.argv_pattern is None:
            return None
        if self._compiled is None:
            object.__setattr__(self, "_compiled", re.compile(self.argv_pattern))
        return self._compiled


class CommandAllowlist:
    """Deny-by-default allowlist for command execution."""

    def __init__(self, rules: Iterable[CommandRule] | None = None) -> None:
        self._rules: dict[str, CommandRule] = {}
        for rule in rules or ():
            self._rules[rule.name] = rule

    # ------------------------------------------------------------- registry
    def register(self, rule: CommandRule) -> None:
        self._rules[rule.name] = rule

    def rules(self) -> list[CommandRule]:
        return sorted(self._rules.values(), key=lambda item: item.name)

    def get(self, name: str) -> CommandRule | None:
        return self._rules.get(name)

    def names(self) -> list[str]:
        return sorted(self._rules)

    # ------------------------------------------------------------- parsing
    @staticmethod
    def split(command: str) -> list[str]:
        """Split a command string into argv without invoking a shell."""
        if not command or not command.strip():
            raise CommandRejection("Command must not be empty", "command_empty")
        if len(command) > 8192:
            raise CommandRejection("Command string is too long", "command_too_long")
        if _SHELL_METACHARACTERS.search(command):
            raise CommandRejection(
                "Command contains shell metacharacters; shell interpretation is disabled",
                "command_shell_metacharacters",
            )
        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            raise CommandRejection(f"Command could not be parsed: {exc}", "command_unparsable") from exc
        if not argv:
            raise CommandRejection("Command must not be empty", "command_empty")
        return argv

    # ----------------------------------------------------------- validation
    def validate(self, argv: Sequence[str]) -> CommandRule:
        """Validate an argv vector against the allowlist.

        Returns the matched rule.  Raises :class:`CommandRejection` otherwise.
        """
        if not argv:
            raise CommandRejection("Command must not be empty", "command_empty")
        if len(argv) > 64:
            raise CommandRejection("Too many command arguments", "command_too_many_args")

        program = argv[0]
        if os.path.isabs(program):
            raise CommandRejection(
                "Absolute program paths are not permitted; use a command name",
                "command_absolute_path",
            )
        if "/" in program:
            raise CommandRejection(
                "Program names may not contain a path separator",
                "command_path_separator",
            )
        if program.startswith("-"):
            raise CommandRejection("Program name must not be a flag", "command_invalid_program")

        rule = self._rules.get(program)
        if rule is None:
            raise CommandRejection(
                f"Command '{program}' is not in the allowlist",
                "command_not_allowlisted",
            )

        positional: list[str] = []
        for arg in argv[1:]:
            if len(arg) > rule.max_arg_length:
                raise CommandRejection(
                    f"Argument exceeds {rule.max_arg_length} characters",
                    "command_argument_too_long",
                )
            if _DANGEROUS_ARGUMENT_CHARS.search(arg):
                raise CommandRejection(
                    "Argument contains shell metacharacters",
                    "command_argument_metacharacters",
                )
            if arg.startswith("-"):
                flag = arg.split("=", 1)[0]
                if flag in rule.denied_flags:
                    raise CommandRejection(
                        f"Flag '{flag}' is not permitted for '{program}'",
                        "command_flag_denied",
                    )
                if flag in rule.denied_flag_values:
                    raise CommandRejection(
                        f"Flag '{flag}' may not be used with '{program}'",
                        "command_flag_denied",
                    )
                if flag in _DANGEROUS_FLAGS and flag not in rule.denied_flags:
                    raise CommandRejection(
                        f"Flag '{flag}' is not permitted in the sandbox",
                        "command_flag_denied",
                    )
            else:
                positional.append(arg)

        if len(positional) > rule.max_args:
            raise CommandRejection(
                f"Command '{program}' accepts at most {rule.max_args} positional arguments",
                "command_too_many_args",
            )

        pattern = rule.compiled()
        if pattern is not None:
            joined = " ".join(argv)
            if not pattern.search(joined):
                raise CommandRejection(
                    f"Command line does not match the approved pattern for '{program}'",
                    "command_pattern_mismatch",
                )

        return rule

    def validate_executable(self, executable_paths: Iterable[Path]) -> Path:
        """Verify that a resolved executable lives in a trusted bin directory."""
        for candidate in executable_paths:
            resolved = Path(candidate).resolve()
            if any(str(resolved).startswith(f"{directory}/") for directory in _SAFE_BIN_DIRS):
                return resolved
        raise CommandRejection(
            "Resolved executable is not located in a trusted bin directory",
            "command_untrusted_executable",
        )
