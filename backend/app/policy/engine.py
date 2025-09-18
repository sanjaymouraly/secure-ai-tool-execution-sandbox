"""Deterministic, deny-by-default policy engine.

Evaluation order
----------------
1.  **Hard guards** – code enforced invariants (path escapes, shell
    metacharacters, network, oversized arguments).  A guard violation always
    wins; policy can never relax it.
2.  **Policy rules** – administrator controlled rules, evaluated in a stable
    order (descending ``priority``, then ascending ``id``).  The first rule
    whose subject, tool and constraint selectors all match decides.
3.  **Session grants** – previously approved "allow for session" grants.
4.  **Document defaults** – deny unless the policy says otherwise.

Every decision carries a human readable explanation that the dashboard and
the audit trail display verbatim.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..core.commands import CommandAllowlist
from ..core.paths import SafePathResolver
from .guards import GuardContext, GuardViolation, evaluate_guards
from .schema import PolicyDocument, PolicyRule

__all__ = [
    "PolicyDecision",
    "PolicyEngine",
    "PolicyLoadError",
    "argument_signature",
    "canonical_arguments",
]

#: Fields that never participate in an approval signature.
VOLATILE_ARGUMENT_FIELDS = frozenset({"request_id", "trace_id", "reason", "comment"})


class PolicyLoadError(RuntimeError):
    """Raised when a policy document cannot be loaded or validated."""


@dataclass
class PolicyDecision:
    """The outcome of a policy evaluation."""

    allowed: bool
    effect: str  # allow | deny | require_approval
    reason: str
    rule_id: str = ""
    rule_description: str = ""
    policy_version: str = ""
    policy_revision: int = 0
    source: str = "policy"  # policy | guard | grant | default
    explanation: list[str] = field(default_factory=list)
    matched_constraints: list[str] = field(default_factory=list)
    requires_approval: bool = False
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "effect": self.effect,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "rule_description": self.rule_description,
            "policy_version": self.policy_version,
            "policy_revision": self.policy_revision,
            "source": self.source,
            "explanation": list(self.explanation),
            "matched_constraints": list(self.matched_constraints),
            "requires_approval": self.requires_approval,
        }


def canonical_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Return a stable, comparable representation of tool arguments."""
    cleaned = {key: value for key, value in arguments.items() if key not in VOLATILE_ARGUMENT_FIELDS}
    return json.loads(json.dumps(cleaned, sort_keys=True, default=str))


def argument_signature(tool_name: str, arguments: Mapping[str, Any]) -> str:
    """Return a SHA-256 signature of a tool + argument pair.

    The signature is what an approval is bound to.  It can never cover more
    than the exact reviewed action.
    """
    payload = json.dumps(
        {"tool": tool_name, "arguments": canonical_arguments(arguments)},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _glob_match(pattern: str, value: str) -> bool:
    """Match a glob style pattern (``*`` wildcard) against a value."""
    if pattern == "*":
        return True
    regex = re.escape(pattern).replace(r"\*", ".*")
    return re.fullmatch(regex, value or "", flags=re.IGNORECASE) is not None


def _any_glob(patterns: Sequence[str], value: str) -> bool:
    return any(_glob_match(pattern, value) for pattern in patterns)


def _subject_matches(subjects, *, user_id, role, agent_id, project_id, session_id) -> bool:
    """Return True when every configured subject dimension matches."""
    if subjects.users and not _any_glob(subjects.users, user_id):
        return False
    if subjects.agents and not _any_glob(subjects.agents, agent_id):
        return False
    if subjects.roles and not _any_glob(subjects.roles, role):
        return False
    if subjects.projects and not _any_glob(subjects.projects, project_id):
        return False
    return not (subjects.sessions and not _any_glob(subjects.sessions, session_id))


def _path_candidates(arguments: Mapping[str, Any], resolver: SafePathResolver | None) -> list[str]:
    """Return every path form a rule may match against.

    Both the *requested* path and the *resolved* path are considered.  This
    is what stops a symbolic link from laundering a protected path into an
    apparently harmless one: the rule that protects ``protected/secret.txt``
    also matches ``documents/link-to-secret.txt`` because the latter resolves
    to the former.
    """
    raw_values: list[str] = []
    for key, value in arguments.items():
        if isinstance(value, str) and key in (
            "path",
            "directory",
            "file",
            "source",
            "destination",
            "target",
            "root",
        ):
            raw_values.append(value)
        elif isinstance(value, str) and key in ("paths", "files"):
            raw_values.extend(item for item in value.split(",") if item)

    candidates: list[str] = list(raw_values)
    if resolver is None:
        return candidates

    for raw in raw_values:
        try:
            resolved = resolver.resolve(raw, must_exist=False)
        except Exception:  # nosec B112
            continue
        try:
            relative = resolved.relative.as_posix()
        except Exception:
            relative = ""
        if relative:
            candidates.append(relative)
        candidates.append(str(resolved.path))
    return candidates


def _constraint_matches(
    constraints,
    arguments: Mapping[str, Any],
    *,
    path_values: Sequence[str] | None = None,
) -> tuple[bool, list[str]]:
    """Evaluate the constraint selectors of a rule."""
    matched: list[str] = []

    if path_values is None:
        path_values = []
        for key, value in arguments.items():
            if isinstance(value, str) and key in (
                "path",
                "directory",
                "file",
                "source",
                "destination",
                "target",
                "root",
            ):
                path_values.append(value)
            elif isinstance(value, str) and key in ("paths", "files"):
                path_values.extend(item for item in value.split(",") if item)
    path_values = list(path_values)

    if constraints.path_prefixes:
        hit = any(
            any(
                value == prefix
                or value.startswith(prefix.rstrip("/") + "/")
                or ("/" + value.strip("/")).startswith(prefix.strip("/") + "/")
                for prefix in constraints.path_prefixes
            )
            for value in path_values
        )
        if not hit:
            return False, matched
        matched.append(f"path_prefixes={constraints.path_prefixes}")

    if constraints.path_contains:
        hit = any(any(fragment in value for fragment in constraints.path_contains) for value in path_values)
        if not hit:
            return False, matched
        matched.append(f"path_contains={constraints.path_contains}")

    if constraints.path_regex:
        compiled = [re.compile(pattern) for pattern in constraints.path_regex]
        hit = any(any(regex.search(value) for regex in compiled) for value in path_values)
        if not hit:
            return False, matched
        matched.append(f"path_regex={constraints.path_regex}")

    if constraints.allowed_extensions:
        hit = False
        for value in path_values:
            suffix = Path(value).suffix.lower()
            if suffix in constraints.allowed_extensions:
                hit = True
                break
        if not hit:
            return False, matched
        matched.append(f"allowed_extensions={constraints.allowed_extensions}")

    if constraints.denied_extensions:
        hit = any(Path(value).suffix.lower() in constraints.denied_extensions for value in path_values)
        if hit:
            return False, matched
        matched.append(f"denied_extensions={constraints.denied_extensions}")

    if constraints.command_names:
        command = arguments.get("command")
        program = ""
        if isinstance(command, str):
            program = command.strip().split(" ")[0] if command.strip() else ""
        elif isinstance(command, (list, tuple)) and command:
            program = str(command[0])
        if program not in constraints.command_names:
            return False, matched
        matched.append(f"command_names={constraints.command_names}")

    if constraints.argument_patterns:
        payload = json.dumps(dict(arguments), sort_keys=True, default=str)
        compiled = [re.compile(pattern) for pattern in constraints.argument_patterns]
        if not any(regex.search(payload) for regex in compiled):
            return False, matched
        matched.append(f"argument_patterns={constraints.argument_patterns}")

    if constraints.max_path_depth is not None:
        for value in path_values:
            depth = len([part for part in value.split("/") if part])
            if depth > constraints.max_path_depth:
                return False, matched
        matched.append(f"max_path_depth<={constraints.max_path_depth}")

    if constraints.max_argument_bytes is not None:
        payload = json.dumps(dict(arguments), sort_keys=True, default=str)
        if len(payload.encode("utf-8")) > constraints.max_argument_bytes:
            return False, matched
        matched.append(f"max_argument_bytes<={constraints.max_argument_bytes}")

    if constraints.network is not None:
        network_requested = any(
            isinstance(value, str)
            and key.lower() in ("url", "host", "hostname", "endpoint", "uri", "address")
            for key, value in arguments.items()
        )
        if network_requested and constraints.network == "deny":
            return False, matched
        matched.append(f"network={constraints.network}")

    return True, matched


class PolicyEngine:
    """Evaluate tool requests against a versioned policy document."""

    def __init__(
        self,
        document: PolicyDocument,
        *,
        path_resolver: SafePathResolver,
        command_allowlist: CommandAllowlist,
        guard_context: GuardContext | None = None,
    ) -> None:
        self.document = document
        self.path_resolver = path_resolver
        self.command_allowlist = command_allowlist
        self.guard_context = guard_context or GuardContext(
            path_resolver=path_resolver, command_allowlist=command_allowlist
        )
        self._ordered_rules: list[PolicyRule] = sorted(
            (rule for rule in document.rules if rule.enabled),
            key=lambda rule: (-rule.priority, rule.id),
        )

    # ------------------------------------------------------------- factory
    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        path_resolver: SafePathResolver,
        command_allowlist: CommandAllowlist,
        guard_context: GuardContext | None = None,
    ) -> PolicyEngine:
        """Load and validate a policy document from a YAML or JSON file."""
        if not path.exists():
            raise PolicyLoadError(f"Policy file not found: {path}")
        raw = path.read_text(encoding="utf-8")
        try:
            if path.suffix.lower() in {".yaml", ".yml"}:
                data = yaml.safe_load(raw)
            else:
                data = json.loads(raw)
        except yaml.YAMLError as exc:
            raise PolicyLoadError(f"Policy file is not valid YAML: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyLoadError(f"Policy file is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise PolicyLoadError("Policy document must be a mapping")
        try:
            document = PolicyDocument.model_validate(data)
        except Exception as exc:
            raise PolicyLoadError(f"Policy document failed schema validation: {exc}") from exc
        return cls(
            document,
            path_resolver=path_resolver,
            command_allowlist=command_allowlist,
            guard_context=guard_context,
        )

    # ------------------------------------------------------------ metadata
    @property
    def version(self) -> str:
        return self.document.version

    @property
    def revision(self) -> int:
        return self.document.revision

    def rules(self) -> list[dict[str, Any]]:
        """Return the rules in evaluation order for the policy editor UI."""
        return [rule.model_dump(mode="json") for rule in self._ordered_rules]

    # ----------------------------------------------------------- evaluation
    def evaluate(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        user_id: str = "",
        role: str = "",
        agent_id: str = "",
        project_id: str = "",
        session_id: str = "",
        session_grants: Iterable[Any] = (),
    ) -> PolicyDecision:
        """Evaluate a tool request and return the decision."""
        explanation: list[str] = []
        arguments = dict(arguments or {})

        # ------------------------------------------------ 1. hard guards
        violations: list[GuardViolation] = evaluate_guards(tool_name, arguments, self.guard_context)
        if violations:
            for violation in violations:
                explanation.append(f"Hard guard [{violation.rule_id}]: {violation.message}")
            return PolicyDecision(
                allowed=False,
                effect="deny",
                reason=violations[0].message,
                rule_id=violations[0].rule_id,
                rule_description="Hard guard (code enforced invariant)",
                policy_version=self.document.version,
                policy_revision=self.document.revision,
                source="guard",
                explanation=explanation,
            )
        explanation.append("All hard guards passed.")

        # ------------------------------------------------ 2. session grants
        signature = argument_signature(tool_name, arguments)
        for grant in session_grants or ():
            if not _grant_matches(grant, tool_name, signature):
                continue
            if getattr(grant, "expires_at", None) is not None:
                expires = grant.expires_at
                if expires.tzinfo is None:
                    import datetime as _dt

                    expires = expires.replace(tzinfo=_dt.UTC)
                if expires.timestamp() < time.time():
                    explanation.append(f"Session grant {grant.id} has expired.")
                    continue
            explanation.append(f"Session grant {grant.id} authorised '{tool_name}' for this session.")
            return PolicyDecision(
                allowed=True,
                effect="allow",
                reason="Action covered by an approved session grant",
                rule_id=f"grant:{getattr(grant, 'id', 'unknown')}",
                rule_description="Session scoped grant",
                policy_version=self.document.version,
                policy_revision=self.document.revision,
                source="grant",
                explanation=explanation,
            )

        # ------------------------------------------------ 3. policy rules
        effective_paths = _path_candidates(arguments, self.path_resolver)
        for rule in self._ordered_rules:
            if not _any_glob(rule.tools, tool_name):
                continue
            if not _subject_matches(
                rule.subjects,
                user_id=user_id,
                role=role,
                agent_id=agent_id,
                project_id=project_id,
                session_id=session_id,
            ):
                continue
            matched, matched_constraints = _constraint_matches(
                rule.constraints, arguments, path_values=effective_paths
            )
            if not matched:
                continue

            explanation.append(f"Rule '{rule.id}' matched tool='{tool_name}' priority={rule.priority}.")
            if matched_constraints:
                explanation.append("Matched constraints: " + ", ".join(matched_constraints))

            requires_approval = rule.requires_approval or rule.effect == "require_approval"
            reason = rule.reason or rule.description or f"Rule '{rule.id}' applied"

            if rule.effect == "deny":
                explanation.append(f"Effect: deny -> {reason}")
                return PolicyDecision(
                    allowed=False,
                    effect="deny",
                    reason=reason,
                    rule_id=rule.id,
                    rule_description=rule.description,
                    policy_version=self.document.version,
                    policy_revision=self.document.revision,
                    source="policy",
                    explanation=explanation,
                    matched_constraints=matched_constraints,
                )

            if requires_approval:
                explanation.append(f"Effect: require_approval -> {reason}")
                return PolicyDecision(
                    allowed=False,
                    effect="require_approval",
                    reason=reason,
                    rule_id=rule.id,
                    rule_description=rule.description,
                    policy_version=self.document.version,
                    policy_revision=self.document.revision,
                    source="policy",
                    explanation=explanation,
                    matched_constraints=matched_constraints,
                    requires_approval=True,
                )

            explanation.append(f"Effect: allow -> {reason}")
            return PolicyDecision(
                allowed=True,
                effect="allow",
                reason=reason,
                rule_id=rule.id,
                rule_description=rule.description,
                policy_version=self.document.version,
                policy_revision=self.document.revision,
                source="policy",
                explanation=explanation,
                matched_constraints=matched_constraints,
            )

        # ------------------------------------------------ 4. defaults
        default_effect = self.document.defaults.effect
        default_reason = self.document.defaults.reason
        explanation.append(f"No policy rule matched; default effect is '{default_effect}'.")
        if default_effect == "allow":
            return PolicyDecision(
                allowed=True,
                effect="allow",
                reason=default_reason,
                rule_id="default",
                rule_description="Document default",
                policy_version=self.document.version,
                policy_revision=self.document.revision,
                source="default",
                explanation=explanation,
            )
        if default_effect == "require_approval":
            return PolicyDecision(
                allowed=False,
                effect="require_approval",
                reason=default_reason,
                rule_id="default",
                rule_description="Document default",
                policy_version=self.document.version,
                policy_revision=self.document.revision,
                source="default",
                explanation=explanation,
                requires_approval=True,
            )
        return PolicyDecision(
            allowed=False,
            effect="deny",
            reason=default_reason,
            rule_id="default",
            rule_description="Document default",
            policy_version=self.document.version,
            policy_revision=self.document.revision,
            source="default",
            explanation=explanation,
        )


def _grant_matches(grant: Any, tool_name: str, signature: str) -> bool:
    """Return True when a session grant covers this exact action."""
    if getattr(grant, "tool_name", None) != tool_name:
        return False
    if getattr(grant, "argument_hash", None) != signature:
        return False
    return getattr(grant, "uses_remaining", -1) != 0
