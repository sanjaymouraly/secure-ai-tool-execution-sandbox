"""Strict schema for versioned policy documents.

Policies are YAML or JSON documents validated with Pydantic.  Unknown fields
are rejected so that a typo in a policy file fails loudly instead of silently
disabling a control.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Effect = Literal["allow", "deny", "require_approval"]
PathEffect = Literal["allow", "deny"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PolicySubjects(_Strict):
    """Dimension selectors for a rule.  An empty list means "any"."""

    users: list[str] = Field(default_factory=list)
    agents: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    projects: list[str] = Field(default_factory=list)
    sessions: list[str] = Field(default_factory=list)


class PolicyConstraints(_Strict):
    """Additional conditions that a request must satisfy for a rule to apply."""

    path_prefixes: list[str] = Field(default_factory=list)
    path_contains: list[str] = Field(default_factory=list)
    path_regex: list[str] = Field(default_factory=list)
    allowed_extensions: list[str] = Field(default_factory=list)
    denied_extensions: list[str] = Field(default_factory=list)
    command_names: list[str] = Field(default_factory=list)
    argument_patterns: list[str] = Field(default_factory=list)
    max_path_depth: int | None = Field(default=None, ge=0, le=64)
    max_argument_bytes: int | None = Field(default=None, ge=0)
    network: PathEffect | None = None

    @field_validator("allowed_extensions", "denied_extensions")
    @classmethod
    def _normalise_extensions(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            ext = item.strip().lower()
            if not ext.startswith("."):
                ext = f".{ext}"
            cleaned.append(ext)
        return cleaned


class PolicyRule(_Strict):
    """A single policy rule."""

    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    description: str = Field(default="", max_length=2000)
    effect: Effect
    priority: int = Field(default=100, ge=0, le=10_000)
    enabled: bool = True
    tools: list[str] = Field(default_factory=lambda: ["*"])
    subjects: PolicySubjects = Field(default_factory=PolicySubjects)
    constraints: PolicyConstraints = Field(default_factory=PolicyConstraints)
    reason: str = Field(default="", max_length=2000)
    requires_approval: bool = False

    @field_validator("tools")
    @classmethod
    def _validate_tools(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("A rule must reference at least one tool")
        return value


class PolicyDefaults(_Strict):
    """The outcome used when no rule matches."""

    effect: Effect = "deny"
    reason: str = "Default deny: no policy rule matched this request"


class PolicyDocument(_Strict):
    """A complete, versioned policy document."""

    version: str = Field(default="1.0.0", max_length=32)
    revision: int = Field(default=1, ge=1)
    name: str = Field(default="default", max_length=128)
    description: str = Field(default="", max_length=4000)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    rules: list[PolicyRule] = Field(default_factory=list)
    tool_risk: dict[str, str] = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)

    @field_validator("rules")
    @classmethod
    def _unique_rule_ids(cls, value: list[PolicyRule]) -> list[PolicyRule]:
        seen: set[str] = set()
        for rule in value:
            if rule.id in seen:
                raise ValueError(f"Duplicate policy rule id: {rule.id}")
            seen.add(rule.id)
        return value
