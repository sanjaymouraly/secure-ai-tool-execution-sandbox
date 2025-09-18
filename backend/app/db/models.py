"""ORM models for the Secure AI Tool Execution & Permission Sandbox."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, IdMixin, TimestampMixin, utcnow

__all__ = [
    "AgentSession",
    "Approval",
    "AttackLabRun",
    "AuditEvent",
    "Base",
    "Execution",
    "Message",
    "PolicyDocument",
    "Project",
    "ProviderProfile",
    "SessionGrant",
    "UsageRecord",
    "User",
]


class User(IdMixin, TimestampMixin, Base):
    """An authenticated principal."""

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="analyst", nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sessions: Mapped[list[AgentSession]] = relationship(back_populates="user")

    @property
    def is_admin(self) -> bool:
        return self.is_superuser or self.role == "admin"


class Project(IdMixin, TimestampMixin, Base):
    """A logical grouping of sessions with its own permission scope."""

    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    owner: Mapped[User] = relationship()


class AgentSession(IdMixin, TimestampMixin, Base):
    """An agent conversation and its execution history."""

    __tablename__ = "agent_sessions"

    title: Mapped[str] = mapped_column(String(255), default="New session", nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id"), nullable=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), default="simulation", nullable=False)
    model: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    system_prompt: Mapped[str] = mapped_column(Text, default="", nullable=False)
    step_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    approved_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cancelled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    user: Mapped[User] = relationship(back_populates="sessions")
    project: Mapped[Project | None] = relationship()
    messages: Mapped[list[Message]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="Message.sequence"
    )
    executions: Mapped[list[Execution]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="Execution.created_at"
    )
    approvals: Mapped[list[Approval]] = relationship(back_populates="session", cascade="all, delete-orphan")
    grants: Mapped[list[SessionGrant]] = relationship(back_populates="session", cascade="all, delete-orphan")
    usage_records: Mapped[list[UsageRecord]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class Message(IdMixin, TimestampMixin, Base):
    """A single conversation turn (system/user/assistant/tool)."""

    __tablename__ = "messages"
    __table_args__ = (Index("ix_messages_session_sequence", "session_id", "sequence"),)

    session_id: Mapped[str] = mapped_column(ForeignKey("agent_sessions.id"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tool_calls: Mapped[list | None] = mapped_column(JSON, nullable=True)
    tool_call_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_untrusted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    usage_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    session: Mapped[AgentSession] = relationship(back_populates="messages")


class Execution(IdMixin, TimestampMixin, Base):
    """A single tool invocation and its outcome."""

    __tablename__ = "executions"
    __table_args__ = (Index("ix_executions_session_created", "session_id", "created_at"),)

    session_id: Mapped[str | None] = mapped_column(ForeignKey("agent_sessions.id"), nullable=True, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    trace_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    arguments: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    redacted_arguments: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    decision_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    policy_rule_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    approval_id: Mapped[str | None] = mapped_column(ForeignKey("approvals.id"), nullable=True, index=True)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output: Mapped[str] = mapped_column(Text, default="", nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cpu_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    memory_peak_mb: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    output_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sandbox_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    sandbox_backend: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    timed_out: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    step_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    session: Mapped[AgentSession | None] = relationship(back_populates="executions")
    approval: Mapped[Approval | None] = relationship(back_populates="executions")


class Approval(IdMixin, TimestampMixin, Base):
    """A human approval request for a sensitive action."""

    __tablename__ = "approvals"

    session_id: Mapped[str | None] = mapped_column(ForeignKey("agent_sessions.id"), nullable=True, index=True)
    requested_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    arguments: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    redacted_arguments: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    argument_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    risk: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False, index=True)
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope: Mapped[str] = mapped_column(String(16), default="once", nullable=False)

    session: Mapped[AgentSession | None] = relationship(back_populates="approvals")
    executions: Mapped[list[Execution]] = relationship(back_populates="approval")


class SessionGrant(IdMixin, TimestampMixin, Base):
    """A session scoped grant produced by an 'Allow for session' decision."""

    __tablename__ = "session_grants"
    __table_args__ = (UniqueConstraint("session_id", "tool_name", "argument_hash", name="uq_grant_scope"),)

    session_id: Mapped[str] = mapped_column(ForeignKey("agent_sessions.id"), nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    argument_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    granted_by: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    uses_remaining: Mapped[int] = mapped_column(Integer, default=-1, nullable=False)

    session: Mapped[AgentSession] = relationship(back_populates="grants")


class PolicyDocument(IdMixin, TimestampMixin, Base):
    """A versioned policy document."""

    __tablename__ = "policy_documents"

    version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    name: Mapped[str] = mapped_column(String(128), default="default", nullable=False)
    content: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_by: Mapped[str] = mapped_column(String(64), default="system", nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)


class AuditEvent(IdMixin, Base):
    """An append-only audit record with an integrity chain."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_sequence", "sequence"),
        Index("ix_audit_actor_created", "actor_id", "created_at"),
    )

    sequence: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_role: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(32), default="", nullable=False, index=True)
    policy_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    policy_rule_id: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    target: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    arguments: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    redacted_arguments: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    result_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    sandbox_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    approval_decision: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    approved_by: Mapped[str] = mapped_column(String(64), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    chain_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class ProviderProfile(IdMixin, TimestampMixin, Base):
    """A stored AI provider configuration (API keys are encrypted)."""

    __tablename__ = "provider_profiles"

    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    provider_type: Mapped[str] = mapped_column(String(32), nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    model: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_key_hint: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    extra_headers: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    options: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cost_per_1k_input: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    cost_per_1k_output: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_test_message: Mapped[str] = mapped_column(Text, default="", nullable=False)


class UsageRecord(IdMixin, TimestampMixin, Base):
    """Token usage and estimated cost for a provider call."""

    __tablename__ = "usage_records"

    session_id: Mapped[str | None] = mapped_column(ForeignKey("agent_sessions.id"), nullable=True, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    call_type: Mapped[str] = mapped_column(String(32), default="chat", nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    session: Mapped[AgentSession | None] = relationship(back_populates="usage_records")


class AttackLabRun(IdMixin, TimestampMixin, Base):
    """The result of running a single prompt-injection scenario."""

    __tablename__ = "attack_lab_runs"

    scenario_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scenario_title: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="", nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    expectation: Mapped[str] = mapped_column(String(16), default="deny", nullable=False)
    observed_outcome: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    attack_input: Mapped[str] = mapped_column(Text, default="", nullable=False)
    proposed_tool_call: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    policy_decision: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    execution_result: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    trace_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
