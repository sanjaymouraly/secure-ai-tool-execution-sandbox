"""The execution broker - the single enforcement point.

Every tool call, no matter who originated it (the dashboard, the agent loop,
the attack laboratory or a script), passes through :meth:`ToolBroker.execute`.

The order of operations is fixed and cannot be skipped:

1.  **Schema validation** - unknown tools and malformed arguments are rejected.
2.  **Policy evaluation** - the deterministic policy engine plus the hard
    guards decide whether the action is allowed, denied or needs approval.
3.  **Approval** - when approval is required the action is parked until a
    human decides, and the approval is re-validated immediately before use.
4.  **Execution** - only then is the tool handler invoked.
5.  **Audit** - the decision, the result and the sandbox identity are recorded.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..core.commands import CommandAllowlist, CommandRule
from ..core.paths import SafePathResolver
from ..core.redaction import redact
from ..db.models import AgentSession, Execution, User
from ..policy.engine import PolicyDecision, PolicyEngine, argument_signature
from ..sandbox.base import SandboxBackend, SandboxRequest, SandboxResult
from ..tools.base import ToolContext, ToolError, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)


#: The default command allowlist.  Only read-only inspection commands are
#: enabled by default; an administrator can extend it through the policy
#: document or the API.
DEFAULT_COMMAND_RULES = (
    CommandRule(name="ls", description="List directory contents", max_args=8),
    CommandRule(name="cat", description="Print file contents", max_args=8),
    CommandRule(name="head", description="Print the first lines of a file", max_args=8),
    CommandRule(name="tail", description="Print the last lines of a file", max_args=8),
    CommandRule(name="wc", description="Count lines, words and characters", max_args=8),
    CommandRule(name="sort", description="Sort lines", max_args=8),
    CommandRule(name="uniq", description="Filter duplicate lines", max_args=8),
    CommandRule(name="grep", description="Search for a pattern", max_args=12),
    CommandRule(name="find", description="Find files by name", max_args=12),
    CommandRule(name="echo", description="Print arguments", max_args=16),
    CommandRule(name="pwd", description="Print the working directory", max_args=0),
    CommandRule(name="stat", description="Show file metadata", max_args=8),
    CommandRule(name="sha256sum", description="Compute a SHA-256 digest", max_args=8),
    CommandRule(name="diff", description="Compare two files", max_args=8),
    CommandRule(name="sed", description="Stream editor (print mode only)", max_args=12),
    CommandRule(name="true", description="Do nothing successfully", max_args=0),
)


@dataclass
class BrokerResult:
    """The outcome of a brokered tool call."""

    execution: Execution
    decision: PolicyDecision
    tool_result: ToolResult | None = None
    status: str = "completed"
    error: str | None = None
    trace_id: str = ""
    sandbox: SandboxResult | None = None
    approval_required: bool = False
    approval_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution.id,
            "trace_id": self.trace_id,
            "tool_name": self.execution.tool_name,
            "status": self.status,
            "decision": self.decision.to_dict(),
            "approval_required": self.approval_required,
            "approval_id": self.approval_id,
            "output": self.execution.output,
            "error": self.error or self.execution.error,
            "exit_code": self.execution.exit_code,
            "duration_ms": self.execution.duration_ms,
            "sandbox_id": self.execution.sandbox_id,
            "sandbox_backend": self.execution.sandbox_backend,
            "isolated": bool(self.metadata.get("isolated")),
            "metadata": self.metadata,
        }


class ToolBroker:
    """Authorise, execute and audit tool calls."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        sandbox: SandboxBackend,
        tool_registry: ToolRegistry,
        audit: Any,
        approvals: Any,
        settings: Any = None,
        path_resolver: SafePathResolver | None = None,
        command_allowlist: CommandAllowlist | None = None,
        artifact_store: Any = None,
        workspace: Any = None,
    ) -> None:
        from ..core.config import get_settings

        self.settings = settings or get_settings()
        self.policy_engine = policy_engine
        self.sandbox = sandbox
        self.tool_registry = tool_registry
        self.audit = audit
        self.approvals = approvals
        self.path_resolver = path_resolver
        self.command_allowlist = command_allowlist or CommandAllowlist(DEFAULT_COMMAND_RULES)
        self.artifact_store = artifact_store
        self.workspace = workspace

    # ------------------------------------------------------------ helpers
    def _sandbox_request(self, **kwargs: Any) -> SandboxRequest:
        return SandboxRequest(
            max_output_bytes=self.settings.sandbox_max_output_bytes,
            env={"SANDBOX_JOB": str(getattr(kwargs.get("workspace"), "job_id", ""))},
            **kwargs,
        )

    def _build_context(
        self,
        *,
        user: User,
        agent_session: AgentSession | None,
        db: Session,
    ) -> ToolContext:
        return ToolContext(
            user=user,
            agent_session=agent_session,
            path_resolver=self.path_resolver,  # type: ignore[arg-type]
            artifact_store=self.artifact_store,
            sandbox=self.sandbox,
            workspace=self.workspace,
            approvals=self.approvals,
            db=db,
            request_meta={
                "command_allowlist": self.command_allowlist,
                "job_root": Path(self.settings.job_root),
                "sandbox_timeout": self.settings.sandbox_timeout_seconds,
                "sandbox_request": self._sandbox_request,
                "tool_registry": self.tool_registry,
                "policy_engine": self.policy_engine,
                "workspace_root": Path(self.settings.workspace_root),
                "max_staged_bytes": self.settings.max_staged_bytes,
                "max_staged_files": self.settings.max_staged_files,
            },
        )

    # ----------------------------------------------------------- execution
    async def execute(
        self,
        db: Session,
        *,
        tool_name: str,
        arguments: Mapping[str, Any],
        user: User,
        agent_session: AgentSession | None = None,
        agent_id: str = "default",
        project_id: str = "",
        approval_id: str | None = None,
        step_index: int = 0,
        source: str = "api",
    ) -> BrokerResult:
        """Run a tool call through the complete enforcement pipeline."""
        trace_id = f"tr-{uuid.uuid4().hex[:20]}"
        started = time.monotonic()

        # -------------------------------------------- 1. schema validation
        spec = self.tool_registry.get(tool_name)
        if spec is None:
            decision = PolicyDecision(
                allowed=False,
                effect="deny",
                reason=f"Unknown tool '{tool_name}'.",
                rule_id="tool:unknown",
                source="guard",
                explanation=[f"Tool '{tool_name}' is not registered."],
                policy_version=self.policy_engine.version,
                policy_revision=self.policy_engine.revision,
            )
            return self._record(
                db,
                decision=decision,
                tool_name=tool_name,
                arguments=arguments,
                user=user,
                agent_session=agent_session,
                trace_id=trace_id,
                status="denied",
                error=decision.reason,
                started=started,
            )

        try:
            validated = self.tool_registry.validate_arguments(spec, arguments)
        except ToolError as exc:
            decision = PolicyDecision(
                allowed=False,
                effect="deny",
                reason=str(exc),
                rule_id="guard:tool_invalid_arguments",
                source="guard",
                explanation=[str(exc)],
                policy_version=self.policy_engine.version,
                policy_revision=self.policy_engine.revision,
            )
            return self._record(
                db,
                decision=decision,
                tool_name=tool_name,
                arguments=arguments,
                user=user,
                agent_session=agent_session,
                trace_id=trace_id,
                status="denied",
                error=str(exc),
                started=started,
            )

        # ------------------------------------------- 2. policy evaluation
        grants = self.approvals.session_grants(db, agent_session.id) if agent_session else []
        decision = self.policy_engine.evaluate(
            tool_name,
            validated,
            user_id=user.id,
            role=user.role,
            agent_id=agent_id,
            project_id=project_id or (agent_session.project_id or "" if agent_session else ""),
            session_id=agent_session.id if agent_session else "",
            session_grants=grants,
        )

        if decision.requires_approval and not approval_id:
            approval = self._ensure_approval(
                db,
                tool_name=tool_name,
                arguments=validated,
                user=user,
                agent_session=agent_session,
                decision=decision,
            )
            return self._record(
                db,
                decision=decision,
                tool_name=tool_name,
                arguments=validated,
                user=user,
                agent_session=agent_session,
                trace_id=trace_id,
                status="awaiting_approval",
                error="A human approval is required before this action can run.",
                started=started,
                approval_id=approval.id if approval else None,
                metadata={"approval_required": True},
            )

        if not decision.allowed and not approval_id:
            return self._record(
                db,
                decision=decision,
                tool_name=tool_name,
                arguments=validated,
                user=user,
                agent_session=agent_session,
                trace_id=trace_id,
                status="denied",
                error=decision.reason,
                started=started,
            )

        # ---------------------------------------- 3. approval re-validation
        approval_decision = ""
        approved_by: str | None = None
        approval_record = None
        if approval_id:
            approval_record = self.approvals.get(db, approval_id)
            if approval_record is None:
                decision = PolicyDecision(
                    allowed=False,
                    effect="deny",
                    reason=f"Approval {approval_id} does not exist.",
                    rule_id="approval:missing",
                    source="guard",
                    explanation=[f"Approval {approval_id} does not exist."],
                    policy_version=self.policy_engine.version,
                    policy_revision=self.policy_engine.revision,
                )
                return self._record(
                    db,
                    decision=decision,
                    tool_name=tool_name,
                    arguments=validated,
                    user=user,
                    agent_session=agent_session,
                    trace_id=trace_id,
                    status="denied",
                    error=decision.reason,
                    started=started,
                )
            ok, reason = self.approvals.approved_execution_allowed(
                db, approval=approval_record, tool_name=tool_name, arguments=validated
            )
            if not ok:
                decision = PolicyDecision(
                    allowed=False,
                    effect="deny",
                    reason=reason,
                    rule_id=f"approval:{approval_record.id}",
                    source="guard",
                    explanation=[reason],
                    policy_version=self.policy_engine.version,
                    policy_revision=self.policy_engine.revision,
                )
                return self._record(
                    db,
                    decision=decision,
                    tool_name=tool_name,
                    arguments=validated,
                    user=user,
                    agent_session=agent_session,
                    trace_id=trace_id,
                    status="denied",
                    error=reason,
                    started=started,
                )
            approval_decision = approval_record.scope or "once"
            approved_by = approval_record.decided_by

        # ---------------------------------------------------- 4. execution
        context = self._build_context(user=user, agent_session=agent_session, db=db)
        try:
            tool_result = await spec.handler(context, dict(validated))
        except ToolError as exc:
            tool_result = ToolResult(ok=False, error=str(exc), error_code=exc.code)
        except Exception as exc:
            logger.exception("Tool %s failed", tool_name)
            tool_result = ToolResult(
                ok=False, error=f"Tool execution failed: {exc}", error_code="tool_failed"
            )

        output_text = ""
        if tool_result.output is not None:
            import json

            try:
                output_text = json.dumps(tool_result.output, default=str)
            except (TypeError, ValueError):  # pragma: no cover - defensive
                output_text = str(tool_result.output)
        if len(output_text) > self.settings.sandbox_max_output_bytes:
            output_text = output_text[: self.settings.sandbox_max_output_bytes] + "\n[truncated]"

        sandbox_id = str(tool_result.metadata.get("sandbox_id", ""))
        backend = str(tool_result.metadata.get("backend", ""))
        status = "completed" if tool_result.ok else "failed"
        if tool_result.metadata.get("timed_out"):
            status = "timeout"

        return self._record(
            db,
            decision=decision,
            tool_name=tool_name,
            arguments=validated,
            user=user,
            agent_session=agent_session,
            trace_id=trace_id,
            status=status,
            error=tool_result.error,
            started=started,
            output=output_text,
            tool_result=tool_result,
            approval_id=approval_id,
            approval_decision=approval_decision,
            approved_by=approved_by,
            sandbox_id=sandbox_id,
            backend=backend,
            step_index=step_index,
            metadata={
                "isolated": bool(tool_result.metadata.get("isolated", False)),
                "error_code": tool_result.error_code,
                "exit_code": tool_result.metadata.get("exit_code", 0),
                "source": source,
            },
        )

    # ----------------------------------------------------------- approval
    def _ensure_approval(
        self,
        db: Session,
        *,
        tool_name: str,
        arguments: Mapping[str, Any],
        user: User,
        agent_session: AgentSession | None,
        decision: PolicyDecision,
    ) -> Any:
        """Create (or reuse) an approval request for an action."""
        signature = argument_signature(tool_name, arguments)
        existing = self.approvals.find_pending(
            db, agent_session.id if agent_session else "", tool_name, signature
        )
        if existing is not None:
            return existing
        spec = self.tool_registry.get(tool_name)
        return self.approvals.create(
            db,
            session_id=agent_session.id if agent_session else None,
            user=user,
            tool_name=tool_name,
            arguments=arguments,
            reason=decision.reason,
            risk=spec.risk if spec else "medium",
        )

    # ------------------------------------------------------------ record
    def _record(
        self,
        db: Session,
        *,
        decision: PolicyDecision,
        tool_name: str,
        arguments: Mapping[str, Any],
        user: User,
        agent_session: AgentSession | None,
        trace_id: str,
        status: str,
        error: str | None = None,
        started: float = 0.0,
        output: str = "",
        tool_result: ToolResult | None = None,
        approval_id: str | None = None,
        approval_decision: str = "",
        approved_by: str | None = None,
        sandbox_id: str = "",
        backend: str = "",
        step_index: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> BrokerResult:
        """Persist the execution row and the audit event."""
        duration_ms = int((time.monotonic() - started) * 1000)
        exit_code = 0
        if tool_result is not None:
            exit_code = int(tool_result.metadata.get("exit_code", 0) or 0)

        execution = Execution(
            session_id=agent_session.id if agent_session else None,
            user_id=user.id,
            trace_id=trace_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            redacted_arguments=redact(dict(arguments)),
            status=status,
            decision=decision.effect,
            decision_reason=decision.reason,
            policy_rule_id=decision.rule_id,
            policy_version=decision.policy_version,
            approval_id=approval_id,
            approved_by=approved_by,
            output=output,
            error=error,
            exit_code=exit_code,
            duration_ms=duration_ms,
            cpu_seconds=float((tool_result.metadata.get("cpu_seconds", 0.0)) if tool_result else 0.0),
            memory_peak_mb=float((tool_result.metadata.get("memory_peak_mb", 0.0)) if tool_result else 0.0),
            output_bytes=len(output.encode("utf-8")),
            sandbox_id=sandbox_id,
            sandbox_backend=backend,
            timed_out=bool(tool_result.metadata.get("timed_out") if tool_result else False),
            truncated=bool(tool_result.metadata.get("truncated") if tool_result else False),
            step_index=step_index,
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)

        self.audit.record(
            db,
            action=f"tool.{tool_name}",
            actor_id=user.id,
            actor_role=user.role,
            session_id=agent_session.id if agent_session else None,
            trace_id=trace_id,
            tool_name=tool_name,
            outcome=status,
            policy_version=decision.policy_version,
            policy_rule_id=decision.rule_id,
            target=str(arguments.get("path") or arguments.get("name") or arguments.get("command") or ""),
            arguments=arguments,
            result_summary=(error or "")[:2000] if error else status,
            sandbox_id=sandbox_id,
            approval_decision=approval_decision,
            approved_by=approved_by,
            duration_ms=duration_ms,
            metadata={
                "decision": decision.to_dict(),
                "status": status,
                **(metadata or {}),
            },
        )

        return BrokerResult(
            execution=execution,
            decision=decision,
            tool_result=tool_result,
            status=status,
            error=error,
            trace_id=trace_id,
            approval_required=status == "awaiting_approval",
            approval_id=approval_id,
            metadata={"isolated": bool((metadata or {}).get("isolated", False))},
        )
