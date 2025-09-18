"""The agent loop.

    user request
        -> trusted orchestrator
        -> LLM tool proposal
        -> schema validation
        -> deterministic policy evaluation
        -> optional human approval
        -> isolated execution
        -> sanitised result
        -> audit record
        -> agent continuation

The orchestrator never executes anything itself.  It only proposes tool calls
to the broker, and it only feeds *sanitised* results back to the model.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from ..core.redaction import redact
from ..db.models import AgentSession, Execution, UsageRecord, User
from ..db.models import Message as MessageModel
from ..providers.base import Message, Provider, ProviderError, ProviderResponse, ToolCall
from ..providers.registry import BudgetGuard, estimate_cost
from ..tools.base import ToolRegistry
from .prompts import build_system_prompt

logger = logging.getLogger(__name__)


@dataclass
class StepRecord:
    """A single iteration of the agent loop."""

    index: int
    provider: str
    model: str
    text: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    cost_usd: float = 0.0
    error: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "provider": self.provider,
            "model": self.model,
            "text": self.text,
            "tool_calls": self.tool_calls,
            "usage": self.usage,
            "cost_usd": round(self.cost_usd, 8),
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class AgentResult:
    """The outcome of a complete agent run."""

    session: AgentSession
    final_text: str = ""
    steps: list[StepRecord] = field(default_factory=list)
    executions: list[Execution] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    error: str = ""
    status: str = "completed"
    blocked: int = 0
    approved: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session.id,
            "status": self.status,
            "final_text": self.final_text,
            "steps": [step.to_dict() for step in self.steps],
            "executions": [
                {
                    "id": execution.id,
                    "tool_name": execution.tool_name,
                    "status": execution.status,
                    "decision": execution.decision,
                    "reason": execution.decision_reason,
                    "trace_id": execution.trace_id,
                    "duration_ms": execution.duration_ms,
                    "output": execution.output[:20_000],
                    "error": execution.error,
                }
                for execution in self.executions
            ],
            "total_cost_usd": round(self.total_cost_usd, 8),
            "total_tokens": self.total_tokens,
            "blocked": self.blocked,
            "approved": self.approved,
            "error": self.error,
        }


class AgentOrchestrator:
    """Drive the model / policy / sandbox loop."""

    def __init__(
        self,
        *,
        provider: Provider,
        tool_registry: ToolRegistry,
        broker: Any,
        settings: Any = None,
    ) -> None:
        from ..core.config import get_settings

        self.provider = provider
        self.tool_registry = tool_registry
        self.broker = broker
        self.settings = settings or get_settings()
        self.budget = BudgetGuard(self.settings)

    # ------------------------------------------------------------ messages
    def _load_history(self, db: Session, session: AgentSession, limit: int = 40) -> list[Message]:
        from sqlalchemy import select

        rows = list(
            db.execute(
                select(MessageModel)
                .where(MessageModel.session_id == session.id)
                .order_by(MessageModel.sequence.desc())
                .limit(limit)
            ).scalars()
        )
        history: list[Message] = []
        for row in reversed(rows):
            if row.role == "tool":
                history.append(
                    Message(
                        role="tool",
                        content=row.content,
                        tool_call_id=row.tool_call_id,
                        name=row.name,
                    )
                )
            elif row.role == "assistant" and row.tool_calls:
                history.append(
                    Message(
                        role="assistant",
                        content=row.content,
                        tool_calls=[
                            ToolCall(
                                id=str(call.get("id") or ""),
                                name=str(call.get("name") or ""),
                                arguments=dict(call.get("arguments") or {}),
                            )
                            for call in row.tool_calls
                        ],
                    )
                )
            else:
                history.append(Message(role=row.role, content=row.content))
        return history

    def _persist_message(
        self,
        db: Session,
        session: AgentSession,
        *,
        role: str,
        content: str,
        sequence: int,
        tool_calls: list[dict[str, Any]] | None = None,
        tool_call_id: str | None = None,
        name: str | None = None,
        usage: dict[str, Any] | None = None,
        is_untrusted: bool = False,
    ) -> None:
        db.add(
            MessageModel(
                session_id=session.id,
                role=role,
                content=content,
                sequence=sequence,
                tool_calls=tool_calls,
                tool_call_id=tool_call_id,
                name=name,
                is_untrusted=is_untrusted,
                usage_json=usage,
            )
        )
        db.commit()

    # --------------------------------------------------------------- budget
    def _daily_cost(self, db: Session) -> float:
        from sqlalchemy import func, select

        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        total = db.execute(
            select(func.coalesce(func.sum(UsageRecord.estimated_cost_usd), 0.0)).where(
                UsageRecord.created_at >= today
            )
        ).scalar()
        return float(total or 0.0)

    # ----------------------------------------------------------------- run
    async def run(
        self,
        db: Session,
        *,
        session: AgentSession,
        user: User,
        user_message: str,
        agent_id: str = "default",
        project_id: str = "",
        max_steps: int | None = None,
    ) -> AgentResult:
        """Execute the agent loop for a single user request."""
        result = AgentResult(session=session)
        steps_limit = max_steps or self.settings.agent_max_steps

        if not user_message.strip():
            result.status = "failed"
            result.error = "The request is empty."
            return result

        history = self._load_history(db, session)
        system_prompt = session.system_prompt or build_system_prompt()
        messages: list[Message] = [Message(role="system", content=system_prompt), *history]
        messages.append(Message(role="user", content=user_message))

        self._persist_message(
            db,
            session,
            role="user",
            content=user_message,
            sequence=self._next_sequence(db, session),
        )

        tools = self.tool_registry.json_schemas()
        sequence = self._next_sequence(db, session)

        for step_index in range(steps_limit):
            if session.cancelled:
                result.status = "cancelled"
                result.error = "The run was cancelled."
                break

            started = time.monotonic()
            try:
                response = await self.provider.chat(messages, tools=tools)
            except ProviderError as exc:
                result.status = "failed"
                result.error = str(exc)
                self._record_usage(db, session, response=None, error=str(exc), provider=self.provider)
                result.steps.append(
                    StepRecord(
                        index=step_index,
                        provider=self.provider.name,
                        model=self.provider.config.model,
                        error=str(exc),
                        duration_ms=int((time.monotonic() - started) * 1000),
                    )
                )
                break
            except Exception as exc:
                result.status = "failed"
                result.error = f"Unexpected provider failure: {exc}"
                break

            duration_ms = int((time.monotonic() - started) * 1000)
            cost = estimate_cost(
                response.model or self.provider.config.model,
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
            )
            response.usage.estimated_cost_usd = cost
            result.total_cost_usd += cost
            result.total_tokens += response.usage.total_tokens

            step = StepRecord(
                index=step_index,
                provider=response.provider or self.provider.name,
                model=response.model,
                text=response.text,
                usage=response.usage.to_dict(),
                cost_usd=cost,
                duration_ms=duration_ms,
            )

            self._record_usage(db, session, response=response)

            if not response.tool_calls:
                if not response.text.strip():
                    # Some small models return an empty turn; make the
                    # transcript explicit instead of showing nothing.
                    response.text = (
                        "The model returned an empty final message. "
                        "The tool results above are the complete evidence for this run."
                    )
                step.tool_calls = []
                result.steps.append(step)
                result.final_text = response.text
                self._persist_message(
                    db,
                    session,
                    role="assistant",
                    content=response.text,
                    sequence=sequence,
                    usage=response.usage.to_dict(),
                )
                sequence += 1
                break

            call_payload = [call.to_dict() for call in response.tool_calls]
            step.tool_calls = call_payload
            result.steps.append(step)
            self._persist_message(
                db,
                session,
                role="assistant",
                content=response.text,
                sequence=sequence,
                tool_calls=call_payload,
                usage=response.usage.to_dict(),
            )
            sequence += 1

            # The assistant turn that carries the tool calls must be part of
            # the conversation *before* the tool results, otherwise the
            # provider receives an out-of-order transcript.
            messages.append(
                Message(
                    role="assistant",
                    content=response.text,
                    tool_calls=response.tool_calls,
                )
            )

            # ---------------------------------------------- execute the tools
            for call in response.tool_calls[: self.settings.agent_max_tool_calls_per_step]:
                broker_result = await self.broker.execute(
                    db,
                    tool_name=call.name,
                    arguments=call.arguments,
                    user=user,
                    agent_session=session,
                    agent_id=agent_id,
                    project_id=project_id,
                    step_index=step_index,
                    source="agent",
                )
                result.executions.append(broker_result.execution)
                if broker_result.status == "denied":
                    result.blocked += 1
                elif broker_result.status == "awaiting_approval":
                    result.approved += 0
                elif broker_result.status == "completed":
                    result.approved += 1

                tool_text = self._format_tool_result(broker_result)
                messages.append(
                    Message(
                        role="tool",
                        content=tool_text,
                        tool_call_id=call.id,
                        name=call.name,
                    )
                )
                self._persist_message(
                    db,
                    session,
                    role="tool",
                    content=tool_text,
                    sequence=sequence,
                    tool_call_id=call.id,
                    name=call.name,
                    is_untrusted=True,
                )
                sequence += 1

        else:
            result.status = "max_steps"
            result.error = (
                f"The agent reached the limit of {steps_limit} steps without producing a final answer."
            )

        session.step_count += len(result.steps)
        session.tool_call_count += len(result.executions)
        session.blocked_count += result.blocked
        session.approved_count += result.approved
        session.total_cost_usd += result.total_cost_usd
        session.total_tokens += result.total_tokens
        session.provider = self.provider.name
        session.model = self.provider.config.model
        if result.status == "completed":
            session.status = "active"
        db.commit()

        return result

    # ------------------------------------------------------------- helpers
    def _next_sequence(self, db: Session, session: AgentSession) -> int:
        from sqlalchemy import func, select

        current = db.execute(
            select(func.coalesce(func.max(MessageModel.sequence), 0)).where(
                MessageModel.session_id == session.id
            )
        ).scalar()
        return int(current or 0) + 1

    def _format_tool_result(self, broker_result: Any) -> str:
        """Render the tool outcome for the model, clearly marking denials."""
        payload: dict[str, Any] = {
            "tool": broker_result.execution.tool_name,
            "status": broker_result.status,
            "decision": broker_result.decision.effect,
            "policy_rule": broker_result.decision.rule_id,
        }
        if broker_result.decision.reason:
            payload["reason"] = broker_result.decision.reason
        if broker_result.status == "denied":
            payload["result"] = (
                "The action was DENIED by the security policy and was not executed. "
                "Do not attempt to work around it; report the denial."
            )
        elif broker_result.status == "awaiting_approval":
            payload["result"] = "The action requires a human approval and is pending. It has not run yet."
        else:
            payload["result"] = broker_result.execution.output[:20_000]
            if broker_result.error:
                payload["error"] = broker_result.error
        return json.dumps(redact(payload), default=str)

    def _record_usage(
        self,
        db: Session,
        session: AgentSession,
        *,
        response: ProviderResponse | None,
        error: str = "",
        provider: Provider | None = None,
    ) -> None:
        active = provider or self.provider
        if response is None:
            db.add(
                UsageRecord(
                    session_id=session.id,
                    user_id=session.user_id,
                    provider=active.name,
                    model=active.config.model,
                    call_type="chat",
                    succeeded=False,
                    error=error[:2000],
                )
            )
            db.commit()
            return
        db.add(
            UsageRecord(
                session_id=session.id,
                user_id=session.user_id,
                provider=active.name,
                model=response.model or active.config.model,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
                estimated_cost_usd=response.usage.estimated_cost_usd,
                call_type="chat",
                succeeded=True,
            )
        )
        db.commit()
