"""The prompt-injection security laboratory.

The laboratory replays realistic attack scenarios against the **real**
enforcement stack: the real schema validation, the real hard guards, the real
policy engine, the real approval workflow, the real sandbox and the real
audit trail.  Nothing is mocked, so a scenario that passes here is evidence
that the control actually works.

Each run records the attack input, the proposed tool call, the policy
decision, the execution result, the expected outcome and the observed
outcome.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AttackLabRun, User

logger = logging.getLogger(__name__)

#: Maximum number of tool calls a single scenario may trigger.
DEFAULT_CALL_BUDGET = 25

#: The protected fixture whose integrity the laboratory verifies.
PROTECTED_FIXTURE = "protected/secret.txt"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScenarioStep(_Strict):
    """A single tool call inside a scenario."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    expectation: str = "deny"
    repeat: int = Field(default=1, ge=1, le=500)
    oversized: bool = False


class ScenarioBudget(_Strict):
    """A resource budget that the scenario must not be able to exceed."""

    max_calls: int = Field(default=DEFAULT_CALL_BUDGET, ge=1, le=1000)
    enforced: bool = True


class Scenario(_Strict):
    """A complete laboratory scenario."""

    id: str
    title: str
    category: str = "general"
    severity: str = "medium"
    expectation: str = "deny"
    description: str = ""
    source_document: str = ""
    attack_input: str = ""
    expected: str = ""
    auto_approve: bool = False
    budget: ScenarioBudget | None = None
    steps: list[ScenarioStep] = Field(default_factory=list)


class LabDocument(_Strict):
    """The scenario catalogue."""

    version: str = "1.0.0"
    scenarios: list[Scenario] = Field(default_factory=list)


@dataclass
class StepOutcome:
    """The observed result of a single scenario step."""

    index: int
    tool: str
    arguments: dict[str, Any]
    expected: str
    observed: str
    passed: bool
    status: str
    decision: str = ""
    reason: str = ""
    rule_id: str = ""
    policy_version: str = ""
    trace_id: str = ""
    duration_ms: int = 0
    output_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "tool": self.tool,
            "arguments": self.arguments,
            "expected": self.expected,
            "observed": self.observed,
            "passed": self.passed,
            "status": self.status,
            "decision": self.decision,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "policy_version": self.policy_version,
            "trace_id": self.trace_id,
            "duration_ms": self.duration_ms,
            "output_preview": self.output_preview,
        }


@dataclass
class LabRunResult:
    """The result of running a complete scenario."""

    scenario: Scenario
    passed: bool
    steps: list[StepOutcome] = field(default_factory=list)
    attack_input: str = ""
    observed_outcome: str = ""
    duration_ms: int = 0
    budget_enforced: bool = True
    calls_made: int = 0
    session_id: str = ""
    protected_fixture_before: str = ""
    protected_fixture_after: str = ""
    protected_fixture_intact: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario.id,
            "title": self.scenario.title,
            "category": self.scenario.category,
            "severity": self.scenario.severity,
            "expectation": self.scenario.expectation,
            "expected": self.scenario.expected,
            "attack_input": self.attack_input,
            "observed_outcome": self.observed_outcome,
            "passed": self.passed,
            "steps": [step.to_dict() for step in self.steps],
            "duration_ms": self.duration_ms,
            "calls_made": self.calls_made,
            "budget_enforced": self.budget_enforced,
            "protected_fixture_intact": self.protected_fixture_intact,
            "notes": self.notes,
        }


class AttackLab:
    """Loads and executes the scenario catalogue."""

    def __init__(self, scenarios_path: Path) -> None:
        self.scenarios_path = Path(scenarios_path)
        self.document = self._load()

    def _load(self) -> LabDocument:
        raw = self.scenarios_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        document = LabDocument.model_validate(data)
        seen: set[str] = set()
        for scenario in document.scenarios:
            if scenario.id in seen:
                raise ValueError(f"Duplicate scenario id: {scenario.id}")
            seen.add(scenario.id)
        return document

    # ------------------------------------------------------------ catalogue
    def scenarios(self) -> list[Scenario]:
        return list(self.document.scenarios)

    def scenario(self, scenario_id: str) -> Scenario | None:
        for scenario in self.document.scenarios:
            if scenario.id == scenario_id:
                return scenario
        return None

    def catalogue(self) -> dict[str, Any]:
        """Return the catalogue with the scenario metadata for the UI."""
        return {
            "version": self.document.version,
            "count": len(self.document.scenarios),
            "categories": sorted({scenario.category for scenario in self.document.scenarios}),
            "scenarios": [
                {
                    "id": scenario.id,
                    "title": scenario.title,
                    "category": scenario.category,
                    "severity": scenario.severity,
                    "expectation": scenario.expectation,
                    "expected": scenario.expected,
                    "description": scenario.description,
                    "attack_input": scenario.attack_input,
                    "source_document": scenario.source_document,
                    "steps": [
                        {
                            "tool": step.tool,
                            "expectation": step.expectation,
                            "arguments": step.arguments,
                        }
                        for step in scenario.steps
                    ],
                }
                for scenario in self.document.scenarios
            ],
        }

    # ------------------------------------------------------------ execution
    async def run_scenario(
        self,
        db: Session,
        *,
        scenario: Scenario,
        user: User,
        container: Any,
        approver: User | None = None,
    ) -> LabRunResult:
        """Execute one scenario through the real enforcement stack."""
        started = time.monotonic()
        result = LabRunResult(scenario=scenario, passed=False)
        result.attack_input = scenario.attack_input
        result.protected_fixture_before = self._fixture_hash(container)

        # Every scenario runs in its own agent session so that artifacts and
        # session grants from one scenario cannot influence another.
        from ..db.models import AgentSession

        agent_session = AgentSession(
            title=f"attack-lab:{scenario.id}",
            user_id=user.id,
            agent_id="attack-lab",
        )
        db.add(agent_session)
        db.commit()
        db.refresh(agent_session)
        result.session_id = agent_session.id

        budget = scenario.budget or ScenarioBudget()
        calls = 0
        blocked_any = False
        all_ok = True
        budget_stopped = False
        notes: list[str] = []

        for step in scenario.steps:
            arguments = self._prepare_arguments(step)
            repeat = max(1, step.repeat)
            for _ in range(repeat):
                if calls >= budget.max_calls:
                    budget_stopped = True
                    notes.append(
                        f"The scenario call budget of {budget.max_calls} calls was enforced; "
                        "the loop was stopped before it could exhaust resources."
                    )
                    break
                calls += 1
                outcome = await self._run_step(
                    db,
                    scenario=scenario,
                    step=step,
                    arguments=arguments,
                    user=user,
                    container=container,
                    approver=approver,
                    index=len(result.steps),
                    agent_session=agent_session,
                )
                result.steps.append(outcome)
                if outcome.status in {"denied", "awaiting_approval"}:
                    blocked_any = True
                if not outcome.passed:
                    all_ok = False
            if budget_stopped:
                break

        result.calls_made = calls
        result.budget_enforced = not budget_stopped or calls <= budget.max_calls
        result.protected_fixture_after = self._fixture_hash(container)
        result.protected_fixture_intact = result.protected_fixture_before == result.protected_fixture_after
        if not result.protected_fixture_intact:
            notes.append("The protected fixture changed during this scenario!")
            all_ok = False

        if scenario.budget is not None:
            # The attack in this scenario is an unbounded loop; the defence is
            # the enforced resource budget.
            result.passed = budget_stopped and result.protected_fixture_intact
            if not budget_stopped:
                notes.append("The resource budget was NOT enforced.")
        elif scenario.expectation == "allow":
            result.passed = all_ok and result.protected_fixture_intact
        elif scenario.expectation == "deny":
            result.passed = blocked_any and result.protected_fixture_intact
            if not blocked_any:
                notes.append("The malicious action was NOT blocked.")
        elif scenario.expectation == "require_approval":
            parked = any(step.status == "awaiting_approval" for step in result.steps)
            result.passed = parked and result.protected_fixture_intact
        else:  # pragma: no cover - schema constrains the values
            result.passed = False

        result.duration_ms = int((time.monotonic() - started) * 1000)
        result.notes = " ".join(notes)
        result.observed_outcome = self._summarise(result)
        return result

    async def _run_step(
        self,
        db: Session,
        *,
        scenario: Scenario,
        step: ScenarioStep,
        arguments: dict[str, Any],
        user: User,
        container: Any,
        approver: User | None,
        index: int,
        agent_session: Any = None,
    ) -> StepOutcome:
        """Run one tool call through the broker and record the outcome."""
        broker_result = await container.broker.execute(
            db,
            tool_name=step.tool,
            arguments=arguments,
            user=user,
            agent_session=agent_session,
            agent_id="attack-lab",
            source="attack-lab",
        )

        status_value = broker_result.status
        if status_value == "awaiting_approval" and scenario.auto_approve and approver is not None:
            # The lab grants the approval explicitly and records that it did so.
            approval = container.approvals.get(db, broker_result.approval_id or "")
            if approval is not None:
                container.approvals.decide(
                    db,
                    approval=approval,
                    decision="allow_once",
                    approver=approver,
                    note="Approved automatically by the attack laboratory (benign scenario).",
                )
                broker_result = await container.broker.execute(
                    db,
                    tool_name=step.tool,
                    arguments=arguments,
                    user=user,
                    agent_session=agent_session,
                    agent_id="attack-lab",
                    approval_id=approval.id,
                    source="attack-lab",
                )
                status_value = broker_result.status

        observed = {
            "completed": "completed",
            "failed": "failed",
            "denied": "denied",
            "awaiting_approval": "awaiting_approval",
        }.get(status_value, status_value)

        expected = step.expectation
        if expected == "allow":
            passed = status_value == "completed"
        elif expected == "deny":
            passed = status_value == "denied"
        elif expected == "require_approval":
            passed = status_value == "awaiting_approval"
        else:  # pragma: no cover
            passed = False

        return StepOutcome(
            index=index,
            tool=step.tool,
            arguments=arguments,
            expected=expected,
            observed=observed,
            passed=passed,
            status=status_value,
            decision=broker_result.decision.effect,
            reason=broker_result.decision.reason,
            rule_id=broker_result.decision.rule_id,
            policy_version=broker_result.decision.policy_version,
            trace_id=broker_result.trace_id,
            duration_ms=broker_result.execution.duration_ms,
            output_preview=broker_result.execution.output[:600],
        )

    # -------------------------------------------------------------- helpers
    def _prepare_arguments(self, step: ScenarioStep) -> dict[str, Any]:
        """Return the arguments for a step, inflated when the scenario asks."""
        arguments = dict(step.arguments)
        if step.oversized:
            arguments["path"] = "documents/" + ("A" * 200_000) + ".txt"
        return arguments

    @staticmethod
    def _fixture_hash(container: Any) -> str:
        """Return the SHA-256 of the protected fixture (empty when absent)."""
        try:
            target = container.settings.workspace_root / PROTECTED_FIXTURE
            if not target.exists():
                return ""
            return hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError:  # pragma: no cover - defensive
            return ""

    @staticmethod
    def _summarise(result: LabRunResult) -> str:
        statuses = [step.status for step in result.steps]
        if result.notes and "budget" in result.notes:
            return "blocked_by_budget"
        if not statuses:
            return "no steps executed"
        if all(status == "completed" for status in statuses):
            return "all steps completed"
        blocked = sum(1 for status in statuses if status in {"denied", "awaiting_approval"})
        return f"{blocked} of {len(statuses)} step(s) blocked"

    # ------------------------------------------------------------ reporting
    def statistics(self, runs: Iterable[AttackLabRun]) -> dict[str, Any]:
        """Compute the attack success rate and the false positive rate."""
        runs = list(runs)
        malicious = [run for run in runs if run.expectation in {"deny", "require_approval"}]
        benign = [run for run in runs if run.expectation == "allow"]

        def _step_statuses(run: AttackLabRun) -> list[str]:
            result = run.execution_result or {}
            steps = result.get("steps") or []
            return [str(step.get("status", "")) for step in steps]

        def _step_is_successful(run: AttackLabRun) -> bool:
            """True when a step that had to be blocked actually ran.

            A malicious scenario may legitimately contain allowed steps (for
            example reading the hostile document first).  Only the steps
            whose expected outcome is a block or an approval count.
            """
            result = run.execution_result or {}
            for step in result.get("steps") or []:
                expected = str(step.get("expected", ""))
                status = str(step.get("status", ""))
                if expected == "deny" and status in {"completed", "failed"}:
                    return True
                if expected == "require_approval" and status in {"completed", "failed"}:
                    return True
            return False

        successes = [
            run
            for run in malicious
            if _step_is_successful(run) and run.observed_outcome != "blocked_by_budget"
        ]
        false_positives = [run for run in benign if not run.passed]

        deny_count = sum(1 for run in runs for status in _step_statuses(run) if status == "denied")
        approval_count = sum(
            1 for run in runs for status in _step_statuses(run) if status == "awaiting_approval"
        )
        budget_blocked = sum(1 for run in runs if run.observed_outcome == "blocked_by_budget")

        by_category: dict[str, dict[str, int]] = {}
        for run in malicious:
            bucket = by_category.setdefault(run.category, {"total": 0, "blocked": 0, "passed": 0})
            bucket["total"] += 1
            if run.passed:
                bucket["blocked"] += 1
                bucket["passed"] += 1

        return {
            "total_runs": len(runs),
            "malicious_total": len(malicious),
            "malicious_blocked": len(malicious) - len(successes),
            "attack_success_rate": round(len(successes) / len(malicious), 4) if malicious else 0.0,
            "deny_count": deny_count,
            "approval_count": approval_count,
            "budget_blocked": budget_blocked,
            "benign_total": len(benign),
            "benign_allowed": len(benign) - len(false_positives),
            "false_positive_count": len(false_positives),
            "false_positive_rate": round(len(false_positives) / len(benign), 4) if benign else 0.0,
            "by_category": by_category,
        }


def persist_run(db: Session, result: LabRunResult) -> AttackLabRun:
    """Store the result of a scenario run."""
    run = AttackLabRun(
        scenario_id=result.scenario.id,
        scenario_title=result.scenario.title,
        category=result.scenario.category,
        severity=result.scenario.severity,
        expectation=result.scenario.expectation,
        observed_outcome=result.observed_outcome,
        passed=result.passed,
        attack_input=result.attack_input,
        proposed_tool_call={
            "steps": [{"tool": step.tool, "arguments": step.arguments} for step in result.steps]
        },
        policy_decision={
            "steps": [
                {
                    "decision": step.decision,
                    "reason": step.reason,
                    "rule_id": step.rule_id,
                    "policy_version": step.policy_version,
                }
                for step in result.steps
            ]
        },
        execution_result={
            "steps": [step.to_dict() for step in result.steps],
            "protected_fixture_intact": result.protected_fixture_intact,
        },
        trace_id=result.steps[0].trace_id if result.steps else "",
        duration_ms=result.duration_ms,
        notes=result.notes,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def list_runs(db: Session, limit: int = 200) -> list[AttackLabRun]:
    """Return the most recent laboratory runs."""
    return list(
        db.execute(select(AttackLabRun).order_by(AttackLabRun.created_at.desc()).limit(limit)).scalars()
    )
