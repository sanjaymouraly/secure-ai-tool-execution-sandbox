"""Attack laboratory routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...core.security import hash_password
from ...db.models import User
from ...db.session import get_db
from ...services.attack_lab import AttackLab, list_runs, persist_run
from ..deps import get_container_dep, get_current_user

router = APIRouter(prefix="/attack-lab", tags=["attack-lab"])


def _lab(container: Any) -> AttackLab:
    from ...core.config import get_settings

    return AttackLab(get_settings().policy_dir.parent / "attack_lab" / "scenarios.yaml")


def _ensure_user(db: Session, username: str, role: str) -> User:
    user = db.execute(select(User).where(User.username == username)).scalars().first()
    if user is None:
        user = User(
            username=username,
            email=f"{username}@localhost",
            hashed_password=hash_password("lab-account-not-interactive-" + username),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


@router.get("/scenarios")
async def list_scenarios(
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Return the scenario catalogue."""
    return _lab(container).catalogue()


@router.get("/runs")
async def list_lab_runs(
    limit: int = 200,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Return the recorded laboratory runs and the aggregate statistics."""
    runs = list_runs(db, limit=limit)
    lab = _lab(container)
    return {
        "runs": [
            {
                "id": run.id,
                "scenario_id": run.scenario_id,
                "title": run.scenario_title,
                "category": run.category,
                "severity": run.severity,
                "expectation": run.expectation,
                "observed_outcome": run.observed_outcome,
                "passed": run.passed,
                "attack_input": run.attack_input,
                "proposed_tool_call": run.proposed_tool_call,
                "policy_decision": run.policy_decision,
                "execution_result": run.execution_result,
                "trace_id": run.trace_id,
                "duration_ms": run.duration_ms,
                "notes": run.notes,
                "created_at": run.created_at.isoformat(),
            }
            for run in runs
        ],
        "statistics": lab.statistics(runs),
    }


@router.post("/run/{scenario_id}")
async def run_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Run a single scenario through the real enforcement stack."""
    lab = _lab(container)
    scenario = lab.scenario(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scenario not found.")

    actor = _ensure_user(db, "attack-lab-runner", "analyst")
    approver = _ensure_user(db, "attack-lab-approver", "approver")

    result = await lab.run_scenario(
        db,
        scenario=scenario,
        user=actor,
        container=container,
        approver=approver,
    )
    run = persist_run(db, result)

    container.audit.record(
        db,
        action="attack_lab.run",
        actor_id=current_user.id,
        actor_role=current_user.role,
        outcome="allowed" if result.passed else "failed",
        target=scenario.id,
        arguments={"scenario": scenario.id, "category": scenario.category},
        result_summary=(
            f"Scenario {scenario.id} {'passed' if result.passed else 'failed'}: {result.observed_outcome}"
        ),
        metadata={"passed": result.passed, "calls": result.calls_made},
    )

    return {
        "run_id": run.id,
        "passed": result.passed,
        "result": result.to_dict(),
    }


@router.post("/run-all")
async def run_all(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    container=Depends(get_container_dep),
) -> dict[str, Any]:
    """Run the whole catalogue and report the aggregate statistics."""
    lab = _lab(container)
    actor = _ensure_user(db, "attack-lab-runner", "analyst")
    approver = _ensure_user(db, "attack-lab-approver", "approver")

    results = []
    for scenario in lab.scenarios():
        result = await lab.run_scenario(
            db,
            scenario=scenario,
            user=actor,
            container=container,
            approver=approver,
        )
        persist_run(db, result)
        results.append(result)

    runs = list_runs(db, limit=500)
    return {
        "total": len(results),
        "passed": sum(1 for result in results if result.passed),
        "failed": sum(1 for result in results if not result.passed),
        "statistics": lab.statistics(runs),
        "results": [result.to_dict() for result in results],
    }
