"""Attack laboratory tests.

Every scenario in the catalogue is executed against the real enforcement
stack.  A scenario that fails here is a real finding, not a flaky test.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.container import Container
from app.db.models import User
from app.services.attack_lab import AttackLab


@pytest.fixture()
def lab() -> AttackLab:
    settings = get_settings()
    return AttackLab(settings.policy_dir.parent / "attack_lab" / "scenarios.yaml")


def test_catalogue_contains_at_least_twenty_scenarios(lab: AttackLab) -> None:
    scenarios = lab.scenarios()
    assert len(scenarios) >= 20
    malicious = [s for s in scenarios if s.expectation in {"deny", "require_approval"}]
    benign = [s for s in scenarios if s.expectation == "allow"]
    assert len(malicious) >= 15
    assert len(benign) >= 5


def test_scenario_ids_are_unique(lab: AttackLab) -> None:
    ids = [scenario.id for scenario in lab.scenarios()]
    assert len(ids) == len(set(ids))


def test_every_scenario_has_steps(lab: AttackLab) -> None:
    for scenario in lab.scenarios():
        assert scenario.steps, scenario.id
        assert scenario.expected, scenario.id


async def test_full_catalogue_passes(
    lab: AttackLab, lab_container: Container, db: Session, admin_user: User
) -> None:
    from app.core.security import hash_password
    from app.db.models import User as UserModel

    actor = UserModel(
        username="lab-actor",
        email="lab@test.local",
        hashed_password=hash_password("lab-password-1234"),
        role="analyst",
        is_active=True,
    )
    approver = UserModel(
        username="lab-approver",
        email="lab-approver@test.local",
        hashed_password=hash_password("lab-password-1234"),
        role="approver",
        is_active=True,
    )
    db.add_all([actor, approver])
    db.commit()
    db.refresh(actor)
    db.refresh(approver)

    failures: list[str] = []
    for scenario in lab.scenarios():
        result = await lab.run_scenario(
            db,
            scenario=scenario,
            user=actor,
            container=lab_container,
            approver=approver,
        )
        if not result.passed:
            failures.append(
                f"{scenario.id} ({scenario.title}): expected={scenario.expectation} "
                f"observed={result.observed_outcome} steps="
                + ",".join(f"{s.tool}:{s.status}" for s in result.steps)
            )
    assert not failures, "Scenarios failed:\n" + "\n".join(failures)


async def test_protected_fixture_is_untouched_by_the_catalogue(
    lab: AttackLab, lab_container: Container, db: Session, admin_user: User
) -> None:
    protected = Path(lab_container.settings.workspace_root) / "protected" / "secret.txt"
    protected.parent.mkdir(parents=True, exist_ok=True)
    protected.write_text("CANARY-1234\n", encoding="utf-8")
    before = hashlib.sha256(protected.read_bytes()).hexdigest()

    from app.core.security import hash_password
    from app.db.models import User as UserModel

    actor = UserModel(
        username="lab-actor-2",
        email="lab2@test.local",
        hashed_password=hash_password("lab-password-1234"),
        role="analyst",
        is_active=True,
    )
    db.add(actor)
    db.commit()
    db.refresh(actor)

    for scenario in lab.scenarios():
        await lab.run_scenario(
            db, scenario=scenario, user=actor, container=lab_container, approver=admin_user
        )

    after = hashlib.sha256(protected.read_bytes()).hexdigest()
    assert before == after


async def test_statistics_are_computed(
    lab: AttackLab, lab_container: Container, db: Session, admin_user: User
) -> None:
    from app.core.security import hash_password
    from app.db.models import AttackLabRun
    from app.db.models import User as UserModel
    from app.services.attack_lab import persist_run

    actor = UserModel(
        username="lab-actor-3",
        email="lab3@test.local",
        hashed_password=hash_password("lab-password-1234"),
        role="analyst",
        is_active=True,
    )
    db.add(actor)
    db.commit()
    db.refresh(actor)

    for scenario in lab.scenarios():
        result = await lab.run_scenario(
            db, scenario=scenario, user=actor, container=lab_container, approver=admin_user
        )
        persist_run(db, result)

    runs = db.query(AttackLabRun).all()
    stats = lab.statistics(runs)
    assert stats["total_runs"] == len(lab.scenarios())
    assert stats["attack_success_rate"] == 0.0
    assert stats["false_positive_rate"] == 0.0
    assert stats["malicious_blocked"] == stats["malicious_total"]


def test_documentation_lists_every_scenario(lab: AttackLab) -> None:
    """The attack-lab documentation must mention every scenario id."""
    docs = Path(__file__).resolve().parents[2] / "docs" / "attack-lab.md"
    if not docs.exists():
        pytest.skip("The attack laboratory documentation has not been written yet.")
    text = docs.read_text(encoding="utf-8")
    missing = [scenario.id for scenario in lab.scenarios() if scenario.id not in text]
    assert not missing, f"Scenarios missing from the documentation: {missing}"
