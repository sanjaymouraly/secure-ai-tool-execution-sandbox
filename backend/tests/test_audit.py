"""Audit trail integrity tests."""

from __future__ import annotations

import json
from datetime import UTC

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.container import Container
from app.db.models import AuditEvent, User
from app.services.audit import export_events


def _record(container: Container, db: Session, user: User, action: str) -> AuditEvent:
    return container.audit.record(
        db,
        action=action,
        actor_id=user.id,
        actor_role=user.role,
        outcome="allowed",
        arguments={"path": "documents/report.md", "api_key": "sk-secret-value-123456"},
    )


def test_audit_events_are_chained(container: Container, db: Session, admin_user: User) -> None:
    first = _record(container, db, admin_user, "tool.read_file")
    second = _record(container, db, admin_user, "tool.list_files")
    assert second.previous_hash == first.event_hash
    assert first.event_hash


def test_chain_verifies(container: Container, db: Session, admin_user: User) -> None:
    for index in range(5):
        _record(container, db, admin_user, f"tool.action_{index}")
    result = container.audit.verify_chain(db)
    assert result["valid"] is True
    assert result["records"] == 5
    assert result["broken"] == []


def test_tampering_is_detected(container: Container, db: Session, admin_user: User) -> None:
    for index in range(3):
        _record(container, db, admin_user, f"tool.action_{index}")
    event = db.execute(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1)).scalars().first()
    event.outcome = "tampered"
    db.commit()

    result = container.audit.verify_chain(db)
    assert result["valid"] is False
    assert result["broken"]
    assert result["broken"][0]["reason"] == "hash_mismatch"


def test_sequence_gaps_are_detected(container: Container, db: Session, admin_user: User) -> None:
    for index in range(3):
        _record(container, db, admin_user, f"tool.action_{index}")
    event = db.execute(select(AuditEvent).order_by(AuditEvent.sequence.asc()).limit(1)).scalars().first()
    db.delete(event)
    db.commit()
    result = container.audit.verify_chain(db)
    assert result["valid"] is False


def test_secrets_are_redacted_in_the_audit_trail(container: Container, db: Session, admin_user: User) -> None:
    event = _record(container, db, admin_user, "tool.read_file")
    assert "sk-secret-value-123456" not in json.dumps(event.redacted_arguments)
    assert event.redacted_arguments["api_key"] == "[REDACTED]"


def test_export_json_and_csv(container: Container, db: Session, admin_user: User) -> None:
    _record(container, db, admin_user, "tool.read_file")
    events = list(db.execute(select(AuditEvent)).scalars())

    json_payload, media_type = export_events(events, "json")
    assert media_type == "application/json"
    parsed = json.loads(json_payload)
    assert parsed[0]["tool_name"] == ""

    csv_payload, csv_type = export_events(events, "csv")
    assert csv_type == "text/csv"
    assert "sequence,created_at" in csv_payload


def test_retention_purges_old_events(container: Container, db: Session, admin_user: User) -> None:
    from datetime import datetime, timedelta

    event = _record(container, db, admin_user, "tool.read_file")
    event.created_at = datetime.now(UTC) - timedelta(days=200)
    db.commit()
    removed = container.audit.purge_expired(db, 90)
    assert removed == 1
    assert db.execute(select(AuditEvent)).scalars().all() == []
