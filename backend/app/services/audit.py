"""Append-only audit trail with an integrity chain.

Every audit record carries the hash of its predecessor, forming a chain that
can be verified at any time.  The chain hash is computed with HMAC-SHA256 over
a canonical JSON encoding of the record, keyed with the server secret.  This
detects tampering with the audit table by anyone who does not also hold the
server secret.

Limitations (documented in ``docs/limitations.md``):

* the chain is enforced by the application, not by the database - an operator
  with direct write access to the database can rewrite history *and* the
  chain, unless the server secret is also compromised;
* the chain provides tamper *evidence*, not tamper *prevention*;
* records are not written to append-only/WORM storage.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import Settings, get_settings
from ..core.redaction import redact
from ..db.models import AuditEvent

logger = logging.getLogger(__name__)

#: Fields that participate in the chain hash.
CHAINED_FIELDS = (
    "sequence",
    "created_at",
    "actor_id",
    "actor_role",
    "session_id",
    "trace_id",
    "action",
    "tool_name",
    "outcome",
    "policy_version",
    "policy_rule_id",
    "target",
    "redacted_arguments",
    "result_summary",
    "sandbox_id",
    "approval_decision",
    "approved_by",
    "duration_ms",
)


class AuditService:
    """Write and verify audit records."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    # ------------------------------------------------------------- hashing
    def _key(self) -> bytes:
        return self.settings.secret_key.encode("utf-8")

    def compute_hash(self, payload: Mapping[str, Any], previous_hash: str) -> str:
        """Compute the chain hash of a record."""
        canonical = json.dumps(
            {key: payload.get(key) for key in CHAINED_FIELDS},
            sort_keys=True,
            default=str,
        )
        digest = hmac.new(self._key(), canonical.encode("utf-8"), hashlib.sha256)
        digest.update(b"|")
        digest.update(previous_hash.encode("utf-8"))
        return digest.hexdigest()

    def _next_sequence(self, db: Session) -> int:
        current = db.execute(
            select(AuditEvent.sequence).order_by(AuditEvent.sequence.desc()).limit(1)
        ).scalar()
        return (current or 0) + 1

    def _last_hash(self, db: Session) -> tuple[int, str]:
        row = db.execute(
            select(AuditEvent.sequence, AuditEvent.event_hash).order_by(AuditEvent.sequence.desc()).limit(1)
        ).first()
        if row is None:
            return 0, ""
        return row[0], row[1] or ""

    # ------------------------------------------------------------ recording
    def record(
        self,
        db: Session,
        *,
        action: str,
        actor_id: str,
        outcome: str,
        actor_role: str = "",
        session_id: str | None = None,
        trace_id: str | None = None,
        tool_name: str = "",
        policy_version: str = "",
        policy_rule_id: str = "",
        target: str = "",
        arguments: Mapping[str, Any] | None = None,
        result_summary: str = "",
        sandbox_id: str = "",
        approval_decision: str = "",
        approved_by: str | None = None,
        duration_ms: int = 0,
        metadata: Mapping[str, Any] | None = None,
        commit: bool = True,
    ) -> AuditEvent:
        """Append an audit event."""
        safe_arguments = redact(dict(arguments or {}))
        sequence = self._next_sequence(db)
        _, previous_hash = self._last_hash(db)
        created_at = datetime.now(UTC)

        payload = {
            "sequence": sequence,
            "created_at": created_at.isoformat(),
            "actor_id": actor_id,
            "actor_role": actor_role,
            "session_id": session_id,
            "trace_id": trace_id,
            "action": action,
            "tool_name": tool_name,
            "outcome": outcome,
            "policy_version": policy_version,
            "policy_rule_id": policy_rule_id,
            "target": target[:512],
            "redacted_arguments": safe_arguments,
            "result_summary": result_summary[:4000],
            "sandbox_id": sandbox_id,
            "approval_decision": approval_decision,
            "approved_by": approved_by,
            "duration_ms": duration_ms,
        }
        event_hash = self.compute_hash(payload, previous_hash)

        event = AuditEvent(
            sequence=sequence,
            created_at=created_at,
            actor_id=actor_id,
            actor_role=actor_role,
            session_id=session_id,
            trace_id=trace_id,
            action=action,
            tool_name=tool_name,
            outcome=outcome,
            policy_version=policy_version,
            policy_rule_id=policy_rule_id,
            target=target[:512],
            arguments=dict(arguments or {}),
            redacted_arguments=safe_arguments,
            result_summary=result_summary[:4000],
            sandbox_id=sandbox_id,
            approval_decision=approval_decision,
            approved_by=approved_by,
            duration_ms=duration_ms,
            previous_hash=previous_hash,
            event_hash=event_hash,
            chain_valid=True,
            metadata_json=dict(metadata or {}),
        )
        db.add(event)
        if commit:
            db.commit()
        else:
            db.flush()
        return event

    # ------------------------------------------------------------ verifying
    def verify_chain(self, db: Session, *, limit: int | None = None) -> dict[str, Any]:
        """Verify the integrity chain of the audit table."""
        statement = select(AuditEvent).order_by(AuditEvent.sequence.asc())
        if limit:
            statement = statement.limit(limit)
        events = list(db.execute(statement).scalars())

        previous_hash = ""
        expected_sequence = 1
        broken: list[dict[str, Any]] = []

        for event in events:
            if event.sequence != expected_sequence:
                broken.append(
                    {
                        "sequence": event.sequence,
                        "reason": "sequence_gap",
                        "expected": expected_sequence,
                    }
                )
            expected_sequence = event.sequence + 1

            payload = {
                "sequence": event.sequence,
                "created_at": event.created_at.isoformat()
                if event.created_at.tzinfo
                else event.created_at.replace(tzinfo=UTC).isoformat(),
                "actor_id": event.actor_id,
                "actor_role": event.actor_role,
                "session_id": event.session_id,
                "trace_id": event.trace_id,
                "action": event.action,
                "tool_name": event.tool_name,
                "outcome": event.outcome,
                "policy_version": event.policy_version,
                "policy_rule_id": event.policy_rule_id,
                "target": event.target,
                "redacted_arguments": event.redacted_arguments,
                "result_summary": event.result_summary,
                "sandbox_id": event.sandbox_id,
                "approval_decision": event.approval_decision,
                "approved_by": event.approved_by,
                "duration_ms": event.duration_ms,
            }
            expected_hash = self.compute_hash(payload, previous_hash)
            if expected_hash != event.event_hash:
                broken.append(
                    {
                        "sequence": event.sequence,
                        "reason": "hash_mismatch",
                        "expected_hash": expected_hash,
                        "stored_hash": event.event_hash,
                    }
                )
            previous_hash = event.event_hash

        return {
            "valid": not broken,
            "records": len(events),
            "broken": broken,
            "checked_at": datetime.now(UTC).isoformat(),
        }

    # ------------------------------------------------------------- purging
    def purge_expired(self, db: Session, retention_days: int) -> int:
        """Delete audit records older than the retention window."""
        if retention_days <= 0:
            return 0
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        events = list(db.execute(select(AuditEvent).where(AuditEvent.created_at < cutoff)).scalars())
        for event in events:
            db.delete(event)
        db.commit()
        logger.info("Purged %s audit events older than %s days", len(events), retention_days)
        return len(events)


def export_events(events: Iterable[AuditEvent], fmt: str) -> tuple[str, str]:
    """Export audit events as JSON or CSV."""
    rows: list[dict[str, Any]] = []
    for event in events:
        rows.append(
            {
                "sequence": event.sequence,
                "created_at": event.created_at.isoformat(),
                "actor_id": event.actor_id,
                "actor_role": event.actor_role,
                "session_id": event.session_id,
                "trace_id": event.trace_id,
                "action": event.action,
                "tool_name": event.tool_name,
                "outcome": event.outcome,
                "policy_version": event.policy_version,
                "policy_rule_id": event.policy_rule_id,
                "target": event.target,
                "redacted_arguments": json.dumps(event.redacted_arguments, default=str),
                "result_summary": event.result_summary,
                "sandbox_id": event.sandbox_id,
                "approval_decision": event.approval_decision,
                "approved_by": event.approved_by,
                "duration_ms": event.duration_ms,
                "event_hash": event.event_hash,
                "previous_hash": event.previous_hash,
            }
        )

    if fmt.lower() == "csv":
        import csv
        import io

        buffer = io.StringIO()
        if rows:
            writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return buffer.getvalue(), "text/csv"

    return json.dumps(rows, indent=2, default=str), "application/json"
