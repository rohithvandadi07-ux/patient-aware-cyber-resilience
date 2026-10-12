"""Outbox repository for the five chaincode *write* operations -- in-memory
by default, a real Postgres-backed implementation available via
`Settings.repository_backend = "postgres"`.

Architecture spec Section 14: "every off-chain record ... carries a
nullable `chain_tx_id` column, populated once the outbox worker ... confirms
the transaction. A record with `chain_tx_id IS NULL` means 'not yet
committed,' visible as a pending-provenance state on the dashboard -- never
silently hidden." The real `chain_tx_id` column lives on each of Phase 9's
Postgres tables (`incidents`, `decisions`, etc.), not here; this module is
the queue an async worker (`outbox_worker.py`) drains to actually commit
each entry's provenance to the chain. `OutboxRepository` (below) was the
in-memory stand-in; `PostgresOutboxRepository`, added later, is the real
Postgres-backed one -- same public methods, backed by the
`outbox_entries` table (`app/models/orm.py`) instead of a dict. The five
typed `enqueue_*` helpers at the bottom of this file take a repository
instance as their first argument and call only `.enqueue(...)`, so they
work unchanged against either repository.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.core.db import session_scope
from app.models.orm import OutboxEntryORM
from app.schemas.blockchain import (
    ApprovalProvenance,
    DecisionProvenance,
    IncidentProvenance,
    RecoveryProvenance,
    ResponseProvenance,
)
from app.schemas.enums import OutboxRecordType, OutboxStatus


class OutboxEntryNotFoundError(KeyError):
    """Raised when an outbox entry id has no corresponding record."""


@dataclass
class OutboxEntry:
    id: int
    record_type: OutboxRecordType
    payload: dict[str, Any]
    created_at: datetime
    status: OutboxStatus = OutboxStatus.PENDING
    chain_tx_id: str | None = None
    attempts: int = 0
    last_error: str | None = None
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class OutboxRepository:
    def __init__(self) -> None:
        self._entries: dict[int, OutboxEntry] = {}
        self._ids = itertools.count(1)

    def enqueue(self, record_type: OutboxRecordType, payload: dict[str, Any]) -> OutboxEntry:
        entry = OutboxEntry(
            id=next(self._ids),
            record_type=record_type,
            payload=payload,
            created_at=datetime.now(UTC),
        )
        self._entries[entry.id] = entry
        return entry

    def get(self, entry_id: int) -> OutboxEntry:
        try:
            return self._entries[entry_id]
        except KeyError as exc:
            raise OutboxEntryNotFoundError(entry_id) from exc

    def list_pending(self) -> list[OutboxEntry]:
        """Every entry still awaiting (or mid-retry of) chain confirmation,
        oldest first -- the order the worker should process them in, since
        a decision/approval/response/recovery entry for an incident can
        depend on that incident's own entry having committed first."""
        return [e for e in self._entries.values() if e.status == OutboxStatus.PENDING]

    def list_for_incident(self, incident_id: str) -> list[OutboxEntry]:
        return [e for e in self._entries.values() if e.payload.get("incident_id") == incident_id]

    def list_all(self) -> list[OutboxEntry]:
        """Every outbox entry regardless of status or incident -- added in
        Phase 9 for the `/blockchain/audit` API router's unfiltered listing
        (Section 16's Blockchain Audit dashboard section), in insertion
        order. Filtering by status/incident_id is left to the caller
        (the router), the same way `AgentTraceRecorder.all_traces` leaves
        filtering to its callers rather than growing a method per filter
        combination."""
        return list(self._entries.values())

    def mark_confirmed(self, entry_id: int, chain_tx_id: str) -> OutboxEntry:
        entry = self.get(entry_id)
        entry.status = OutboxStatus.CONFIRMED
        entry.chain_tx_id = chain_tx_id
        entry.updated_at = datetime.now(UTC)
        return entry

    def mark_failed(self, entry_id: int, error: str) -> OutboxEntry:
        entry = self.get(entry_id)
        entry.status = OutboxStatus.FAILED
        entry.last_error = error
        entry.updated_at = datetime.now(UTC)
        return entry

    def record_retry_attempt(self, entry_id: int, error: str) -> OutboxEntry:
        """Records a failed-but-transient attempt without changing status
        out of PENDING -- the entry stays queued for the worker to retry."""
        entry = self.get(entry_id)
        entry.attempts += 1
        entry.last_error = error
        entry.updated_at = datetime.now(UTC)
        return entry

    def clear(self) -> None:
        self._entries.clear()


# --- Typed enqueue helpers, one per off-chain provenance schema
# (app/schemas/blockchain.py) -- these are what call sites (the response
# orchestrator, recovery orchestrator, policy engine, approval endpoint)
# should use, rather than building a raw payload dict by hand and getting
# a field name wrong in a way nothing would catch until the worker runs. ---


def enqueue_incident(repository: OutboxRepository, provenance: IncidentProvenance) -> OutboxEntry:
    return repository.enqueue(OutboxRecordType.INCIDENT, provenance.model_dump(mode="json"))


def enqueue_decision(repository: OutboxRepository, provenance: DecisionProvenance) -> OutboxEntry:
    return repository.enqueue(OutboxRecordType.DECISION, provenance.model_dump(mode="json"))


def enqueue_approval(repository: OutboxRepository, provenance: ApprovalProvenance) -> OutboxEntry:
    return repository.enqueue(OutboxRecordType.APPROVAL, provenance.model_dump(mode="json"))


def enqueue_response(repository: OutboxRepository, provenance: ResponseProvenance) -> OutboxEntry:
    return repository.enqueue(OutboxRecordType.RESPONSE, provenance.model_dump(mode="json"))


def enqueue_recovery(repository: OutboxRepository, provenance: RecoveryProvenance) -> OutboxEntry:
    return repository.enqueue(OutboxRecordType.RECOVERY, provenance.model_dump(mode="json"))


def _entry_from_row(row: OutboxEntryORM) -> OutboxEntry:
    return OutboxEntry(
        id=row.id,
        record_type=OutboxRecordType(row.record_type),
        payload=row.payload,
        created_at=row.created_at,
        status=OutboxStatus(row.status),
        chain_tx_id=row.chain_tx_id,
        attempts=row.attempts,
        last_error=row.last_error,
        updated_at=row.updated_at,
    )


class PostgresOutboxRepository:
    """Real, Postgres-backed `OutboxRepository` -- same public interface,
    backed by the `outbox_entries` table (`app/models/orm.py`) instead of a
    dict. One short-lived session per call (`session_scope`), matching
    `PostgresIncidentRepository`'s pattern. `id` is the table's real
    autoincrementing primary key (assigned by Postgres on `flush()`),
    taking over from the in-memory repository's `itertools.count`.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def enqueue(self, record_type: OutboxRecordType, payload: dict[str, Any]) -> OutboxEntry:
        with session_scope(self._session_factory) as session:
            now = datetime.now(UTC)
            row = OutboxEntryORM(
                record_type=record_type.value,
                payload=payload,
                created_at=now,
                status=OutboxStatus.PENDING.value,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            return _entry_from_row(row)

    def get(self, entry_id: int) -> OutboxEntry:
        with session_scope(self._session_factory) as session:
            row = session.get(OutboxEntryORM, entry_id)
            if row is None:
                raise OutboxEntryNotFoundError(entry_id)
            return _entry_from_row(row)

    def list_pending(self) -> list[OutboxEntry]:
        with session_scope(self._session_factory) as session:
            rows = (
                session.query(OutboxEntryORM)
                .filter(OutboxEntryORM.status == OutboxStatus.PENDING.value)
                .all()
            )
            return [_entry_from_row(row) for row in rows]

    def list_for_incident(self, incident_id: str) -> list[OutboxEntry]:
        with session_scope(self._session_factory) as session:
            rows = session.query(OutboxEntryORM).all()
            return [
                _entry_from_row(row)
                for row in rows
                if row.payload.get("incident_id") == incident_id
            ]

    def list_all(self) -> list[OutboxEntry]:
        with session_scope(self._session_factory) as session:
            rows = session.query(OutboxEntryORM).all()
            return [_entry_from_row(row) for row in rows]

    def mark_confirmed(self, entry_id: int, chain_tx_id: str) -> OutboxEntry:
        with session_scope(self._session_factory) as session:
            row = session.get(OutboxEntryORM, entry_id)
            if row is None:
                raise OutboxEntryNotFoundError(entry_id)
            row.status = OutboxStatus.CONFIRMED.value
            row.chain_tx_id = chain_tx_id
            row.updated_at = datetime.now(UTC)
            session.flush()
            return _entry_from_row(row)

    def mark_failed(self, entry_id: int, error: str) -> OutboxEntry:
        with session_scope(self._session_factory) as session:
            row = session.get(OutboxEntryORM, entry_id)
            if row is None:
                raise OutboxEntryNotFoundError(entry_id)
            row.status = OutboxStatus.FAILED.value
            row.last_error = error
            row.updated_at = datetime.now(UTC)
            session.flush()
            return _entry_from_row(row)

    def record_retry_attempt(self, entry_id: int, error: str) -> OutboxEntry:
        with session_scope(self._session_factory) as session:
            row = session.get(OutboxEntryORM, entry_id)
            if row is None:
                raise OutboxEntryNotFoundError(entry_id)
            row.attempts += 1
            row.last_error = error
            row.updated_at = datetime.now(UTC)
            session.flush()
            return _entry_from_row(row)

    def clear(self) -> None:
        """Test-only convenience, mirroring the in-memory repository's
        `clear()` -- deletes every row in `outbox_entries` rather than
        dropping/recreating the table."""
        with session_scope(self._session_factory) as session:
            session.query(OutboxEntryORM).delete()
