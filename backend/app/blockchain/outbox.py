"""In-memory outbox repository for the five chaincode *write* operations.

Architecture spec Section 14: "every off-chain record ... carries a
nullable `chain_tx_id` column, populated once the outbox worker ... confirms
the transaction. A record with `chain_tx_id IS NULL` means 'not yet
committed,' visible as a pending-provenance state on the dashboard -- never
silently hidden." The real `chain_tx_id` column lives on each of Phase 9's
Postgres tables (`incidents`, `decisions`, etc.), not here; this module is
the queue an async worker (`outbox_worker.py`) drains to actually commit
each entry's provenance to the chain, in the same in-memory-now,
Postgres-later pattern as every other repository in this codebase
(`app/repositories/*.py`) -- swapping this for a Postgres-backed queue
later is a constructor change, not an API rewrite.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

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
