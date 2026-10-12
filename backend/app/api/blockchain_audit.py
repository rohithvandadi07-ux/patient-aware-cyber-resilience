"""`/blockchain/audit` — L9 off-chain outbox audit trail, over HTTP
(architecture spec Section 16's "Blockchain Audit" dashboard section;
Section 14's "a record with `chain_tx_id IS NULL` means 'not yet
committed,' visible as a pending-provenance state on the dashboard -- never
silently hidden").

Read-only listing over `OutboxRepository` (Phase 8, `app/blockchain/outbox.py`),
plus one action endpoint: `POST /blockchain/audit/process` drains every
currently-pending entry once via `OutboxWorker.process_once()` (Phase 8,
`app/blockchain/outbox_worker.py`) against whichever `FabricClient` this
process is configured with (`Settings.fabric_client_mode` -- `MockFabricClient`
by default; see `app/core/app_factory.py`'s Phase 9 docstring for why a real
`SubprocessFabricClient` is opt-in, not the default). This is a manual
trigger, not a background loop -- Section 7 step 13's "never blocks" is
about the request path that enqueues, not a claim that this process runs
an unattended drain loop, which `app_factory.py` deliberately does not
start (see its own docstring on `outbox_worker`).
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.dependencies import get_outbox_repository, get_outbox_worker
from app.blockchain.outbox import OutboxEntry, OutboxRepository
from app.blockchain.outbox_worker import OutboxWorker
from app.schemas.enums import OutboxRecordType, OutboxStatus

router = APIRouter(prefix="/blockchain/audit", tags=["blockchain-audit"])


class OutboxEntryOut(BaseModel):
    """`OutboxEntry` (a plain dataclass -- see `app/blockchain/outbox.py`)
    re-shaped as the API's response schema, field-for-field."""

    id: int
    record_type: OutboxRecordType
    payload: dict
    created_at: datetime
    status: OutboxStatus
    chain_tx_id: str | None
    attempts: int
    last_error: str | None
    updated_at: datetime

    @classmethod
    def from_entry(cls, entry: OutboxEntry) -> "OutboxEntryOut":
        return cls(
            id=entry.id,
            record_type=entry.record_type,
            payload=entry.payload,
            created_at=entry.created_at,
            status=entry.status,
            chain_tx_id=entry.chain_tx_id,
            attempts=entry.attempts,
            last_error=entry.last_error,
            updated_at=entry.updated_at,
        )


@router.get("", response_model=list[OutboxEntryOut])
async def list_audit_entries(
    incident_id: str | None = None,
    status: OutboxStatus | None = None,
    repo: OutboxRepository = Depends(get_outbox_repository),
) -> list[OutboxEntryOut]:
    entries = repo.list_for_incident(incident_id) if incident_id is not None else repo.list_all()
    if status is not None:
        entries = [e for e in entries if e.status == status]
    return [OutboxEntryOut.from_entry(e) for e in entries]


@router.get("/{incident_id}", response_model=list[OutboxEntryOut])
async def get_audit_trail_for_incident(
    incident_id: str, repo: OutboxRepository = Depends(get_outbox_repository)
) -> list[OutboxEntryOut]:
    return [OutboxEntryOut.from_entry(e) for e in repo.list_for_incident(incident_id)]


@router.post("/process", response_model=list[OutboxEntryOut])
async def process_pending_entries(
    worker: OutboxWorker = Depends(get_outbox_worker),
) -> list[OutboxEntryOut]:
    """Drains every currently-pending entry once. See this module's
    docstring: this is a manual trigger a human/test calls, not a
    background loop this process runs on its own."""
    processed = await worker.process_once()
    return [OutboxEntryOut.from_entry(e) for e in processed]
