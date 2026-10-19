"""Queue the active routing policy's hash for the ledger, and report its anchoring status."""

from datetime import UTC, datetime
from typing import Any

from app.blockchain.outbox import OutboxEntry, OutboxRepository, enqueue_policy
from app.policy_engine.table import get_active_table
from app.schemas.blockchain import PolicyProvenance
from app.schemas.enums import OutboxRecordType, OutboxStatus


def _policy_entries(repository: OutboxRepository, policy_hash: str) -> list[OutboxEntry]:
    return [
        e
        for e in repository.list_all()
        if e.record_type == OutboxRecordType.POLICY and e.payload.get("policy_hash") == policy_hash
    ]


def anchor_active_policy(repository: OutboxRepository) -> bool:
    """Queue the active policy's hash unless a live (pending or confirmed) entry exists.
    A FAILED earlier attempt does not count, so it is queued again. Returns True if queued."""
    table = get_active_table()
    if any(e.status != OutboxStatus.FAILED for e in _policy_entries(repository, table.policy_hash)):
        return False
    enqueue_policy(
        repository,
        PolicyProvenance(
            policy_hash=table.policy_hash,
            policy_name=table.doc.name,
            policy_version=table.doc.version,
            timestamp=datetime.now(UTC),
        ),
    )
    return True


def policy_anchor_status(repository: OutboxRepository, policy_hash: str) -> dict[str, Any]:
    entries = _policy_entries(repository, policy_hash)
    if not entries:
        return {"state": "not_queued", "chain_tx_id": None, "last_error": None}
    latest = max(entries, key=lambda e: e.id)
    return {
        "state": latest.status.value,
        "chain_tx_id": latest.chain_tx_id,
        "last_error": latest.last_error,
    }
