"""Async outbox worker (architecture spec Section 7 step 13 / Section 14):
drains `OutboxRepository`'s pending entries and commits each one to the
chaincode via a `FabricClient`, populating `chain_tx_id` on success.
Deliberately never sits on the response-execution hot path -- nothing in
`app/response_engine/` or `app/recovery/` calls a `FabricClient` directly;
they enqueue an outbox entry (see `outbox.py`'s `enqueue_*` helpers) and
this worker is what actually talks to the chain, on its own schedule.
"""

from __future__ import annotations

import asyncio
import logging

from app.blockchain.fabric_client import FabricClient, FabricInvocationError, TransientFabricError
from app.blockchain.outbox import OutboxEntry, OutboxRepository
from app.schemas.enums import OutboxRecordType

logger = logging.getLogger(__name__)

_DEFAULT_MAX_ATTEMPTS = 5
_DEFAULT_BASE_BACKOFF_SECONDS = 1.0


class OutboxWorker:
    """Processes `OutboxRepository` entries against a `FabricClient`.

    Retry policy: a `TransientFabricError` (the multi-org endorsement
    timing race documented in the project's architecture decisions --
    see `fabric_client.py`) is retried with exponential backoff, up to
    `max_attempts`; any other `FabricInvocationError` (bad arguments, or
    the chaincode correctly rejecting an out-of-order/duplicate call) is
    NOT retried -- it's marked FAILED immediately, since retrying it would
    just fail the same way forever.
    """

    def __init__(
        self,
        repository: OutboxRepository,
        fabric_client: FabricClient,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
        base_backoff_seconds: float = _DEFAULT_BASE_BACKOFF_SECONDS,
    ) -> None:
        self._repository = repository
        self._client = fabric_client
        self._max_attempts = max_attempts
        self._base_backoff_seconds = base_backoff_seconds

    async def process_once(self) -> list[OutboxEntry]:
        """Attempts every currently-pending entry once (a transient failure
        that still has retries left stays PENDING for the next call to
        `process_once`, after sleeping its backoff here). Returns the
        entries that were processed this call, whatever their resulting
        status."""
        processed = []
        for entry in self._repository.list_pending():
            processed.append(await self._process_entry(entry))
        return processed

    async def run_forever(self, poll_interval_seconds: float, stop_event: asyncio.Event) -> None:
        """Runs `process_once` in a loop until `stop_event` is set. This is
        what a real deployment runs as a background task (or separate
        process) -- tests call `process_once` directly instead, so a test
        doesn't need a real sleep loop to observe one batch of outbox
        processing."""
        while not stop_event.is_set():
            await self.process_once()
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=poll_interval_seconds)
            except TimeoutError:
                pass

    async def _process_entry(self, entry: OutboxEntry) -> OutboxEntry:
        try:
            result = await self._dispatch(entry)
        except TransientFabricError as exc:
            attempt_number = entry.attempts + 1
            if attempt_number >= self._max_attempts:
                logger.warning(
                    "outbox entry %s (%s) exhausted %d attempts on transient errors, marking FAILED: %s",
                    entry.id, entry.record_type, self._max_attempts, exc,
                )
                return self._repository.mark_failed(
                    entry.id, f"exhausted {self._max_attempts} attempts, last error: {exc}"
                )
            self._repository.record_retry_attempt(entry.id, str(exc))
            backoff = self._base_backoff_seconds * (2 ** entry.attempts)
            logger.info(
                "outbox entry %s (%s) hit a transient Fabric error, retrying in %.1fs (attempt %d/%d): %s",
                entry.id, entry.record_type, backoff, attempt_number, self._max_attempts, exc,
            )
            await asyncio.sleep(backoff)
            return entry
        except FabricInvocationError as exc:
            logger.error(
                "outbox entry %s (%s) rejected by chaincode, marking FAILED (not retrying): %s",
                entry.id, entry.record_type, exc,
            )
            return self._repository.mark_failed(entry.id, str(exc))
        else:
            logger.info(
                "outbox entry %s (%s) committed, chain_tx_id=%s", entry.id, entry.record_type, result.tx_id
            )
            return self._repository.mark_confirmed(entry.id, result.tx_id)

    async def _dispatch(self, entry: OutboxEntry):
        payload = entry.payload
        match entry.record_type:
            case OutboxRecordType.INCIDENT:
                return await self._client.record_incident(
                    incident_id=payload["incident_id"],
                    device_id=payload["device_id"],
                    attack_type=payload["attack_type"],
                    evidence_hash=payload["evidence_hash"],
                    timestamp=payload["timestamp"],
                )
            case OutboxRecordType.DECISION:
                return await self._client.record_decision(
                    incident_id=payload["incident_id"],
                    risk_score_hash=payload["risk_score_hash"],
                    policy_rule_id=payload["policy_rule_id"],
                    recommended_action=payload["recommended_action"],
                )
            case OutboxRecordType.APPROVAL:
                return await self._client.record_approval(
                    incident_id=payload["incident_id"],
                    approver_identity=payload["approver_identity"],
                    decision=payload["decision"],
                    timestamp=payload["timestamp"],
                )
            case OutboxRecordType.RESPONSE:
                return await self._client.record_response(
                    incident_id=payload["incident_id"],
                    action_taken=payload["action_taken"],
                    executed_by=payload["executed_by"],
                    timestamp=payload["timestamp"],
                )
            case OutboxRecordType.RECOVERY:
                return await self._client.record_recovery(
                    incident_id=payload["incident_id"],
                    recovery_verified=payload["recovery_verified"],
                    residual_threats_hash=payload.get("residual_threats_hash"),
                )
            case _:
                raise AssertionError(f"unhandled OutboxRecordType: {entry.record_type}")
