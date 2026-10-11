from app.blockchain.fabric_client import FabricInvocationError, FabricTxResult, TransientFabricError
from app.blockchain.mock_fabric_client import MockFabricClient
from app.blockchain.outbox import OutboxRepository
from app.blockchain.outbox_worker import OutboxWorker
from app.schemas.enums import OutboxRecordType, OutboxStatus

TS = "2026-10-12T00:00:00+00:00"


class _FlakyThenSucceedsClient:
    """Raises TransientFabricError the first `fail_times` calls to
    record_incident, then succeeds. Mirrors the real multi-org endorsement
    timing race documented in fabric_client.py -- this double exists to
    prove the worker actually retries that specific error type rather than
    failing fast on it."""

    def __init__(self, fail_times: int) -> None:
        self._fail_times = fail_times
        self._calls = 0

    async def record_incident(self, **kwargs):
        self._calls += 1
        if self._calls <= self._fail_times:
            raise TransientFabricError("endorsement failure ... has no recordIncident entry")
        return FabricTxResult(tx_id="tx-after-retry", payload={})

    async def record_decision(self, **kwargs): ...
    async def record_approval(self, **kwargs): ...
    async def record_response(self, **kwargs): ...
    async def record_recovery(self, **kwargs): ...
    async def verify_evidence(self, evidence_hash): ...


class _AlwaysRejectsClient:
    async def record_incident(self, **kwargs):
        raise FabricInvocationError("incident 'INC-1' already has a recordIncident entry")

    async def record_decision(self, **kwargs): ...
    async def record_approval(self, **kwargs): ...
    async def record_response(self, **kwargs): ...
    async def record_recovery(self, **kwargs): ...
    async def verify_evidence(self, evidence_hash): ...


def _incident_payload(incident_id="INC-1"):
    return {
        "incident_id": incident_id,
        "device_id": "dev-1",
        "attack_type": "ddos",
        "evidence_hash": "hash-1",
        "timestamp": TS,
    }


async def test_process_once_confirms_a_successful_entry():
    repo = OutboxRepository()
    entry = repo.enqueue(OutboxRecordType.INCIDENT, _incident_payload())
    worker = OutboxWorker(repo, MockFabricClient())

    processed = await worker.process_once()

    assert len(processed) == 1
    updated = repo.get(entry.id)
    assert updated.status == OutboxStatus.CONFIRMED
    assert updated.chain_tx_id


async def test_process_once_marks_a_rejected_entry_failed_without_retrying():
    repo = OutboxRepository()
    entry = repo.enqueue(OutboxRecordType.INCIDENT, _incident_payload())
    worker = OutboxWorker(repo, _AlwaysRejectsClient())

    await worker.process_once()

    updated = repo.get(entry.id)
    assert updated.status == OutboxStatus.FAILED
    assert updated.attempts == 0  # not a retry -- failed on the first and only attempt
    assert "already has a recordIncident entry" in updated.last_error


async def test_process_once_retries_a_transient_error_and_eventually_confirms():
    repo = OutboxRepository()
    entry = repo.enqueue(OutboxRecordType.INCIDENT, _incident_payload())
    # base_backoff_seconds is tiny so this test doesn't actually wait real
    # exponential-backoff time.
    worker = OutboxWorker(repo, _FlakyThenSucceedsClient(fail_times=2), base_backoff_seconds=0.001)

    await worker.process_once()  # attempt 1: fails transiently, stays pending
    after_first = repo.get(entry.id)
    assert after_first.status == OutboxStatus.PENDING
    assert after_first.attempts == 1

    await worker.process_once()  # attempt 2: fails transiently again
    after_second = repo.get(entry.id)
    assert after_second.status == OutboxStatus.PENDING
    assert after_second.attempts == 2

    await worker.process_once()  # attempt 3: client now succeeds
    after_third = repo.get(entry.id)
    assert after_third.status == OutboxStatus.CONFIRMED
    assert after_third.chain_tx_id == "tx-after-retry"


async def test_process_once_marks_failed_after_exhausting_max_attempts_on_transient_errors():
    repo = OutboxRepository()
    entry = repo.enqueue(OutboxRecordType.INCIDENT, _incident_payload())
    # Always transiently fails; max_attempts=2 means it should give up after
    # the second attempt rather than retry forever.
    worker = OutboxWorker(
        repo, _FlakyThenSucceedsClient(fail_times=999), max_attempts=2, base_backoff_seconds=0.001
    )

    await worker.process_once()
    assert repo.get(entry.id).status == OutboxStatus.PENDING

    await worker.process_once()
    final = repo.get(entry.id)
    assert final.status == OutboxStatus.FAILED
    assert "exhausted 2 attempts" in final.last_error


async def test_process_once_processes_multiple_independent_entries():
    repo = OutboxRepository()
    repo.enqueue(OutboxRecordType.INCIDENT, _incident_payload("INC-1"))
    repo.enqueue(OutboxRecordType.INCIDENT, _incident_payload("INC-2"))
    worker = OutboxWorker(repo, MockFabricClient())

    processed = await worker.process_once()

    assert len(processed) == 2
    assert all(e.status == OutboxStatus.CONFIRMED for e in processed)


async def test_full_lifecycle_dispatches_every_record_type_to_the_matching_client_method():
    # Exercises the worker's dispatch table end to end against a real
    # (mock) incident lifecycle: incident -> decision -> approval ->
    # response -> recovery, each depending on the incident already having
    # committed -- the same dependency MockFabricClient enforces.
    repo = OutboxRepository()
    client = MockFabricClient()
    worker = OutboxWorker(repo, client)

    repo.enqueue(OutboxRecordType.INCIDENT, _incident_payload("INC-LIFECYCLE"))
    await worker.process_once()

    repo.enqueue(
        OutboxRecordType.DECISION,
        {
            "incident_id": "INC-LIFECYCLE",
            "risk_score_hash": "hash-risk",
            "policy_rule_id": "RULE-1",
            "recommended_action": "isolate_critical",
        },
    )
    repo.enqueue(
        OutboxRecordType.APPROVAL,
        {
            "incident_id": "INC-LIFECYCLE",
            "approver_identity": "soc-analyst-1",
            "decision": "approved",
            "timestamp": TS,
        },
    )
    repo.enqueue(
        OutboxRecordType.RESPONSE,
        {
            "incident_id": "INC-LIFECYCLE",
            "action_taken": "isolate_critical",
            "executed_by": "orchestrator",
            "timestamp": TS,
        },
    )
    repo.enqueue(
        OutboxRecordType.RECOVERY,
        {"incident_id": "INC-LIFECYCLE", "recovery_verified": True, "residual_threats_hash": None},
    )

    processed = await worker.process_once()

    assert len(processed) == 4
    assert all(e.status == OutboxStatus.CONFIRMED for e in processed)
    assert await client.verify_evidence("hash-1") is True  # the incident's own evidence_hash
