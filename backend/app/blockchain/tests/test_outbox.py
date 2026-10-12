from datetime import UTC, datetime

import pytest

from app.blockchain.outbox import (
    OutboxEntryNotFoundError,
    OutboxRepository,
    enqueue_approval,
    enqueue_decision,
    enqueue_incident,
    enqueue_recovery,
    enqueue_response,
)
from app.schemas.blockchain import (
    ApprovalProvenance,
    DecisionProvenance,
    IncidentProvenance,
    RecoveryProvenance,
    ResponseProvenance,
)
from app.schemas.enums import ApprovalDecision, OutboxRecordType, OutboxStatus, ResponseActionCategory

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def test_enqueue_returns_pending_entry_with_no_chain_tx_id():
    repo = OutboxRepository()
    entry = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-1"})

    assert entry.status == OutboxStatus.PENDING
    assert entry.chain_tx_id is None
    assert entry.attempts == 0


def test_list_pending_only_returns_pending_entries():
    repo = OutboxRepository()
    pending = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-1"})
    confirmed = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-2"})
    repo.mark_confirmed(confirmed.id, "tx-123")

    assert [e.id for e in repo.list_pending()] == [pending.id]


def test_mark_confirmed_sets_status_and_chain_tx_id():
    repo = OutboxRepository()
    entry = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-1"})

    confirmed = repo.mark_confirmed(entry.id, "tx-abc")

    assert confirmed.status == OutboxStatus.CONFIRMED
    assert confirmed.chain_tx_id == "tx-abc"


def test_mark_failed_sets_status_and_error():
    repo = OutboxRepository()
    entry = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-1"})

    failed = repo.mark_failed(entry.id, "boom")

    assert failed.status == OutboxStatus.FAILED
    assert failed.last_error == "boom"
    assert failed.chain_tx_id is None


def test_record_retry_attempt_increments_attempts_and_stays_pending():
    repo = OutboxRepository()
    entry = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-1"})

    repo.record_retry_attempt(entry.id, "transient error")
    retried = repo.get(entry.id)

    assert retried.attempts == 1
    assert retried.status == OutboxStatus.PENDING
    assert retried.last_error == "transient error"


def test_get_unknown_entry_raises():
    repo = OutboxRepository()
    with pytest.raises(OutboxEntryNotFoundError):
        repo.get(999)


def test_list_for_incident_filters_by_incident_id_in_payload():
    repo = OutboxRepository()
    repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-1"})
    repo.enqueue(OutboxRecordType.DECISION, {"incident_id": "INC-2"})

    assert len(repo.list_for_incident("INC-1")) == 1


def test_list_all_returns_every_entry_regardless_of_status():
    repo = OutboxRepository()
    pending = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-1"})
    confirmed = repo.enqueue(OutboxRecordType.INCIDENT, {"incident_id": "INC-2"})
    repo.mark_confirmed(confirmed.id, "tx-123")

    assert {e.id for e in repo.list_all()} == {pending.id, confirmed.id}


def test_enqueue_incident_dumps_provenance_with_snake_case_keys():
    repo = OutboxRepository()
    provenance = IncidentProvenance(
        incident_id="INC-1",
        device_id="dev-1",
        attack_type="ddos",
        evidence_hash="hash-1",
        timestamp=NOW,
    )

    entry = enqueue_incident(repo, provenance)

    assert entry.record_type == OutboxRecordType.INCIDENT
    assert entry.payload["incident_id"] == "INC-1"
    assert entry.payload["device_id"] == "dev-1"
    # datetime fields serialize to ISO strings -- chaincode args are always
    # strings, and model_dump(mode="json") is what guarantees that here.
    assert isinstance(entry.payload["timestamp"], str)


def test_enqueue_decision_serializes_enum_to_its_string_value():
    repo = OutboxRepository()
    provenance = DecisionProvenance(
        incident_id="INC-1",
        risk_score_hash="hash-risk",
        policy_rule_id="RULE-1",
        recommended_action=ResponseActionCategory.ISOLATE_CRITICAL,
    )

    entry = enqueue_decision(repo, provenance)

    assert entry.payload["recommended_action"] == "isolate_critical"


def test_enqueue_approval_serializes_decision_enum():
    repo = OutboxRepository()
    provenance = ApprovalProvenance(
        incident_id="INC-1",
        approver_identity="soc-analyst-1",
        decision=ApprovalDecision.APPROVED,
        timestamp=NOW,
    )

    entry = enqueue_approval(repo, provenance)

    assert entry.payload["decision"] == "approved"


def test_enqueue_response_round_trips_all_fields():
    repo = OutboxRepository()
    provenance = ResponseProvenance(
        incident_id="INC-1",
        action_taken=ResponseActionCategory.SHUTDOWN,
        executed_by="orchestrator",
        timestamp=NOW,
    )

    entry = enqueue_response(repo, provenance)

    assert entry.payload["action_taken"] == "shutdown"
    assert entry.payload["executed_by"] == "orchestrator"


def test_enqueue_recovery_with_no_residual_hash_serializes_to_none():
    repo = OutboxRepository()
    provenance = RecoveryProvenance(incident_id="INC-1", recovery_verified=True)

    entry = enqueue_recovery(repo, provenance)

    assert entry.payload["recovery_verified"] is True
    assert entry.payload["residual_threats_hash"] is None
