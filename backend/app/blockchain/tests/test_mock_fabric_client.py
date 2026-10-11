import pytest

from app.blockchain.fabric_client import FabricInvocationError
from app.blockchain.mock_fabric_client import MockFabricClient

TS = "2026-10-12T00:00:00+00:00"


async def _record_incident(client, incident_id="INC-1", evidence_hash="hash-ev-1"):
    return await client.record_incident(incident_id, "dev-1", "ddos", evidence_hash, TS)


async def test_record_incident_returns_a_tx_id_and_echoes_fields():
    client = MockFabricClient()
    result = await _record_incident(client)

    assert result.tx_id
    assert result.payload["incidentId"] == "INC-1"
    assert result.payload["evidenceHash"] == "hash-ev-1"


async def test_record_incident_rejects_duplicate_incident_id():
    client = MockFabricClient()
    await _record_incident(client)

    with pytest.raises(FabricInvocationError, match="already has a recordIncident entry"):
        await _record_incident(client)


async def test_record_decision_requires_existing_incident():
    client = MockFabricClient()
    with pytest.raises(FabricInvocationError, match="has no recordIncident entry"):
        await client.record_decision("INC-UNKNOWN", "hash-risk", "RULE-1", "isolate_critical")


async def test_record_decision_validates_recommended_action():
    client = MockFabricClient()
    await _record_incident(client)

    with pytest.raises(FabricInvocationError, match="recommended_action must be one of"):
        await client.record_decision("INC-1", "hash-risk", "RULE-1", "not_a_real_action")


async def test_record_approval_validates_decision_value():
    client = MockFabricClient()
    await _record_incident(client)

    with pytest.raises(FabricInvocationError, match="decision must be one of"):
        await client.record_approval("INC-1", "soc-analyst-1", "maybe", TS)

    result = await client.record_approval("INC-1", "soc-analyst-1", "approved", TS)
    assert result.payload["decision"] == "approved"


async def test_record_response_validates_action_taken():
    client = MockFabricClient()
    await _record_incident(client)

    with pytest.raises(FabricInvocationError, match="action_taken must be one of"):
        await client.record_response("INC-1", "not_a_real_action", "orchestrator", TS)


async def test_record_recovery_without_residual_hash_does_not_index_a_hash():
    client = MockFabricClient()
    await _record_incident(client)

    result = await client.record_recovery("INC-1", True, None)

    assert result.payload["residualThreatsHash"] is None
    assert await client.verify_evidence("") is False


async def test_record_recovery_with_residual_hash_makes_it_verifiable():
    client = MockFabricClient()
    await _record_incident(client)

    await client.record_recovery("INC-1", False, "residual-hash-1")

    assert await client.verify_evidence("residual-hash-1") is True


async def test_verify_evidence_true_for_incident_hash_false_for_unknown():
    client = MockFabricClient()
    await _record_incident(client, evidence_hash="hash-ev-2")

    assert await client.verify_evidence("hash-ev-2") is True
    assert await client.verify_evidence("never-recorded") is False


async def test_two_client_instances_have_isolated_ledgers():
    client_a = MockFabricClient()
    client_b = MockFabricClient()
    await _record_incident(client_a, incident_id="INC-SHARED")

    # The same incident_id on a fresh client must not collide with client_a's
    # ledger -- each MockFabricClient is its own isolated world state.
    await _record_incident(client_b, incident_id="INC-SHARED")
