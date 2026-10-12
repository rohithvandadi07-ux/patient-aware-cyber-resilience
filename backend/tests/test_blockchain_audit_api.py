"""`/blockchain/audit` API tests. Uses the default-configured app, which
runs with `MockFabricClient` (`Settings.fabric_client_mode` defaults to
"mock" -- see `app/core/app_factory.py`), so `POST /process` drains for
real against an in-memory ledger, no live Fabric network required.
"""

from fastapi.testclient import TestClient

from app.core.app_factory import create_app

app = create_app()
client = TestClient(app)


def _create_incident(incident_id: str, device_id: str = "ecg-monitor-01") -> None:
    response = client.post(
        "/incidents",
        json={
            "incident_id": incident_id,
            "device_id": device_id,
            "attack_type": "dos",
            "evidence_ref": f"evidence-ref-{incident_id}",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )
    assert response.status_code == 201


def test_list_audit_entries_is_empty_before_anything_is_enqueued():
    assert client.get("/blockchain/audit").json() == []


def test_creating_an_incident_enqueues_a_pending_audit_entry():
    _create_incident("INC-AUDIT-1")

    all_entries = client.get("/blockchain/audit").json()
    assert any(e["payload"].get("incident_id") == "INC-AUDIT-1" for e in all_entries)

    for_incident = client.get("/blockchain/audit/INC-AUDIT-1").json()
    assert len(for_incident) == 1
    assert for_incident[0]["status"] == "pending"
    assert for_incident[0]["chain_tx_id"] is None


def test_list_audit_entries_filters_by_status():
    _create_incident("INC-AUDIT-2")

    pending = client.get("/blockchain/audit", params={"status": "pending"}).json()
    assert all(e["status"] == "pending" for e in pending)
    assert any(e["payload"].get("incident_id") == "INC-AUDIT-2" for e in pending)

    confirmed_before = client.get("/blockchain/audit", params={"status": "confirmed"}).json()
    assert confirmed_before == []


def test_process_drains_pending_entries_against_the_mock_fabric_client():
    _create_incident("INC-AUDIT-3")

    processed = client.post("/blockchain/audit/process").json()
    assert any(e["payload"].get("incident_id") == "INC-AUDIT-3" for e in processed)

    for_incident = client.get("/blockchain/audit/INC-AUDIT-3").json()
    assert len(for_incident) == 1
    assert for_incident[0]["status"] == "confirmed"
    assert for_incident[0]["chain_tx_id"]


def test_process_with_nothing_pending_returns_empty_list():
    client.post("/blockchain/audit/process")  # drain whatever is left
    response = client.post("/blockchain/audit/process")
    assert response.status_code == 200
    assert response.json() == []
