"""`/incidents` API tests. Own `create_app()` instance -- see
`test_telemetry_events_api.py`'s docstring for why.
"""

from fastapi.testclient import TestClient

from app.core.app_factory import create_app

app = create_app()
client = TestClient(app)


def test_list_incidents_is_empty_before_anything_is_created():
    assert client.get("/incidents").json() == []


def test_get_unknown_incident_returns_404():
    response = client.get("/incidents/does-not-exist")
    assert response.status_code == 404


def test_create_incident_returns_201_and_detected_status():
    response = client.post(
        "/incidents",
        json={
            "incident_id": "INC-TEST-1",
            "device_id": "ventilator-01",
            "attack_type": "mitm_injection",
            "evidence_ref": "evidence-ref-1",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["incident_id"] == "INC-TEST-1"
    assert body["device_id"] == "ventilator-01"
    assert body["status"] == "detected"


def test_created_incident_is_retrievable_and_listed():
    client.post(
        "/incidents",
        json={
            "incident_id": "INC-TEST-2",
            "device_id": "ecg-monitor-01",
            "attack_type": "ddos",
            "evidence_ref": "evidence-ref-2",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )

    get_response = client.get("/incidents/INC-TEST-2")
    assert get_response.status_code == 200
    assert get_response.json()["device_id"] == "ecg-monitor-01"

    listed_ids = {i["incident_id"] for i in client.get("/incidents").json()}
    assert "INC-TEST-2" in listed_ids


def test_create_incident_enqueues_pending_blockchain_provenance():
    client.post(
        "/incidents",
        json={
            "incident_id": "INC-TEST-3",
            "device_id": "infusion-pump-01",
            "attack_type": "spoofing",
            "evidence_ref": "evidence-ref-3",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )

    entries = app.state.outbox_repository.list_for_incident("INC-TEST-3")
    assert len(entries) == 1
    assert entries[0].record_type == "incident"
    assert entries[0].status == "pending"
    assert entries[0].payload["device_id"] == "infusion-pump-01"
    # The raw evidence_ref is never stored -- only its hash.
    assert entries[0].payload["evidence_hash"] != "evidence-ref-3"
    assert len(entries[0].payload["evidence_hash"]) == 64


def test_create_incident_for_unknown_device_returns_404():
    response = client.post(
        "/incidents",
        json={
            "incident_id": "INC-TEST-4",
            "device_id": "does-not-exist",
            "attack_type": "dos",
            "evidence_ref": "evidence-ref-4",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )
    assert response.status_code == 404


def test_create_duplicate_incident_id_returns_409():
    payload = {
        "incident_id": "INC-TEST-5",
        "device_id": "ventilator-01",
        "attack_type": "reconnaissance",
        "evidence_ref": "evidence-ref-5",
        "timestamp": "2026-10-12T00:00:00+00:00",
    }
    first = client.post("/incidents", json=payload)
    assert first.status_code == 201

    second = client.post("/incidents", json=payload)
    assert second.status_code == 409


def test_investigate_unknown_incident_returns_404():
    response = client.post("/incidents/does-not-exist/investigate")
    assert response.status_code == 404


def test_investigate_with_default_mock_backend_returns_503_not_fabricated():
    """Post-Phase-15: `app.state.llm_client` is `MockLLMClient(responses=[])`
    by default (no `GEMINI_API_KEY` configured in this test process) --
    calling /investigate must surface that honestly as a real failure
    (503), never fabricate a successful-looking cycle result."""
    create = client.post(
        "/incidents",
        json={
            "incident_id": "INC-TEST-INVESTIGATE-1",
            "device_id": "ventilator-01",
            "attack_type": "spoofing",
            "evidence_ref": "evidence-ref-investigate-1",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )
    assert create.status_code == 201

    response = client.post("/incidents/INC-TEST-INVESTIGATE-1/investigate")
    assert response.status_code == 503
    assert "LLM backend call failed" in response.json()["detail"]


def test_evidence_for_unknown_incident_returns_404():
    response = client.get("/incidents/does-not-exist/evidence")
    assert response.status_code == 404


def test_evidence_for_known_incident_is_a_real_empty_join_before_anything_runs():
    create = client.post(
        "/incidents",
        json={
            "incident_id": "INC-TEST-EVIDENCE-1",
            "device_id": "ventilator-01",
            "attack_type": "spoofing",
            "evidence_ref": "evidence-ref-evidence-1",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )
    assert create.status_code == 201

    response = client.get("/incidents/INC-TEST-EVIDENCE-1/evidence")
    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "INC-TEST-EVIDENCE-1"
    assert body["device_id"] == "ventilator-01"
    # Nothing has run against this fresh incident yet -- a real empty join,
    # never fabricated placeholder evidence.
    assert body["agent_traces"] == []
    assert body["recovery_results"] == []
