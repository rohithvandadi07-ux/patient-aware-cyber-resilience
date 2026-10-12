"""`/recovery` API tests."""

from fastapi.testclient import TestClient

from app.core.app_factory import create_app

app = create_app()
client = TestClient(app)


def _create_incident(incident_id: str, device_id: str = "infusion-pump-01") -> None:
    response = client.post(
        "/incidents",
        json={
            "incident_id": incident_id,
            "device_id": device_id,
            "attack_type": "mitm_injection",
            "evidence_ref": f"evidence-ref-{incident_id}",
            "timestamp": "2026-10-12T00:00:00+00:00",
        },
    )
    assert response.status_code == 201


def _recovery_result(incident_id, recovery_succeeded, reinvestigation_required, residual_threats=None):
    return {
        "incident_id": incident_id,
        "response_id": "resp-1",
        "containment_verified": recovery_succeeded,
        "residual_threats": residual_threats or [],
        "recovery_succeeded": recovery_succeeded,
        "reinvestigation_required": reinvestigation_required,
    }


def test_successful_recovery_resolves_the_incident():
    _create_incident("INC-REC-1")
    response = client.post(
        "/recovery",
        json=_recovery_result("INC-REC-1", recovery_succeeded=True, reinvestigation_required=False),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_failed_recovery_reopens_the_incident():
    _create_incident("INC-REC-2")
    response = client.post(
        "/recovery",
        json=_recovery_result(
            "INC-REC-2",
            recovery_succeeded=False,
            reinvestigation_required=True,
            residual_threats=["unexplained command still observed"],
        ),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "reopened"


def test_inconsistent_recovery_result_returns_409_but_still_records_evidence():
    _create_incident("INC-REC-3")
    response = client.post(
        "/recovery",
        json=_recovery_result("INC-REC-3", recovery_succeeded=False, reinvestigation_required=False),
    )
    assert response.status_code == 409

    recorded = client.get("/recovery/INC-REC-3").json()
    assert len(recorded) == 1
    assert recorded[0]["recovery_succeeded"] is False


def test_recovery_for_unknown_incident_returns_404():
    response = client.post(
        "/recovery",
        json=_recovery_result("does-not-exist", recovery_succeeded=True, reinvestigation_required=False),
    )
    assert response.status_code == 404


def test_recovery_enqueues_provenance_with_hashed_residual_threats():
    _create_incident("INC-REC-4")
    client.post(
        "/recovery",
        json=_recovery_result(
            "INC-REC-4",
            recovery_succeeded=False,
            reinvestigation_required=True,
            residual_threats=["threat-a"],
        ),
    )

    entries = app.state.outbox_repository.list_for_incident("INC-REC-4")
    recovery_entries = [e for e in entries if e.record_type == "recovery"]
    assert len(recovery_entries) == 1
    assert recovery_entries[0].payload["recovery_verified"] is False
    assert recovery_entries[0].payload["residual_threats_hash"] is not None
    assert len(recovery_entries[0].payload["residual_threats_hash"]) == 64


def test_recovery_with_no_residual_threats_enqueues_null_hash():
    _create_incident("INC-REC-5")
    client.post(
        "/recovery",
        json=_recovery_result("INC-REC-5", recovery_succeeded=True, reinvestigation_required=False),
    )

    entries = app.state.outbox_repository.list_for_incident("INC-REC-5")
    recovery_entries = [e for e in entries if e.record_type == "recovery"]
    assert recovery_entries[0].payload["residual_threats_hash"] is None


def test_list_all_recovery_results_includes_every_incident():
    all_results = client.get("/recovery").json()
    incident_ids = {r["incident_id"] for r in all_results}
    assert {"INC-REC-1", "INC-REC-2", "INC-REC-3", "INC-REC-4", "INC-REC-5"} <= incident_ids
