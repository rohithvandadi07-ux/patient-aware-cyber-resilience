from fastapi.testclient import TestClient

from app.core.app_factory import create_app

app = create_app()
client = TestClient(app)


def _threat(incident_id="INC-1"):
    return {
        "incident_id": incident_id,
        "attack_type": "mitm_injection",
        "severity": "high",
        "confidence": 0.9,
        "propagation_risk": "medium",
        "reasoning_summary": "test reasoning",
    }


def _context(incident_id="INC-1", patient_dependency=True, criticality="high"):
    return {
        "incident_id": incident_id,
        "device_criticality": criticality,
        "patient_dependency": patient_dependency,
        "clinical_impact_level": "high",
        "safety_constraints": [],
    }


def _candidate_responses():
    return [
        {"action_category": "isolate_critical", "description": "isolate the device from the network"},
        {"action_category": "shutdown", "description": "power off the device"},
    ]


def test_calculate_risk_returns_a_risk_score_naming_the_incident():
    response = client.post(
        "/risk-assessments",
        json={
            "threat": _threat(),
            "context": _context(),
            "candidate_responses": _candidate_responses(),
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "INC-1"
    assert 0.0 <= body["cyber_risk"] <= 1.0
    assert 0.0 <= body["clinical_risk"] <= 1.0
    assert set(body["response_impact"]) == {"isolate_critical", "shutdown"}
    assert body["explanation"]


def test_calculate_risk_with_no_candidate_responses_returns_400():
    response = client.post(
        "/risk-assessments",
        json={"threat": _threat(), "context": _context(), "candidate_responses": []},
    )
    assert response.status_code == 400


def test_calculate_risk_with_mismatched_incident_ids_returns_400():
    response = client.post(
        "/risk-assessments",
        json={
            "threat": _threat(incident_id="INC-1"),
            "context": _context(incident_id="INC-2"),
            "candidate_responses": _candidate_responses(),
        },
    )
    assert response.status_code == 400


def test_a_patient_dependent_high_criticality_device_scores_high_clinical_risk():
    # Scenario B's own shape (architecture spec Section 17): a
    # patient-dependent, high-criticality device's clinical risk should be
    # high regardless of cyber severity, so the Policy Engine downstream
    # never sees a RiskScore that understates clinical stakes.
    response = client.post(
        "/risk-assessments",
        json={
            "threat": _threat(),
            "context": _context(patient_dependency=True, criticality="high"),
            "candidate_responses": _candidate_responses(),
        },
    )
    assert response.status_code == 200
    assert response.json()["clinical_risk"] >= 0.7
