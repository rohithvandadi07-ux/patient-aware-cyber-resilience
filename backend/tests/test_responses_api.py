"""`/responses/proposed` and `/responses/executed` API tests."""

from fastapi.testclient import TestClient

from app.core.app_factory import create_app

app = create_app()
client = TestClient(app)


def _create_incident(incident_id: str, device_id: str = "ventilator-01") -> None:
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


def _threat_context_candidate(incident_id):
    threat = {
        "incident_id": incident_id,
        "attack_type": "mitm_injection",
        "severity": "high",
        "confidence": 0.9,
        "propagation_risk": "medium",
        "reasoning_summary": "test reasoning",
    }
    return threat


def _propose(incident_id, action, impact, patient_dependency):
    risk_score = {
        "incident_id": incident_id,
        "cyber_risk": 0.8,
        "clinical_risk": 0.5,
        "response_impact": {action: impact},
        "explanation": "test",
    }
    proposed_response = {
        "incident_id": incident_id,
        "candidate_actions": [{"action_category": action, "description": "test action"}],
        "security_benefit": {action: 0.9},
        "clinical_impact": {action: impact},
        "recommended_action": action,
        "rationale": "test rationale",
    }
    context = {
        "incident_id": incident_id,
        "device_criticality": "high",
        "patient_dependency": patient_dependency,
        "clinical_impact_level": impact,
        "safety_constraints": [],
    }
    return client.post(
        "/responses/proposed",
        json={"risk_score": risk_score, "proposed_response": proposed_response, "context": context},
    )


def test_propose_response_auto_approved_action_is_not_flagged_for_approval():
    _create_incident("INC-RESP-1")
    response = _propose("INC-RESP-1", "isolate_non_critical", "low", patient_dependency=False)
    assert response.status_code == 201
    body = response.json()
    assert body["requires_human_approval"] is False
    assert body["chosen_action"] == "isolate_non_critical"


def test_proposed_response_is_listed_and_enqueues_decision_provenance():
    _create_incident("INC-RESP-2")
    _propose("INC-RESP-2", "isolate_non_critical", "low", patient_dependency=False)

    get_response = client.get("/responses/proposed/INC-RESP-2")
    assert get_response.status_code == 200

    listed_ids = {d["incident_id"] for d in client.get("/responses/proposed").json()}
    assert "INC-RESP-2" in listed_ids

    entries = app.state.outbox_repository.list_for_incident("INC-RESP-2")
    decision_entries = [e for e in entries if e.record_type == "decision"]
    assert len(decision_entries) == 1
    assert decision_entries[0].payload["policy_rule_id"] == "autonomous_low_impact"


def test_get_proposed_response_for_unknown_incident_returns_404():
    response = client.get("/responses/proposed/does-not-exist")
    assert response.status_code == 404


def test_execute_auto_approved_response_executes_immediately_as_system():
    _create_incident("INC-RESP-3")
    _propose("INC-RESP-3", "isolate_non_critical", "low", patient_dependency=False)

    response = client.post("/responses/executed", json={"incident_id": "INC-RESP-3"})
    assert response.status_code == 201
    body = response.json()
    assert body["executed_by"] == "system"
    assert body["action_taken"] == "isolate_non_critical"

    # The proposed decision is cleared once executed.
    assert client.get("/responses/proposed/INC-RESP-3").status_code == 404

    executed_entries = app.state.outbox_repository.list_for_incident("INC-RESP-3")
    assert any(e.record_type == "response" for e in executed_entries)


def test_execute_human_approval_required_response_without_approval_returns_409():
    _create_incident("INC-RESP-4")
    _propose("INC-RESP-4", "shutdown", "critical", patient_dependency=True)

    response = client.post("/responses/executed", json={"incident_id": "INC-RESP-4"})
    assert response.status_code == 409


def test_execute_human_approval_required_response_with_rejection_returns_409():
    _create_incident("INC-RESP-5")
    _propose("INC-RESP-5", "shutdown", "critical", patient_dependency=True)

    response = client.post(
        "/responses/executed",
        json={
            "incident_id": "INC-RESP-5",
            "approval": {
                "incident_id": "INC-RESP-5",
                "approver_identity": "soc-analyst-1",
                "decision": "rejected",
                "timestamp": "2026-10-12T00:00:00+00:00",
            },
        },
    )
    assert response.status_code == 409


def test_execute_human_approval_required_response_with_approval_executes():
    _create_incident("INC-RESP-6")
    _propose("INC-RESP-6", "shutdown", "critical", patient_dependency=True)

    response = client.post(
        "/responses/executed",
        json={
            "incident_id": "INC-RESP-6",
            "approval": {
                "incident_id": "INC-RESP-6",
                "approver_identity": "soc-analyst-1",
                "decision": "approved",
                "timestamp": "2026-10-12T00:00:00+00:00",
            },
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["executed_by"] == "soc-analyst-1"
    assert body["action_taken"] == "shutdown"

    entries = app.state.outbox_repository.list_for_incident("INC-RESP-6")
    assert any(e.record_type == "approval" for e in entries)
    assert any(e.record_type == "response" for e in entries)

    listed = client.get("/responses/executed/INC-RESP-6").json()
    assert len(listed) == 1


def test_execute_with_no_proposed_response_returns_404():
    _create_incident("INC-RESP-7")
    response = client.post("/responses/executed", json={"incident_id": "INC-RESP-7"})
    assert response.status_code == 404


def test_list_executed_responses_includes_prior_executions():
    all_executed = client.get("/responses/executed").json()
    assert any(e["incident_id"] == "INC-RESP-3" for e in all_executed)
    assert any(e["incident_id"] == "INC-RESP-6" for e in all_executed)


# --- opt-in confidence gate (Settings.policy_min_autonomous_confidence) -----


def _propose_with_confidence(incident_id, detection_confidence):
    body = _propose_body(incident_id, "isolate_non_critical", "low", False)
    if detection_confidence is not None:
        body["detection_confidence"] = detection_confidence
    return client.post("/responses/proposed", json=body)


def _propose_body(incident_id, action, impact, patient_dependency):
    risk_score = {
        "incident_id": incident_id,
        "cyber_risk": 0.8,
        "clinical_risk": 0.5,
        "response_impact": {action: impact},
        "explanation": "test",
    }
    proposed_response = {
        "incident_id": incident_id,
        "candidate_actions": [{"action_category": action, "description": "test action"}],
        "security_benefit": {action: 0.9},
        "clinical_impact": {action: impact},
        "recommended_action": action,
        "rationale": "test rationale",
    }
    context = {
        "incident_id": incident_id,
        "device_criticality": "low",
        "patient_dependency": patient_dependency,
        "clinical_impact_level": impact,
        "safety_constraints": [],
    }
    return {"risk_score": risk_score, "proposed_response": proposed_response, "context": context}


def test_confidence_gate_is_off_by_default_and_ignores_the_field():
    _create_incident("INC-GATE-0")
    response = _propose_with_confidence("INC-GATE-0", 0.01)
    assert response.status_code == 201
    assert response.json()["requires_human_approval"] is False


def test_confidence_gate_on_demotes_low_unknown_and_keeps_confident():
    from app.api.dependencies import get_policy_engine
    from app.policy_engine.engine import PolicyEngine

    app.dependency_overrides[get_policy_engine] = lambda: PolicyEngine(min_autonomous_confidence=0.9)
    try:
        for incident_id, confidence, needs_approval, rule in [
            ("INC-GATE-1", 0.7, True, "approval_low_detector_confidence"),
            ("INC-GATE-2", None, True, "approval_unknown_detector_confidence"),
            ("INC-GATE-3", 0.97, False, "autonomous_low_impact"),
        ]:
            _create_incident(incident_id)
            body = _propose_with_confidence(incident_id, confidence).json()
            assert body["requires_human_approval"] is needs_approval, incident_id
            assert body["policy_rule_id"] == rule, incident_id
    finally:
        app.dependency_overrides.pop(get_policy_engine, None)


def test_detection_confidence_out_of_range_is_rejected():
    _create_incident("INC-GATE-4")
    assert _propose_with_confidence("INC-GATE-4", 1.5).status_code == 422
