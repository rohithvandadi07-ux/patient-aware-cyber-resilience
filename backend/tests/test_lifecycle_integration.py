"""Phase 10.8 -- one real incident, driven through its full lifecycle end to
end against a real FastAPI app instance, over the real HTTP API.

**What is real here:** detection (a real trained Random Forest scoring a
real simulated attack scenario), the Investigation/Threat/Clinical/Response
Planning/Recovery agents' structural plumbing (prompt building, schema
validation, retry policy, trace recording -- `app/agents/base.py`), the
deterministic Risk Engine, the Policy Engine, the Response Orchestrator
(which really mutates the simulated ventilator's state), the Recovery
Orchestrator, and the blockchain outbox (real hashing, real enqueue/drain,
a real `MockFabricClient` that enforces the same write-once/append-only
rules the actual chaincode does). Every assertion below is about this real
code's real, observed behavior through the real HTTP endpoints -- nothing
here is asserted "implemented" or "verified" without actually exercising it.

**What is NOT real, and is never claimed to be:** the five agents' LLM
calls. No live LLM backend is wired into this project yet (`app/agents/
llm_client.py`'s own docstring: "no real LLM backend ... is wired in yet
[...] an open Phase 4+ decision"), and no orchestrator sequences the five
agents automatically (same module, same open decision, Section 11). This
test uses `MockLLMClient` -- the project's own established test double,
already used by every one of `app/agents/tests/test_*.py` -- to script each
agent's structured output, and calls the five agent functions directly, in
the order Section 7 describes, standing in for the orchestrator that does
not exist yet. The scripted outputs are written to look like what a real
agent run against this exact scenario would plausibly produce, but they are
authored by this test, not inferred by a model -- nobody should read a
passing run of this test as evidence that live LLM reasoning occurred.

**Why this test exists:** every one of these steps already has its own
dedicated unit/integration tests (risk engine, policy engine, response
orchestrator, recovery orchestrator, outbox, each agent in isolation). What
none of those prove is that they chain together correctly for one real
incident end to end -- that the Risk Engine's output shape is actually what
the Policy Engine's endpoint accepts, that executing a response actually
clears the pending decision the recovery step depends on, that the outbox
actually ends up with a confirmed, hashed entry for every one of the five
provenance event types. That is what this test is for, and it is also what
every SOC dashboard panel built in Phase 10.4-10.7 is designed to render --
a real incident that went through this exact sequence is what "one
incident's full lifecycle is viewable" (Section 19's Phase 10 gate) means.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.agents.healthcare_context import assess_clinical_context
from app.agents.investigation import investigate
from app.agents.llm_client import MockLLMClient
from app.agents.recovery_verification import verify_recovery
from app.agents.response_planning import plan_response
from app.agents.threat_reasoning import assess_threat
from app.agents.tools import AgentToolkit
from app.api.detections import get_detection_service
from app.core.app_factory import create_app
from app.cybersecurity.detection_service import DetectionService, load_model
from app.cybersecurity.synthetic_data import generate_synthetic_dataset
from app.cybersecurity.training import save_artifacts, train_baselines
from app.repositories.log_capture import install, uninstall
from app.schemas.agents import (
    ClinicalContext,
    InvestigationReport,
    ProposedResponse,
    RecoveryResult,
    ThreatAssessment,
)

_DEVICE_ID = "ventilator-01"


@pytest.fixture(scope="module")
def trained_detection_service(tmp_path_factory):
    """Same pattern `tests/test_detections_api.py` already uses: a real
    model, quickly trained against the synthetic stand-in dataset (honestly
    labeled as such -- see `app/cybersecurity/training.py`), so
    `/detections/run-scenario` has something real to score with, without
    requiring a pre-trained artifact to exist on disk for this test to run.
    """
    output_dir = tmp_path_factory.mktemp("lifecycle_models")
    df = generate_synthetic_dataset(seed=7)
    results = train_baselines(df, seed=7)
    save_artifacts(results, output_dir, data_source="synthetic (lifecycle integration test fixture)", seed=7)
    model = load_model(output_dir / "random_forest.joblib")
    return DetectionService(model, confidence_threshold=0.0)


@pytest.fixture(scope="module")
def app(trained_detection_service):
    application = create_app()
    application.dependency_overrides[get_detection_service] = lambda: trained_detection_service
    return application


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app)


def _build_toolkit(app, log_handler) -> AgentToolkit:
    """Wires an `AgentToolkit` to this app's own `app.state` singletons --
    the exact same repositories the HTTP routes read from (see
    `app/core/app_factory.py::_register_state`) -- so a trace recorded here
    is retrievable through `GET /agents/{incident_id}` on this same running
    app, not a disconnected copy."""
    return AgentToolkit(
        device_registry=app.state.device_registry,
        incident_repository=app.state.incident_repository,
        network_event_store=app.state.network_event_store,
        telemetry_store=app.state.telemetry_store,
        log_handler=log_handler,
        trace_recorder=app.state.agent_trace_recorder,
        recovery_result_repository=app.state.recovery_result_repository,
    )


def test_one_incident_full_lifecycle_end_to_end(app, client):
    # --- 1. Detection (real model, real scripted attack scenario) ---
    detect_response = client.post("/detections/run-scenario")
    assert detect_response.status_code == 200
    detections = [d for d in detect_response.json() if d["device_id"] == _DEVICE_ID]
    assert detections, "the fixed scenario injects its attack against ventilator-01"

    incidents = [i for i in client.get("/incidents").json() if i["device_id"] == _DEVICE_ID]
    assert incidents, "a detection must have created a real Incident(status=detected)"
    incident_id = incidents[-1]["incident_id"]
    assert incidents[-1]["status"] == "detected"

    # --- 2. The five agents, manually sequenced (no orchestrator exists
    # yet -- see module docstring), LLM calls scripted via MockLLMClient ---
    log_handler = install()
    try:
        toolkit = _build_toolkit(app, log_handler)

        investigation_report = InvestigationReport(
            incident_id=incident_id,
            evidence=["spoofed_command network event targeting ventilator-01's tidal volume setpoint"],
            timeline=[
                "scenario tick 6: spoofed_command injected",
                "ventilator-01 network_state transitioned to compromised",
            ],
            affected_devices=[_DEVICE_ID],
            observations=["the command did not originate from an authenticated controller"],
            confidence=0.85,
        )
        real_report = investigate(
            MockLLMClient(responses=[investigation_report.model_dump_json()]),
            toolkit,
            incident_id=incident_id,
            device_id=_DEVICE_ID,
        )
        assert real_report == investigation_report

        threat_assessment = ThreatAssessment(
            incident_id=incident_id,
            attack_type="spoofing",
            severity="high",
            confidence=0.85,
            propagation_risk="medium",
            reasoning_summary=(
                "A spoofed command targeting a patient-dependent ventilator's tidal volume setpoint is "
                "high severity given direct patient-safety exposure."
            ),
        )
        real_threat = assess_threat(
            MockLLMClient(responses=[threat_assessment.model_dump_json()]),
            toolkit,
            report=real_report,
            device_id=_DEVICE_ID,
        )
        assert real_threat == threat_assessment

        clinical_context = ClinicalContext(
            incident_id=incident_id,
            device_criticality="high",
            patient_dependency=True,
            clinical_impact_level="high",
            safety_constraints=[
                "ventilator must not be shut down or fully isolated without a verified failover"
            ],
        )
        real_context = assess_clinical_context(
            MockLLMClient(responses=[clinical_context.model_dump_json()]),
            toolkit,
            incident_id=incident_id,
            affected_devices=[_DEVICE_ID],
        )
        assert real_context == clinical_context

        proposed_response = ProposedResponse(
            incident_id=incident_id,
            candidate_actions=[
                {
                    "action_category": "isolate_critical",
                    "description": "Isolate ventilator-01's network segment pending investigation",
                },
                {
                    "action_category": "block_traffic",
                    "description": "Block the spoofed command's source address",
                },
            ],
            security_benefit={"isolate_critical": 0.9, "block_traffic": 0.5},
            clinical_impact={"isolate_critical": "medium", "block_traffic": "low"},
            recommended_action="isolate_critical",
            rationale=(
                "Isolation fully contains the spoofing vector; clinical impact is medium rather than "
                "critical because the device keeps operating locally -- only its network segment is cut off."
            ),
        )
        real_proposal = plan_response(
            MockLLMClient(responses=[proposed_response.model_dump_json()]),
            toolkit,
            threat=real_threat,
            context=real_context,
            risk_score=None,
        )
        assert real_proposal == proposed_response
    finally:
        uninstall(log_handler)

    # The dashboard's Agent Activity panel reads exactly this endpoint.
    traces = client.get(f"/agents/{incident_id}").json()
    assert {t["agent_name"] for t in traces} == {
        "investigation",
        "threat_reasoning",
        "healthcare_context",
        "response_planning",
    }
    assert all(t["succeeded"] for t in traces)

    # --- 3. Risk assessment: real deterministic engine, real inputs ---
    risk_response = client.post(
        "/risk-assessments",
        json={
            "threat": real_threat.model_dump(mode="json"),
            "context": real_context.model_dump(mode="json"),
            "candidate_responses": [a.model_dump(mode="json") for a in real_proposal.candidate_actions],
        },
    )
    assert risk_response.status_code == 200
    risk_score = risk_response.json()
    assert risk_score["incident_id"] == incident_id
    assert 0.0 <= risk_score["cyber_risk"] <= 1.0
    assert 0.0 <= risk_score["clinical_risk"] <= 1.0

    # --- 4. Policy decision: real Policy Engine, persisted server-side ---
    propose_response = client.post(
        "/responses/proposed",
        json={
            "risk_score": risk_score,
            "proposed_response": real_proposal.model_dump(mode="json"),
            "context": real_context.model_dump(mode="json"),
        },
    )
    assert propose_response.status_code == 201
    decision = propose_response.json()
    assert decision["incident_id"] == incident_id

    # Retrievable exactly the way the dashboard's Response panel reads it.
    assert client.get(f"/responses/proposed/{incident_id}").json() == decision

    # --- 5. Execute: honor whichever branch the real policy engine chose ---
    approval = None
    if decision["requires_human_approval"]:
        approval = {
            "incident_id": incident_id,
            "approver_identity": "demo-soc-analyst",
            "decision": "approved",
            "timestamp": "2026-10-12T00:10:00+00:00",
            "notes": "Approved for this end-to-end lifecycle integration test.",
        }
    execute_response = client.post(
        "/responses/executed", json={"incident_id": incident_id, "approval": approval}
    )
    assert execute_response.status_code == 201
    executed = execute_response.json()
    assert executed["incident_id"] == incident_id
    assert executed["action_taken"] == decision["chosen_action"]

    # A real orchestrator side effect: the pending decision is cleared once executed.
    assert client.get(f"/responses/proposed/{incident_id}").status_code == 404
    assert len(client.get(f"/responses/executed/{incident_id}").json()) == 1

    # --- 6. Recovery verification agent, then submit its real result ---
    response_id = f"{incident_id}-response-1"
    log_handler = install()
    try:
        toolkit = _build_toolkit(app, log_handler)
        recovery_result = RecoveryResult(
            incident_id=incident_id,
            response_id=response_id,
            containment_verified=True,
            residual_threats=[],
            recovery_succeeded=True,
            reinvestigation_required=False,
        )
        real_recovery = verify_recovery(
            MockLLMClient(responses=[recovery_result.model_dump_json()]),
            toolkit,
            incident_id=incident_id,
            response_id=response_id,
            device_id=_DEVICE_ID,
        )
        assert real_recovery == recovery_result
    finally:
        uninstall(log_handler)

    recovery_response = client.post("/recovery", json=real_recovery.model_dump(mode="json"))
    assert recovery_response.status_code == 200
    assert recovery_response.json()["status"] == "resolved"

    # --- 7. Blockchain audit: drain the real outbox, confirm real provenance ---
    process_response = client.post("/blockchain/audit/process")
    assert process_response.status_code == 200

    audit_trail = client.get(f"/blockchain/audit/{incident_id}").json()
    expected_record_types = {"incident", "decision", "response", "recovery"}
    if approval is not None:
        expected_record_types.add("approval")
    assert {entry["record_type"] for entry in audit_trail} == expected_record_types
    assert all(entry["status"] == "confirmed" for entry in audit_trail), audit_trail
    assert all(entry["chain_tx_id"] is not None for entry in audit_trail)

    # --- Final state: what the dashboard's StatusBadge renders for this incident ---
    assert client.get(f"/incidents/{incident_id}").json()["status"] == "resolved"
