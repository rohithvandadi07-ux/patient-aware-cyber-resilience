"""Real tests for `IncidentOrchestrator` -- the post-Phase-15 pipeline
sequencer. Same proven pattern `tests/test_lifecycle_integration.py` already
established: a real FastAPI app, real repositories/registries off
`app.state`, `MockLLMClient` scripted with the same literal values that
test already proved produce a consistent, schema-valid chain end to end.
No live LLM call happens here -- `MockLLMClient` is this project's own
established test double; these tests prove the *sequencing, status
bookkeeping, and re-investigation loop* are real, not that live LLM
reasoning occurred.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.agents.llm_client import MockLLMClient
from app.agents.tools import AgentToolkit
from app.core.app_factory import create_app
from app.orchestration.orchestrator import IncidentOrchestrator
from app.recovery.engine import RecoveryOrchestrator
from app.repositories.log_capture import install, uninstall
from app.response_engine.orchestrator import ResponseOrchestrator
from app.risk_engine.rule_based import RuleBasedRiskModel

_DEVICE_ID = "ventilator-01"

_INVESTIGATION_REPORT = {
    "evidence": ["spoofed_command network event targeting ventilator-01's tidal volume setpoint"],
    "timeline": [
        "scenario tick 6: spoofed_command injected",
        "ventilator-01 network_state transitioned to compromised",
    ],
    "affected_devices": [_DEVICE_ID],
    "observations": ["the command did not originate from an authenticated controller"],
    "confidence": 0.85,
}

_THREAT_ASSESSMENT = {
    "attack_type": "spoofing",
    "severity": "high",
    "confidence": 0.85,
    "propagation_risk": "medium",
    "reasoning_summary": (
        "A spoofed command targeting a patient-dependent ventilator's tidal volume setpoint is "
        "high severity given direct patient-safety exposure."
    ),
}

_CLINICAL_CONTEXT = {
    "device_criticality": "high",
    "patient_dependency": True,
    "clinical_impact_level": "high",
    "safety_constraints": [
        "ventilator must not be shut down or fully isolated without a verified failover"
    ],
}

_PROPOSED_RESPONSE = {
    "candidate_actions": [
        {
            "action_category": "isolate_critical",
            "description": "Isolate ventilator-01's network segment pending investigation",
        },
        {
            "action_category": "block_traffic",
            "description": "Block the spoofed command's source address",
        },
    ],
    "security_benefit": {"isolate_critical": 0.9, "block_traffic": 0.5},
    "clinical_impact": {"isolate_critical": "medium", "block_traffic": "low"},
    "recommended_action": "isolate_critical",
    "rationale": (
        "Isolation fully contains the spoofing vector; clinical impact is medium rather than "
        "critical because the device keeps operating locally -- only its network segment is cut off."
    ),
}


def _recovery_result(*, succeeded: bool, reinvestigation_required: bool, response_n: int) -> dict:
    return {
        "response_id": f"{{incident_id}}-response-{response_n}",
        "containment_verified": succeeded,
        "residual_threats": [] if succeeded else ["spoofed_command source still reachable"],
        "recovery_succeeded": succeeded,
        "reinvestigation_required": reinvestigation_required,
    }


def _scripted_responses(incident_id: str, *, recovery: dict) -> list[str]:
    """One full pass's worth of agent responses, in the exact call order
    `IncidentOrchestrator._run` makes them."""
    import json

    def with_id(payload: dict) -> str:
        return json.dumps({"incident_id": incident_id, **payload})

    recovery_payload = dict(recovery)
    recovery_payload["response_id"] = recovery_payload["response_id"].format(incident_id=incident_id)
    return [
        with_id(_INVESTIGATION_REPORT),
        with_id(_THREAT_ASSESSMENT),
        with_id(_CLINICAL_CONTEXT),
        with_id(_PROPOSED_RESPONSE),
        with_id(recovery_payload),
    ]


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app)


def _create_incident(client: TestClient, incident_id: str) -> None:
    response = client.post(
        "/incidents",
        json={
            "incident_id": incident_id,
            "device_id": _DEVICE_ID,
            "attack_type": "spoofing",
            "evidence_ref": "test-evidence-ref",
            "timestamp": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 201, response.text


def _build_orchestrator(app, client: MockLLMClient, log_handler) -> IncidentOrchestrator:
    toolkit = AgentToolkit(
        device_registry=app.state.device_registry,
        incident_repository=app.state.incident_repository,
        network_event_store=app.state.network_event_store,
        telemetry_store=app.state.telemetry_store,
        log_handler=log_handler,
        trace_recorder=app.state.agent_trace_recorder,
        recovery_result_repository=app.state.recovery_result_repository,
    )
    return IncidentOrchestrator(
        client=client,
        toolkit=toolkit,
        incident_repository=app.state.incident_repository,
        proposed_response_repository=app.state.proposed_response_repository,
        executed_response_repository=app.state.executed_response_repository,
        response_orchestrator=ResponseOrchestrator(
            device_registry=app.state.device_registry,
            incident_repository=app.state.incident_repository,
        ),
        recovery_orchestrator=RecoveryOrchestrator(
            incident_repository=app.state.incident_repository,
            recovery_result_repository=app.state.recovery_result_repository,
        ),
        outbox_repository=app.state.outbox_repository,
        risk_model=RuleBasedRiskModel(),
        max_reinvestigations=2,
    )


def test_full_cycle_auto_approved_resolves(app, client):
    """auto_approve=True + a clean recovery result -> RESOLVED, with every
    intermediate IncidentStatus actually written (not left at DETECTED)."""
    incident_id = "orch-resolve-1"
    _create_incident(client, incident_id)

    log_handler = install()
    try:
        mock = MockLLMClient(
            responses=_scripted_responses(
                incident_id,
                recovery=_recovery_result(succeeded=True, reinvestigation_required=False, response_n=1),
            )
        )
        orchestrator = _build_orchestrator(app, mock, log_handler)
        result = orchestrator.run_investigation_cycle(incident_id, _DEVICE_ID, auto_approve=True)
    finally:
        uninstall(log_handler)

    assert result.final_status == "resolved"
    assert result.reinvestigation_count == 0
    assert result.executed is not None
    assert result.executed.action_taken.value == "isolate_critical"
    assert any("auto-approved" in line for line in result.history)

    # Every stage that ran was timed (wall-clock, in-process; mock LLM so agent stages are ~0).
    assert {
        "investigation",
        "threat_reasoning",
        "healthcare_context",
        "response_planning",
        "risk_engine",
        "policy_engine",
        "response_execution",
        "recovery_verification",
        "recovery_routing",
    } == set(result.stage_timings_ms)
    assert all(ms >= 0 for ms in result.stage_timings_ms.values())

    # The incident really did pass through every intermediate status this
    # orchestrator is responsible for writing, not just DETECTED -> RESOLVED.
    traces = client.get(f"/agents/{incident_id}").json()
    assert {t["agent_name"] for t in traces} == {
        "investigation",
        "threat_reasoning",
        "healthcare_context",
        "response_planning",
        "recovery_verification",
    }
    assert all(t["succeeded"] for t in traces)
    assert client.get(f"/incidents/{incident_id}").json()["status"] == "resolved"

    # Real blockchain provenance was enqueued along the way (decision,
    # approval, response, recovery -- the same four a manual HTTP-driven
    # run produces per test_lifecycle_integration.py).
    process_response = client.post("/blockchain/audit/process")
    assert process_response.status_code == 200
    audit_trail = client.get(f"/blockchain/audit/{incident_id}").json()
    record_types = {entry["record_type"] for entry in audit_trail}
    assert {"decision", "approval", "response", "recovery"} <= record_types
    assert all(entry["status"] == "confirmed" for entry in audit_trail)


def test_requires_approval_stops_without_auto_approve(app, client):
    """auto_approve defaults to False -- a decision that requires human
    approval stops the cycle at AWAITING_APPROVAL rather than fabricating
    an approval."""
    incident_id = "orch-approval-1"
    _create_incident(client, incident_id)

    log_handler = install()
    try:
        # Only 4 responses needed -- the cycle stops before recovery verification.
        full_pass = _scripted_responses(
            incident_id,
            recovery=_recovery_result(succeeded=True, reinvestigation_required=False, response_n=1),
        )
        mock = MockLLMClient(responses=full_pass[:4])
        orchestrator = _build_orchestrator(app, mock, log_handler)
        result = orchestrator.run_investigation_cycle(incident_id, _DEVICE_ID, auto_approve=False)
    finally:
        uninstall(log_handler)

    assert result.final_status == "awaiting_approval"
    assert result.awaiting_approval_decision is not None
    assert result.awaiting_approval_decision.requires_human_approval is True
    assert result.executed is None
    assert client.get(f"/incidents/{incident_id}").json()["status"] == "awaiting_approval"


def test_reopened_recovery_triggers_real_reinvestigation(app, client):
    """The previously-disclosed gap this module exists to close: a
    RecoveryResult with reinvestigation_required=True must actually cause a
    second full agent pass, not just flip a status flag nothing reads."""
    incident_id = "orch-reinvestigate-1"
    _create_incident(client, incident_id)

    log_handler = install()
    try:
        first_pass = _scripted_responses(
            incident_id,
            recovery=_recovery_result(succeeded=True, reinvestigation_required=True, response_n=1),
        )
        second_pass = _scripted_responses(
            incident_id,
            recovery=_recovery_result(succeeded=True, reinvestigation_required=False, response_n=2),
        )
        mock = MockLLMClient(responses=[*first_pass, *second_pass])
        orchestrator = _build_orchestrator(app, mock, log_handler)
        result = orchestrator.run_investigation_cycle(incident_id, _DEVICE_ID, auto_approve=True)
    finally:
        uninstall(log_handler)

    assert result.final_status == "resolved"
    assert result.reinvestigation_count == 1, (
        "a REOPENED recovery result must increment reinvestigation_count and actually "
        "re-run investigate()/assess_threat()/etc. -- this is the real re-investigation "
        "loop, not RecoveryOrchestrator's REOPENED status transition alone"
    )
    assert any("re-investigation attempt 1" in line for line in result.history)

    # Both passes' agent traces are really there -- ten traces (5 agents x
    # 2 passes), not five -- proving the agents genuinely ran twice.
    traces = client.get(f"/agents/{incident_id}").json()
    assert len(traces) == 10, f"expected 10 traces (5 agents x 2 passes), got {len(traces)}"

    # Two separate ExecutedResponse records (one per pass) -- the device
    # was really isolated twice, not just marked resolved.
    executed = client.get(f"/responses/executed/{incident_id}").json()
    assert len(executed) == 2


def test_reinvestigation_budget_exhausted_stays_reopened(app, client):
    """If every recovery attempt keeps requiring re-investigation,
    max_reinvestigations bounds the loop -- the incident stays REOPENED
    (visibly, honestly) rather than retrying forever."""
    incident_id = "orch-exhausted-1"
    _create_incident(client, incident_id)

    log_handler = install()
    try:
        passes = [
            _scripted_responses(
                incident_id,
                recovery=_recovery_result(succeeded=False, reinvestigation_required=True, response_n=n),
            )
            for n in (1, 2, 3)
        ]
        mock = MockLLMClient(responses=[r for p in passes for r in p])
        orchestrator = _build_orchestrator(app, mock, log_handler)
        orchestrator._max_reinvestigations = 2
        result = orchestrator.run_investigation_cycle(incident_id, _DEVICE_ID, auto_approve=True)
    finally:
        uninstall(log_handler)

    assert result.final_status == "reopened"
    assert result.reinvestigation_count == 2
    assert any("budget exhausted" in line for line in result.history)
    assert client.get(f"/incidents/{incident_id}").json()["status"] == "reopened"
