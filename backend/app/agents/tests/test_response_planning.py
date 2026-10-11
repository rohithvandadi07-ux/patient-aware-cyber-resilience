import json

import pytest

from app.agents.base import AgentStalledError
from app.agents.llm_client import MockLLMClient
from app.agents.response_planning import plan_response
from app.agents.tools import AgentToolkit
from app.iomt_simulator.hospital import build_default_fleet
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import install, uninstall
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.agents import CandidateAction, ClinicalContext, ProposedResponse, ThreatAssessment
from app.schemas.enums import (
    AttackCategory,
    DeviceCriticality,
    ImpactLevel,
    IncidentStatus,
    ResponseActionCategory,
)
from app.schemas.risk import RiskScore


@pytest.fixture
def toolkit():
    log_handler = install()
    try:
        yield AgentToolkit(
            device_registry=build_default_fleet(),
            incident_repository=IncidentRepository(),
            network_event_store=NetworkEventStore(),
            telemetry_store=TelemetryStore(),
            log_handler=log_handler,
            trace_recorder=AgentTraceRecorder(),
        )
    finally:
        uninstall(log_handler)


def _threat(incident_id: str = "incident-1") -> ThreatAssessment:
    return ThreatAssessment(
        incident_id=incident_id,
        attack_type=AttackCategory.SPOOFING,
        severity=ImpactLevel.HIGH,
        confidence=0.75,
        propagation_risk=ImpactLevel.MEDIUM,
        reasoning_summary="Unauthenticated command injection.",
    )


def _context(incident_id: str = "incident-1") -> ClinicalContext:
    return ClinicalContext(
        incident_id=incident_id,
        device_criticality=DeviceCriticality.HIGH,
        patient_dependency=True,
        clinical_impact_level=ImpactLevel.CRITICAL,
        safety_constraints=["ventilator must not be powered off while patient_dependency is true"],
    )


def _valid_proposal_json(incident_id: str = "incident-1") -> str:
    return ProposedResponse(
        incident_id=incident_id,
        candidate_actions=[
            CandidateAction(
                action_category=ResponseActionCategory.ISOLATE_NON_CRITICAL,
                description="Isolate the compromised network segment",
            )
        ],
        security_benefit={"isolate_non_critical": 0.7},
        clinical_impact={"isolate_non_critical": ImpactLevel.LOW},
        recommended_action=ResponseActionCategory.ISOLATE_NON_CRITICAL,
        rationale="Contains the threat without disrupting the ventilator directly.",
    ).model_dump_json()


def test_plan_response_returns_proposal_on_success(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_proposal_json()])

    proposal = plan_response(client, toolkit, _threat(), _context())

    assert isinstance(proposal, ProposedResponse)
    assert proposal.recommended_action == ResponseActionCategory.ISOLATE_NON_CRITICAL


def test_plan_response_notes_no_risk_score_unavailable_in_prompt(toolkit):
    # No risk_score was passed -- the Policy Engine has nothing to route on,
    # so the prompt must say so honestly rather than fabricating a check.
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_proposal_json()])

    plan_response(client, toolkit, _threat(), _context())

    assert "not available: no RiskScore provided yet" in client.calls[0]


def test_plan_response_notes_no_scored_actions_yet_when_risk_score_response_impact_is_empty(toolkit):
    # A RiskScore technically exists but scored nothing (candidate_responses
    # was empty at risk-engine time) -- the prompt must distinguish this from
    # "no RiskScore at all" and still avoid assuming either routing outcome.
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_proposal_json()])
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.1,
        clinical_risk=0.1,
        response_impact={},
        explanation="test",
    )

    plan_response(client, toolkit, _threat(), _context(), risk_score=risk_score)

    assert "not available: risk_score has no scored candidate actions yet" in client.calls[0]


def test_plan_response_includes_real_policy_pre_check_in_prompt_when_risk_score_provided(toolkit):
    # With a real risk_score, the Phase 6 Policy Engine is wired in for real
    # -- the prompt must carry its actual per-action routing decision, not a
    # stubbed "Phase 6 work" placeholder.
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_proposal_json()])
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.8,
        clinical_risk=0.9,
        response_impact={"isolate_non_critical": ImpactLevel.LOW},
        explanation="High clinical risk due to patient dependency.",
    )

    plan_response(client, toolkit, _threat(), _context(), risk_score=risk_score)

    assert "isolate_non_critical" in client.calls[0]
    assert "autonomous OK" in client.calls[0]
    assert "rule=autonomous_low_impact" in client.calls[0]


def test_plan_response_with_no_risk_score_says_so_rather_than_fabricating_one(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_proposal_json()])

    plan_response(client, toolkit, _threat(), _context(), risk_score=None)

    payload = json.loads(client.calls[0].split("Data:\n", 1)[1])
    assert payload["risk_score"] is None


def test_plan_response_includes_real_risk_score_when_provided(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_proposal_json()])
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.8,
        clinical_risk=0.9,
        response_impact={"isolate_non_critical": ImpactLevel.LOW},
        explanation="High clinical risk due to patient dependency.",
    )

    plan_response(client, toolkit, _threat(), _context(), risk_score=risk_score)

    payload = json.loads(client.calls[0].split("Data:\n", 1)[1])
    assert payload["risk_score"]["cyber_risk"] == 0.8


def test_plan_response_never_calls_an_execute_tool():
    # Structural check: AgentToolkit has no execute-capable method at all for
    # this (or any) agent to call, regardless of what the LLM proposes.
    toolkit_methods = [name for name in dir(AgentToolkit) if not name.startswith("_")]
    assert not any("execute" in name for name in toolkit_methods)


def test_plan_response_stalls_incident_after_repeated_invalid_output(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=["not json", "still not json"])

    with pytest.raises(AgentStalledError) as exc_info:
        plan_response(client, toolkit, _threat(), _context())

    assert exc_info.value.stall_status == IncidentStatus.RESPONSE_PLANNING_STALLED
    status = toolkit.incident_repository.get("incident-1").status
    assert status == IncidentStatus.RESPONSE_PLANNING_STALLED
