import pytest

from app.agents.base import AgentStalledError
from app.agents.llm_client import MockLLMClient
from app.agents.threat_reasoning import assess_threat
from app.agents.tools import AgentToolkit
from app.iomt_simulator.hospital import build_default_fleet
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import install, uninstall
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.agents import InvestigationReport, ThreatAssessment
from app.schemas.enums import AttackCategory, ImpactLevel, IncidentStatus


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


def _report(incident_id: str = "incident-1") -> InvestigationReport:
    return InvestigationReport(
        incident_id=incident_id,
        evidence=["spoofed_command event observed"],
        timeline=["t=30s: spoofed_command received"],
        affected_devices=["ventilator-01"],
        observations=["Command did not originate from an authenticated source"],
        confidence=0.8,
    )


def _valid_assessment_json(incident_id: str) -> str:
    return ThreatAssessment(
        incident_id=incident_id,
        attack_type=AttackCategory.SPOOFING,
        severity=ImpactLevel.HIGH,
        confidence=0.75,
        propagation_risk=ImpactLevel.MEDIUM,
        reasoning_summary="Unauthenticated command injection consistent with spoofing.",
    ).model_dump_json()


def test_assess_threat_returns_assessment_on_success(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_assessment_json("incident-1")])

    assessment = assess_threat(client, toolkit, _report(), device_id="ventilator-01")

    assert isinstance(assessment, ThreatAssessment)
    assert assessment.attack_type == AttackCategory.SPOOFING


def test_assess_threat_prompt_includes_investigation_report_evidence(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_assessment_json("incident-1")])

    assess_threat(client, toolkit, _report(), device_id="ventilator-01")

    assert "spoofed_command event observed" in client.calls[0]


def test_assess_threat_prompt_includes_prior_incidents_on_device_excluding_itself(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    toolkit.incident_repository.create("incident-0", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_assessment_json("incident-1")])

    assess_threat(client, toolkit, _report("incident-1"), device_id="ventilator-01")

    prompt = client.calls[0]
    assert "incident-0" in prompt
    # The incident being assessed should not appear in its own propagation
    # context list (though it legitimately appears elsewhere, e.g. in the
    # serialized investigation_report's incident_id field).
    import json

    payload = json.loads(prompt.split("Data:\n", 1)[1])
    prior_ids = [i["incident_id"] for i in payload["prior_incidents_on_device"]]
    assert "incident-1" not in prior_ids
    assert "incident-0" in prior_ids


def test_assess_threat_stalls_incident_after_repeated_invalid_output(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=["not json", "still not json"])

    with pytest.raises(AgentStalledError) as exc_info:
        assess_threat(client, toolkit, _report(), device_id="ventilator-01")

    assert exc_info.value.stall_status == IncidentStatus.THREAT_REASONING_STALLED
    assert toolkit.incident_repository.get("incident-1").status == IncidentStatus.THREAT_REASONING_STALLED
