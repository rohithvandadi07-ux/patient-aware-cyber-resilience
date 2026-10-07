import logging
from datetime import UTC, datetime

import pytest

from app.agents.base import AgentStalledError
from app.agents.investigation import investigate
from app.agents.llm_client import MockLLMClient
from app.agents.tools import AgentToolkit
from app.iomt_simulator.hospital import build_default_fleet
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import install, uninstall
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.agents import InvestigationReport
from app.schemas.enums import IncidentStatus
from app.schemas.events import NetworkEvent

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


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


def _valid_report_json(incident_id: str) -> str:
    return InvestigationReport(
        incident_id=incident_id,
        evidence=["spoofed_command event observed at t=30s"],
        timeline=["t=30s: spoofed_command received"],
        affected_devices=["ventilator-01"],
        observations=["Command did not originate from an authenticated source"],
        confidence=0.8,
    ).model_dump_json()


def test_investigate_returns_report_on_first_success(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_report_json("incident-1")])

    report = investigate(client, toolkit, incident_id="incident-1", device_id="ventilator-01")

    assert isinstance(report, InvestigationReport)
    assert report.incident_id == "incident-1"
    assert report.affected_devices == ["ventilator-01"]


def test_investigate_records_success_trace(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_report_json("incident-1")])

    investigate(client, toolkit, incident_id="incident-1", device_id="ventilator-01")

    traces = toolkit.trace_recorder.list_for_incident("incident-1")
    assert len(traces) == 1
    assert traces[0].agent_name == "investigation"
    assert traces[0].succeeded is True
    assert traces[0].output_payload["incident_id"] == "incident-1"


def test_investigate_prompt_includes_real_network_events(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    toolkit.network_event_store.record_many(
        [
            NetworkEvent(
                device_id="ventilator-01",
                timestamp=_NOW,
                event_type="spoofed_command",
                source="scenario_runner",
                is_attack_injection=True,
            )
        ]
    )
    client = MockLLMClient(responses=[_valid_report_json("incident-1")])

    investigate(client, toolkit, incident_id="incident-1", device_id="ventilator-01")

    assert "spoofed_command" in client.calls[0]
    assert "scenario_runner" in client.calls[0]


def test_investigate_prompt_includes_captured_logs(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    logger = logging.getLogger("app.test.investigation")
    logger.setLevel(logging.INFO)
    logger.info(
        "unusual command pattern detected",
        extra={"device_id": "ventilator-01", "incident_id": "incident-1"},
    )

    client = MockLLMClient(responses=[_valid_report_json("incident-1")])
    investigate(client, toolkit, incident_id="incident-1", device_id="ventilator-01")

    assert "unusual command pattern detected" in client.calls[0]


def test_investigate_stalls_incident_after_repeated_invalid_output(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=["not json", "still not json"])

    with pytest.raises(AgentStalledError) as exc_info:
        investigate(client, toolkit, incident_id="incident-1", device_id="ventilator-01")

    assert exc_info.value.stall_status == IncidentStatus.INVESTIGATION_STALLED
    assert toolkit.incident_repository.get("incident-1").status == IncidentStatus.INVESTIGATION_STALLED


def test_investigate_records_failure_trace_on_stall(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=["not json", "still not json"])

    with pytest.raises(AgentStalledError):
        investigate(client, toolkit, incident_id="incident-1", device_id="ventilator-01")

    traces = toolkit.trace_recorder.list_for_incident("incident-1")
    assert len(traces) == 1
    assert traces[0].succeeded is False
    assert traces[0].output_payload is None
