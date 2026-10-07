from datetime import UTC, datetime

import pytest

from app.agents.tools import AgentToolkit
from app.iomt_simulator.hospital import build_default_fleet
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import install, uninstall
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
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


def test_get_device_state_returns_real_registry_data(toolkit):
    state = toolkit.get_device_state("ventilator-01")
    assert state.device_id == "ventilator-01"
    assert state.patient_dependency is True


def test_get_network_events_returns_empty_when_nothing_recorded(toolkit):
    assert toolkit.get_network_events("ventilator-01") == []


def test_get_telemetry_returns_empty_when_nothing_recorded(toolkit):
    assert toolkit.get_telemetry("ventilator-01") == []


def test_get_incident_raises_for_unknown_incident(toolkit):
    from app.repositories.incidents import IncidentNotFoundError

    with pytest.raises(IncidentNotFoundError):
        toolkit.get_incident("does-not-exist")


def test_get_prior_incidents_for_device_reflects_repository_state(toolkit):
    # Toolkit wraps a real IncidentRepository instance passed in, so creating
    # an incident through the same repository must show up through the tool.
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    results = toolkit.get_prior_incidents_for_device("ventilator-01")
    assert len(results) == 1
    assert results[0].incident_id == "incident-1"


def test_evaluate_policy_raises_not_implemented(toolkit):
    with pytest.raises(NotImplementedError, match="Phase 6"):
        toolkit.evaluate_policy()


def test_get_network_events_reflects_store_contents(toolkit):
    event = NetworkEvent(device_id="ventilator-01", timestamp=_NOW, event_type="spoofed_command", source="x")
    toolkit.network_event_store.record_many([event])
    results = toolkit.get_network_events("ventilator-01")
    assert len(results) == 1
    assert results[0].event_type == "spoofed_command"
