from datetime import UTC, datetime

import pytest

from app.agents.tools import AgentToolkit
from app.iomt_simulator.hospital import build_default_fleet
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import install, uninstall
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.agents import ClinicalContext
from app.schemas.enums import DeviceCriticality, ImpactLevel, ResponseActionCategory
from app.schemas.events import NetworkEvent
from app.schemas.risk import RiskScore

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


def test_get_recovery_results_for_incident_returns_empty_when_nothing_recorded(toolkit):
    assert toolkit.get_recovery_results_for_incident("incident-1") == []


def test_get_recovery_results_for_incident_reflects_the_same_repository_the_property_exposes(toolkit):
    # Phase 7: toolkit.recovery_result_repository is the same instance the
    # Recovery Orchestrator (L8) records into -- a write through the
    # property must show up through the read-only tool method.
    from app.schemas.agents import RecoveryResult

    result = RecoveryResult(
        incident_id="incident-1",
        response_id="response-1",
        containment_verified=True,
        residual_threats=[],
        recovery_succeeded=True,
        reinvestigation_required=False,
    )
    toolkit.recovery_result_repository.record(result)

    results = toolkit.get_recovery_results_for_incident("incident-1")

    assert results == [result]


def test_toolkit_defaults_to_a_fresh_recovery_result_repository_when_none_is_passed(toolkit):
    # The constructor parameter is optional for backward compatibility with
    # Phase 4-6 callers -- confirms the default is a real, usable repository,
    # not None.
    assert toolkit.get_recovery_results_for_incident("anything") == []


def test_toolkit_uses_an_explicitly_passed_recovery_result_repository_instance():
    from app.repositories.recovery_results import RecoveryResultRepository

    log_handler = install()
    shared_repo = RecoveryResultRepository()
    try:
        toolkit = AgentToolkit(
            device_registry=build_default_fleet(),
            incident_repository=IncidentRepository(),
            network_event_store=NetworkEventStore(),
            telemetry_store=TelemetryStore(),
            log_handler=log_handler,
            trace_recorder=AgentTraceRecorder(),
            recovery_result_repository=shared_repo,
        )
        assert toolkit.recovery_result_repository is shared_repo
    finally:
        uninstall(log_handler)


def test_evaluate_policy_routes_every_scored_action_through_the_real_policy_engine(toolkit):
    # Phase 6 wiring: this used to raise NotImplementedError (Policy Engine
    # not built yet). It now calls the real app/policy_engine/engine.py.
    context = ClinicalContext(
        incident_id="incident-1",
        device_criticality=DeviceCriticality.LOW,
        patient_dependency=False,
        clinical_impact_level=ImpactLevel.LOW,
        safety_constraints=[],
    )
    risk_score = RiskScore(
        incident_id="incident-1",
        cyber_risk=0.4,
        clinical_risk=0.2,
        response_impact={
            "isolate_non_critical": ImpactLevel.LOW,
            "shutdown": ImpactLevel.HIGH,
        },
        explanation="test",
    )

    decisions = toolkit.evaluate_policy(risk_score, context)

    assert set(decisions) == {"isolate_non_critical", "shutdown"}
    assert decisions["isolate_non_critical"].requires_human_approval is False
    assert decisions["shutdown"].requires_human_approval is True
    assert decisions["shutdown"].chosen_action == ResponseActionCategory.SHUTDOWN


def test_evaluate_policy_returns_empty_dict_when_nothing_has_been_scored(toolkit):
    context = ClinicalContext(
        incident_id="incident-1",
        device_criticality=DeviceCriticality.LOW,
        patient_dependency=False,
        clinical_impact_level=ImpactLevel.LOW,
        safety_constraints=[],
    )
    risk_score = RiskScore(
        incident_id="incident-1", cyber_risk=0.1, clinical_risk=0.1, response_impact={}, explanation="test"
    )

    assert toolkit.evaluate_policy(risk_score, context) == {}


def test_get_network_events_reflects_store_contents(toolkit):
    event = NetworkEvent(device_id="ventilator-01", timestamp=_NOW, event_type="spoofed_command", source="x")
    toolkit.network_event_store.record_many([event])
    results = toolkit.get_network_events("ventilator-01")
    assert len(results) == 1
    assert results[0].event_type == "spoofed_command"
