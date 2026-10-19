"""Deterministic guards on LLM agent output (`app.agents.grounding`), and their
wiring into the agent call path. No LLM is involved: scripted `MockLLMClient`
responses stand in for a wrong, lying or manipulated model."""

from datetime import UTC, datetime

import pytest

from app.agents.base import AgentStalledError
from app.agents.grounding import (
    IncidentIdMismatchError,
    check_incident_id,
    ground_clinical_context,
    ground_recovery_result,
)
from app.agents.healthcare_context import assess_clinical_context
from app.agents.llm_client import AgentFailure, MockLLMClient, generate_validated
from app.agents.recovery_verification import count_attack_events, verify_recovery
from app.agents.tools import AgentToolkit
from app.iomt_simulator.hospital import build_default_fleet
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import install, uninstall
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.agents import ClinicalContext, RecoveryResult
from app.schemas.enums import DeviceCriticality, ImpactLevel, IncidentStatus
from app.schemas.events import NetworkEvent

_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_FLEET = build_default_fleet()


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


def _context(**overrides) -> ClinicalContext:
    base = {
        "incident_id": "incident-1",
        "device_criticality": DeviceCriticality.HIGH,
        "patient_dependency": True,
        "clinical_impact_level": ImpactLevel.CRITICAL,
        "safety_constraints": ["do not power off"],
    }
    return ClinicalContext(**{**base, **overrides})


def _recovery(**overrides) -> RecoveryResult:
    base = {
        "incident_id": "incident-1",
        "response_id": "response-1",
        "containment_verified": True,
        "residual_threats": [],
        "recovery_succeeded": True,
        "reinvestigation_required": False,
    }
    return RecoveryResult(**{**base, **overrides})


def _attack_event(device_id: str) -> NetworkEvent:
    return NetworkEvent(
        device_id=device_id,
        timestamp=_NOW,
        event_type="spoofed_command",
        source="scenario_runner",
        is_attack_injection=True,
    )


# --- incident id -----------------------------------------------------------------


def test_matching_incident_id_passes_and_other_outputs_are_not_checked():
    check_incident_id(_context(), "incident-1")
    check_incident_id(_FLEET.get_device_state("ventilator-01"), "anything")  # has no incident_id


def test_a_different_incident_id_is_refused():
    with pytest.raises(IncidentIdMismatchError):
        check_incident_id(_context(incident_id="incident-2"), "incident-1")


def test_generate_validated_retries_a_wrong_incident_id_then_accepts_a_right_one():
    client = MockLLMClient(
        responses=[_context(incident_id="other").model_dump_json(), _context().model_dump_json()]
    )
    out = generate_validated(client, "p", ClinicalContext, "a", expected_incident_id="incident-1")
    assert out.incident_id == "incident-1"
    assert len(client.calls) == 2


def test_generate_validated_fails_when_the_wrong_incident_id_persists():
    wrong = _context(incident_id="other").model_dump_json()
    with pytest.raises(AgentFailure):
        generate_validated(
            MockLLMClient(responses=[wrong, wrong]),
            "p",
            ClinicalContext,
            "a",
            expected_incident_id="incident-1",
        )


def test_generate_validated_does_not_check_the_id_unless_asked():
    out = generate_validated(
        MockLLMClient(responses=[_context(incident_id="other").model_dump_json()]), "p", ClinicalContext, "a"
    )
    assert out.incident_id == "other"


# --- clinical context ---------------------------------------------------------------


def test_consistent_context_is_returned_unchanged():
    vent = _FLEET.get_device_state("ventilator-01")
    context, corrections = ground_clinical_context(_context(), vent)
    assert corrections == []
    assert context == _context()


def test_lying_criticality_and_dependency_are_replaced_with_the_registry_values():
    vent = _FLEET.get_device_state("ventilator-01")
    lie = _context(
        device_criticality=DeviceCriticality.LOW,
        patient_dependency=False,
        clinical_impact_level=ImpactLevel.LOW,
    )
    context, corrections = ground_clinical_context(lie, vent)
    assert context.device_criticality == DeviceCriticality.HIGH
    assert context.patient_dependency is True
    assert context.clinical_impact_level == ImpactLevel.HIGH  # floored
    assert len(corrections) == 3


def test_understated_impact_on_a_high_stakes_device_is_floored_but_never_lowered():
    vent = _FLEET.get_device_state("ventilator-01")
    low, _ = ground_clinical_context(_context(clinical_impact_level=ImpactLevel.MEDIUM), vent)
    assert low.clinical_impact_level == ImpactLevel.HIGH
    top, corrections = ground_clinical_context(_context(clinical_impact_level=ImpactLevel.CRITICAL), vent)
    assert top.clinical_impact_level == ImpactLevel.CRITICAL
    assert corrections == []


def test_impact_is_the_agents_judgement_for_a_device_that_is_not_high_stakes():
    low_devices = [
        _FLEET.get_device_state(d) for d in ("infusion-pump-01", "ecg-monitor-01", "ventilator-01")
    ]
    not_high_stakes = [
        d for d in low_devices if not (d.criticality == DeviceCriticality.HIGH and d.patient_dependency)
    ]
    for device in not_high_stakes:
        honest = _context(
            device_criticality=device.criticality,
            patient_dependency=device.patient_dependency,
            clinical_impact_level=ImpactLevel.LOW,
        )
        context, corrections = ground_clinical_context(honest, device)
        assert context.clinical_impact_level == ImpactLevel.LOW
        assert corrections == []


def test_grounding_does_not_mutate_its_input():
    vent = _FLEET.get_device_state("ventilator-01")
    lie = _context(patient_dependency=False)
    ground_clinical_context(lie, vent)
    assert lie.patient_dependency is False


def test_agent_call_applies_grounding_and_the_trace_shows_what_was_corrected(toolkit, caplog):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    lie = _context(
        device_criticality=DeviceCriticality.LOW,
        patient_dependency=False,
        clinical_impact_level=ImpactLevel.LOW,
    )
    client = MockLLMClient(responses=[lie.model_dump_json()])

    with caplog.at_level("WARNING"):
        context = assess_clinical_context(client, toolkit, "incident-1", ["ventilator-01"])

    assert context.patient_dependency is True
    assert context.device_criticality == DeviceCriticality.HIGH
    (trace,) = toolkit.trace_recorder.list_for_incident("incident-1")
    assert trace.succeeded
    assert len(trace.output_payload["grounding_corrections"]) == 3
    assert trace.output_payload["agent_output_before_grounding"]["patient_dependency"] is False
    assert trace.output_payload["patient_dependency"] is True
    assert "corrected against ground truth" in caplog.text


def test_an_honest_agent_leaves_a_clean_trace(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_context().model_dump_json()])
    assess_clinical_context(client, toolkit, "incident-1", ["ventilator-01"])
    (trace,) = toolkit.trace_recorder.list_for_incident("incident-1")
    assert "grounding_corrections" not in trace.output_payload


def test_a_context_about_another_incident_stalls_the_incident(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    wrong = _context(incident_id="other").model_dump_json()
    with pytest.raises(AgentStalledError):
        assess_clinical_context(
            MockLLMClient(responses=[wrong, wrong]), toolkit, "incident-1", ["ventilator-01"]
        )
    assert toolkit.incident_repository.get("incident-1").status == IncidentStatus.CONTEXT_STALLED


# --- recovery result ----------------------------------------------------------------


def test_recovery_claim_stands_when_no_new_attack_events_arrived():
    result, corrections = ground_recovery_result(_recovery(), 0)
    assert corrections == []
    assert result.recovery_succeeded is True


def test_a_failed_recovery_claim_is_left_alone_even_with_new_attack_events():
    honest_failure = _recovery(
        containment_verified=False, recovery_succeeded=False, reinvestigation_required=True
    )
    result, corrections = ground_recovery_result(honest_failure, 3)
    assert corrections == []
    assert result == honest_failure


def test_claimed_containment_is_overridden_when_attack_events_arrived_afterwards():
    result, corrections = ground_recovery_result(_recovery(), 2)
    assert result.containment_verified is False
    assert result.recovery_succeeded is False
    assert result.reinvestigation_required is True
    assert any("2 attack-labelled" in t for t in result.residual_threats)
    assert len(corrections) == 1


def test_either_claim_alone_triggers_the_override():
    half = _recovery(containment_verified=False, recovery_succeeded=True, reinvestigation_required=False)
    result, corrections = ground_recovery_result(half, 1)
    assert result.recovery_succeeded is False and result.reinvestigation_required is True
    assert corrections


def test_existing_residual_threats_are_kept():
    result, _ = ground_recovery_result(_recovery(residual_threats=["seen earlier"]), 1)
    assert result.residual_threats[0] == "seen earlier"
    assert len(result.residual_threats) == 2


def test_count_attack_events_counts_only_attack_labelled_events(toolkit):
    store = toolkit.network_event_store
    store.record_many([_attack_event("ventilator-01")])
    store.record_many(
        [NetworkEvent(device_id="ventilator-01", timestamp=_NOW, event_type="heartbeat", source="d")]
    )
    store.record_many([_attack_event("ecg-monitor-01")])
    assert count_attack_events(toolkit, "ventilator-01") == 1


def test_verify_recovery_overrides_a_false_all_clear_when_new_attack_evidence_arrived(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    toolkit.network_event_store.record_many([_attack_event("ventilator-01")])
    snapshot = count_attack_events(toolkit, "ventilator-01")
    toolkit.network_event_store.record_many([_attack_event("ventilator-01")])  # after the response

    client = MockLLMClient(responses=[_recovery().model_dump_json()])
    result = verify_recovery(
        client, toolkit, "incident-1", "response-1", "ventilator-01", attack_events_at_execution=snapshot
    )

    assert result.recovery_succeeded is False
    assert result.reinvestigation_required is True
    (trace,) = toolkit.trace_recorder.list_for_incident("incident-1")
    assert trace.output_payload["agent_output_before_grounding"]["recovery_succeeded"] is True


def test_verify_recovery_without_a_snapshot_applies_no_recovery_grounding(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    toolkit.network_event_store.record_many([_attack_event("ventilator-01")])
    client = MockLLMClient(responses=[_recovery().model_dump_json()])
    result = verify_recovery(client, toolkit, "incident-1", "response-1", "ventilator-01")
    assert result.recovery_succeeded is True
