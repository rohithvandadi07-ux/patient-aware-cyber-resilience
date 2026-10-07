import pytest

from app.agents.base import AgentStalledError
from app.agents.healthcare_context import assess_clinical_context
from app.agents.llm_client import MockLLMClient
from app.agents.tools import AgentToolkit
from app.iomt_simulator.hospital import build_default_fleet
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import install, uninstall
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.agents import ClinicalContext
from app.schemas.enums import DeviceCriticality, ImpactLevel, IncidentStatus


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


def _valid_context_json() -> str:
    return ClinicalContext(
        incident_id="incident-1",
        device_criticality=DeviceCriticality.HIGH,
        patient_dependency=True,
        clinical_impact_level=ImpactLevel.CRITICAL,
        safety_constraints=["ventilator must not be powered off while patient_dependency is true"],
    ).model_dump_json()


def test_assess_clinical_context_returns_context_on_success(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_context_json()])

    context = assess_clinical_context(
        client, toolkit, incident_id="incident-1", affected_devices=["ventilator-01"]
    )

    assert isinstance(context, ClinicalContext)
    assert context.device_criticality == DeviceCriticality.HIGH


def test_assess_clinical_context_prompt_reflects_real_device_state(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_context_json()])

    assess_clinical_context(client, toolkit, incident_id="incident-1", affected_devices=["ventilator-01"])

    prompt = client.calls[0]
    assert '"criticality": "high"' in prompt
    assert '"patient_dependency": true' in prompt


def test_assess_clinical_context_picks_most_significant_device_among_several(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_context_json()])

    # infusion-pump-01 is low criticality/non-dependent in the default fleet;
    # ventilator-01 is high criticality/patient-dependent -- the primary
    # device in the prompt must be the ventilator, not whichever is listed first.
    assess_clinical_context(
        client,
        toolkit,
        incident_id="incident-1",
        affected_devices=["infusion-pump-01", "ventilator-01"],
    )

    import json

    prompt = client.calls[0]
    payload = json.loads(prompt.split("Data:\n", 1)[1])
    assert payload["primary_device"]["device_id"] == "ventilator-01"
    assert len(payload["all_affected_devices"]) == 2


def test_assess_clinical_context_raises_value_error_for_empty_device_list(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[])

    with pytest.raises(ValueError, match="non-empty"):
        assess_clinical_context(client, toolkit, incident_id="incident-1", affected_devices=[])


def test_assess_clinical_context_stalls_incident_after_repeated_invalid_output(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=["not json", "still not json"])

    with pytest.raises(AgentStalledError) as exc_info:
        assess_clinical_context(
            client, toolkit, incident_id="incident-1", affected_devices=["ventilator-01"]
        )

    assert exc_info.value.stall_status == IncidentStatus.CONTEXT_STALLED
    assert toolkit.incident_repository.get("incident-1").status == IncidentStatus.CONTEXT_STALLED
