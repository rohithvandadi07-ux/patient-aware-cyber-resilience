from datetime import UTC, datetime

import pytest

from app.agents.base import AgentStalledError
from app.agents.llm_client import MockLLMClient
from app.agents.recovery_verification import verify_recovery
from app.agents.tools import AgentToolkit
from app.iomt_simulator.hospital import build_default_fleet
from app.repositories.agent_traces import AgentTraceRecorder
from app.repositories.incidents import IncidentRepository
from app.repositories.log_capture import install, uninstall
from app.repositories.telemetry_events import NetworkEventStore, TelemetryStore
from app.schemas.agents import RecoveryResult
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


def _valid_result_json(recovery_succeeded: bool = True) -> str:
    return RecoveryResult(
        incident_id="incident-1",
        response_id="response-1",
        containment_verified=recovery_succeeded,
        residual_threats=[] if recovery_succeeded else ["unexplained command still observed"],
        recovery_succeeded=recovery_succeeded,
        reinvestigation_required=not recovery_succeeded,
    ).model_dump_json()


def test_verify_recovery_returns_result_on_success(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_result_json(recovery_succeeded=True)])

    result = verify_recovery(
        client, toolkit, incident_id="incident-1", response_id="response-1", device_id="ventilator-01"
    )

    assert isinstance(result, RecoveryResult)
    assert result.recovery_succeeded is True
    assert result.reinvestigation_required is False


def test_verify_recovery_prompt_includes_response_id_and_device_state(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_result_json()])

    verify_recovery(
        client, toolkit, incident_id="incident-1", response_id="response-1", device_id="ventilator-01"
    )

    prompt = client.calls[0]
    assert "response-1" in prompt
    assert "ventilator-01" in prompt


def test_verify_recovery_prompt_includes_post_response_network_events(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    toolkit.network_event_store.record_many(
        [
            NetworkEvent(
                device_id="ventilator-01",
                timestamp=_NOW,
                event_type="unexplained_command",
                source="unknown",
                is_attack_injection=False,
            )
        ]
    )
    client = MockLLMClient(responses=[_valid_result_json(recovery_succeeded=False)])

    result = verify_recovery(
        client, toolkit, incident_id="incident-1", response_id="response-1", device_id="ventilator-01"
    )

    assert "unexplained_command" in client.calls[0]
    assert result.reinvestigation_required is True


def test_verify_recovery_does_not_itself_mutate_incident_status_on_success(toolkit):
    # Section 7 step 12's "closes the incident" is orchestration logic this
    # agent deliberately does not perform -- it only reports the finding.
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=[_valid_result_json(recovery_succeeded=True)])

    verify_recovery(
        client, toolkit, incident_id="incident-1", response_id="response-1", device_id="ventilator-01"
    )

    assert toolkit.incident_repository.get("incident-1").status == IncidentStatus.DETECTED


def test_verify_recovery_stalls_incident_after_repeated_invalid_output(toolkit):
    toolkit.incident_repository.create("incident-1", device_id="ventilator-01")
    client = MockLLMClient(responses=["not json", "still not json"])

    with pytest.raises(AgentStalledError) as exc_info:
        verify_recovery(
            client, toolkit, incident_id="incident-1", response_id="response-1", device_id="ventilator-01"
        )

    assert exc_info.value.stall_status == IncidentStatus.RECOVERY_VERIFICATION_STALLED
    status = toolkit.incident_repository.get("incident-1").status
    assert status == IncidentStatus.RECOVERY_VERIFICATION_STALLED
