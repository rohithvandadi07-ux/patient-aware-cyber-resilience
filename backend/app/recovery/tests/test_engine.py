import pytest

from app.recovery.engine import InconsistentRecoveryResultError, RecoveryOrchestrator
from app.repositories.incidents import IncidentNotFoundError, IncidentRepository
from app.repositories.recovery_results import RecoveryResultRepository
from app.schemas.agents import RecoveryResult
from app.schemas.enums import IncidentStatus


@pytest.fixture
def incidents() -> IncidentRepository:
    repo = IncidentRepository()
    repo.create("incident-1", device_id="ventilator-01")
    return repo


@pytest.fixture
def recovery_results() -> RecoveryResultRepository:
    return RecoveryResultRepository()


@pytest.fixture
def orchestrator(
    incidents: IncidentRepository, recovery_results: RecoveryResultRepository
) -> RecoveryOrchestrator:
    return RecoveryOrchestrator(incident_repository=incidents, recovery_result_repository=recovery_results)


def _result(
    incident_id: str = "incident-1",
    recovery_succeeded: bool = True,
    reinvestigation_required: bool = False,
) -> RecoveryResult:
    return RecoveryResult(
        incident_id=incident_id,
        response_id="response-1",
        containment_verified=recovery_succeeded,
        residual_threats=[] if recovery_succeeded else ["unexplained command still observed"],
        recovery_succeeded=recovery_succeeded,
        reinvestigation_required=reinvestigation_required,
    )


# --- routing -----------------------------------------------------------


def test_successful_recovery_with_no_reinvestigation_resolves_the_incident(orchestrator, incidents):
    result = _result(recovery_succeeded=True, reinvestigation_required=False)

    incident = orchestrator.process_result(result)

    assert incident.status == IncidentStatus.RESOLVED
    assert incidents.get("incident-1").status == IncidentStatus.RESOLVED


def test_failed_recovery_with_reinvestigation_required_reopens_the_incident(orchestrator, incidents):
    result = _result(recovery_succeeded=False, reinvestigation_required=True)

    incident = orchestrator.process_result(result)

    assert incident.status == IncidentStatus.REOPENED


def test_reinvestigation_required_reopens_even_if_recovery_succeeded_is_also_true(
    orchestrator, incidents
):
    # reinvestigation_required is checked first and wins regardless of
    # recovery_succeeded -- the conservative, safety-relevant signal.
    result = _result(recovery_succeeded=True, reinvestigation_required=True)

    incident = orchestrator.process_result(result)

    assert incident.status == IncidentStatus.REOPENED


def test_recovery_succeeded_false_and_reinvestigation_required_false_raises_and_does_not_mutate_status(
    orchestrator, incidents
):
    # Self-contradictory per the agent's own contract -- refuse to guess.
    result = _result(recovery_succeeded=False, reinvestigation_required=False)

    with pytest.raises(InconsistentRecoveryResultError, match="incident-1"):
        orchestrator.process_result(result)

    assert incidents.get("incident-1").status == IncidentStatus.DETECTED


# --- evidence recording --------------------------------------------------


def test_result_is_recorded_as_evidence_on_success(orchestrator, recovery_results):
    result = _result(recovery_succeeded=True, reinvestigation_required=False)

    orchestrator.process_result(result)

    recorded = recovery_results.list_for_incident("incident-1")
    assert len(recorded) == 1
    assert recorded[0] == result


def test_result_is_recorded_as_evidence_even_on_the_inconsistent_error_path(
    orchestrator, recovery_results
):
    result = _result(recovery_succeeded=False, reinvestigation_required=False)

    with pytest.raises(InconsistentRecoveryResultError):
        orchestrator.process_result(result)

    # The evidence is preserved even though the status transition was refused.
    recorded = recovery_results.list_for_incident("incident-1")
    assert len(recorded) == 1
    assert recorded[0] == result


def test_unknown_incident_id_raises_incident_not_found_and_records_no_evidence(
    orchestrator, recovery_results
):
    result = _result(incident_id="no-such-incident")

    with pytest.raises(IncidentNotFoundError):
        orchestrator.process_result(result)

    assert recovery_results.list_for_incident("no-such-incident") == []
