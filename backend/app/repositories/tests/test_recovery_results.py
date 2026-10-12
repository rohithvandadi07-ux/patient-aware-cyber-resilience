from app.repositories.recovery_results import RecoveryResultRepository
from app.schemas.agents import RecoveryResult


def _result(incident_id: str, recovery_succeeded: bool = True) -> RecoveryResult:
    return RecoveryResult(
        incident_id=incident_id,
        response_id="response-1",
        containment_verified=recovery_succeeded,
        residual_threats=[] if recovery_succeeded else ["unexplained command still observed"],
        recovery_succeeded=recovery_succeeded,
        reinvestigation_required=not recovery_succeeded,
    )


def test_list_for_incident_returns_empty_list_when_nothing_recorded():
    repo = RecoveryResultRepository()
    assert repo.list_for_incident("incident-1") == []


def test_record_and_list_for_incident_filters_by_incident_id():
    repo = RecoveryResultRepository()
    repo.record(_result("incident-1"))
    repo.record(_result("incident-2"))

    results = repo.list_for_incident("incident-1")

    assert len(results) == 1
    assert results[0].incident_id == "incident-1"


def test_list_for_incident_returns_every_check_in_recorded_order():
    # An incident can be checked more than once across a reopen loop.
    repo = RecoveryResultRepository()
    repo.record(_result("incident-1", recovery_succeeded=False))
    repo.record(_result("incident-1", recovery_succeeded=True))

    results = repo.list_for_incident("incident-1")

    assert len(results) == 2
    assert results[0].recovery_succeeded is False
    assert results[1].recovery_succeeded is True


def test_list_all_returns_every_result_across_every_incident_in_recorded_order():
    repo = RecoveryResultRepository()
    repo.record(_result("incident-1", recovery_succeeded=False))
    repo.record(_result("incident-2", recovery_succeeded=True))

    results = repo.list_all()

    assert [r.incident_id for r in results] == ["incident-1", "incident-2"]


def test_clear_empties_the_store():
    repo = RecoveryResultRepository()
    repo.record(_result("incident-1"))

    repo.clear()

    assert repo.list_for_incident("incident-1") == []
