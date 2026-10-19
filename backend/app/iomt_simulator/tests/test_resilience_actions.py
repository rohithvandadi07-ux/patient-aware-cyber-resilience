import pytest

from app.iomt_simulator.device import ActionPreconditionError, Ventilator
from app.response_engine.orchestrator import _apply_action
from app.schemas.device import OperationalState
from app.schemas.enums import DeviceCriticality, ResponseActionCategory as A


def _vent(**kw):
    base = dict(
        device_id="vent-1",
        criticality=DeviceCriticality.HIGH,
        patient_dependency=True,
        active_sessions=["s1", "s2"],
        backup_available=True,
        standby_unit_id="vent-1-standby",
    )
    return Ventilator(**{**base, **kw})


def test_revoke_sessions_clears_them_and_reports_how_many():
    d = _vent()
    assert d.revoke_sessions() == 2
    assert d.active_sessions == []


def test_revoke_with_no_sessions_is_refused_not_faked():
    with pytest.raises(ActionPreconditionError, match="no active sessions"):
        _vent(active_sessions=[]).revoke_sessions()


def test_rotating_credentials_bumps_the_version_and_ends_old_sessions():
    d = _vent()
    assert d.rotate_credentials() == 2
    assert d.credential_version == 2 and d.active_sessions == []


def test_activate_backup_once_then_refuses():
    d = _vent()
    d.activate_backup()
    assert d.backup_active is True
    with pytest.raises(ActionPreconditionError, match="already active"):
        d.activate_backup()


def test_activate_backup_without_one_is_refused():
    with pytest.raises(ActionPreconditionError, match="no backup"):
        _vent(backup_available=False).activate_backup()


def test_failover_moves_service_and_takes_the_unit_out_of_the_clinical_path():
    d = _vent()
    assert d.fail_over() == "vent-1-standby"
    assert d.serving_unit == "vent-1-standby"
    assert d.operational_state == OperationalState.ISOLATED and d.network_state == "isolated"


def test_failover_needs_a_standby_and_only_happens_once():
    with pytest.raises(ActionPreconditionError, match="no standby"):
        _vent(standby_unit_id=None).fail_over()
    d = _vent()
    d.fail_over()
    with pytest.raises(ActionPreconditionError, match="already failed over"):
        d.fail_over()


def test_snapshot_exposes_the_modelled_state():
    d = _vent()
    d.rotate_credentials()
    snap = d.snapshot()
    assert snap.credential_version == 2 and snap.backup_available and snap.standby_unit_id == "vent-1-standby"


@pytest.mark.parametrize(
    "action, check",
    [
        (A.REVOKE_SESSION, lambda d: d.active_sessions == []),
        (A.ROTATE_CREDENTIALS, lambda d: d.credential_version == 2),
        (A.ACTIVATE_BACKUP, lambda d: d.backup_active),
        (A.FAILOVER, lambda d: d.serving_unit == "vent-1-standby"),
    ],
)
def test_the_orchestrator_executes_all_four_resilience_actions(action, check):
    d = _vent()
    _apply_action(d, action)
    assert check(d)
