from app.iomt_simulator.device import EcgMonitor, InfusionPump, Ventilator
from app.schemas.device import OperationalState


def test_ventilator_snapshot_matches_constructor_args():
    vent = Ventilator(
        device_id="vent-01",
        criticality="high",
        patient_dependency=True,
        synthetic_patient_id="pt-001",
    )
    snapshot = vent.snapshot()
    assert snapshot.device_id == "vent-01"
    assert snapshot.device_type == "ventilator"
    assert snapshot.criticality == "high"
    assert snapshot.patient_dependency is True
    assert snapshot.synthetic_patient_id == "pt-001"
    assert snapshot.operational_state == OperationalState.IDLE


def test_isolate_cuts_network_and_operational_state():
    pump = InfusionPump(device_id="pump-01", criticality="low", patient_dependency=False)
    assert pump.network_state == "connected"

    pump.isolate()

    assert pump.network_state == "isolated"
    assert pump.operational_state == OperationalState.ISOLATED


def test_state_history_records_transitions():
    ecg = EcgMonitor(device_id="ecg-01", criticality="medium", patient_dependency=False)
    assert ecg._state_history == []

    ecg.set_operational_state(OperationalState.ACTIVE)
    ecg.set_network_state("degraded")

    assert len(ecg._state_history) == 2
    assert ecg.operational_state == OperationalState.ACTIVE
    assert ecg.network_state == "degraded"
