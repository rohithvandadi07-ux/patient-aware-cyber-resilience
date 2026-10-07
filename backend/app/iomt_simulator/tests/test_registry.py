import pytest

from app.iomt_simulator.device import InfusionPump
from app.iomt_simulator.hospital import build_default_fleet
from app.iomt_simulator.registry import DeviceNotFoundError, DeviceRegistry


def test_register_and_get_device_state():
    registry = DeviceRegistry()
    registry.register(InfusionPump(device_id="pump-01", criticality="low", patient_dependency=False))

    state = registry.get_device_state("pump-01")
    assert state.device_id == "pump-01"
    assert state.device_type == "infusion_pump"


def test_registering_duplicate_device_id_raises():
    registry = DeviceRegistry()
    registry.register(InfusionPump(device_id="pump-01", criticality="low", patient_dependency=False))

    with pytest.raises(ValueError, match="already registered"):
        registry.register(InfusionPump(device_id="pump-01", criticality="low", patient_dependency=False))


def test_unknown_device_raises_device_not_found():
    registry = DeviceRegistry()
    with pytest.raises(DeviceNotFoundError):
        registry.get_device_state("does-not-exist")


def test_default_fleet_has_three_devices_with_expected_clinical_attributes():
    registry = build_default_fleet()
    assert len(registry) == 3

    ventilator = registry.get_device_state("ventilator-01")
    assert ventilator.criticality == "high"
    assert ventilator.patient_dependency is True

    pump = registry.get_device_state("infusion-pump-01")
    assert pump.criticality == "low"
    assert pump.patient_dependency is False
