"""Default smart-hospital device fleet.

A single, named factory for the three primary devices (architecture spec Section
1) so tests, the ScenarioRunner, and later the API layer all build the same
baseline fleet instead of each hand-rolling slightly different device instances.
"""

from app.iomt_simulator.device import EcgMonitor, InfusionPump, Ventilator
from app.iomt_simulator.registry import DeviceRegistry
from app.schemas.enums import DeviceCriticality


def build_default_fleet() -> DeviceRegistry:
    """Three devices matching the brief's primary simulated device list, with
    clinical attributes chosen to be immediately useful for the two scenario
    tests in architecture spec Section 17:

    - infusion-pump-01: low criticality, no patient dependency (Scenario A target)
    - ventilator-01: high criticality, patient-dependent (Scenario B target)
    - ecg-monitor-01: medium criticality, patient-dependent (fleet realism; not a
      named scenario target yet)
    """
    registry = DeviceRegistry()

    registry.register(
        InfusionPump(
            device_id="infusion-pump-01",
            criticality=DeviceCriticality.LOW,
            patient_dependency=False,
        )
    )
    registry.register(
        Ventilator(
            device_id="ventilator-01",
            criticality=DeviceCriticality.HIGH,
            patient_dependency=True,
            synthetic_patient_id="synthetic-patient-001",
        )
    )
    registry.register(
        EcgMonitor(
            device_id="ecg-monitor-01",
            criticality=DeviceCriticality.MEDIUM,
            patient_dependency=True,
            synthetic_patient_id="synthetic-patient-002",
        )
    )

    return registry
