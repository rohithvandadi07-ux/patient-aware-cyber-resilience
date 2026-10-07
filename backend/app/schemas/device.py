"""L1 — Device registry schema.

This is the single source-of-truth shape for "what is this device, and is it
currently patient-dependent." The Healthcare Context Agent and the simulator both
read through this schema via the shared `get_device_state` tool (architecture spec
Section 9), rather than each holding their own copy of device/clinical context.
"""

from enum import StrEnum

from pydantic import BaseModel, Field

from app.schemas.enums import DeviceCriticality


class DeviceType(StrEnum):
    INFUSION_PUMP = "infusion_pump"
    VENTILATOR = "ventilator"
    ECG_MONITOR = "ecg_monitor"


class OperationalState(StrEnum):
    IDLE = "idle"
    ACTIVE = "active"
    ALARM = "alarm"
    ISOLATED = "isolated"


class DeviceState(BaseModel):
    device_id: str
    device_type: DeviceType
    criticality: DeviceCriticality
    patient_dependency: bool = Field(
        description="True if a synthetic patient currently depends on this device. Drives the "
        "Policy Engine's 'never autonomously shut down a patient-dependent, high-criticality "
        "device' rule."
    )
    synthetic_patient_id: str | None = Field(
        default=None,
        description="Synthetic identifier only — never real patient data (brief Section 5).",
    )
    operational_state: OperationalState
    network_state: str = Field(description="e.g. 'connected', 'isolated', 'degraded'.")
