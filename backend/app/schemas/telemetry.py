"""L1/L2 — Telemetry reading schema.

One schema shape across all device types rather than a schema per device: the
telemetry collector (L2) and storage layer treat a reading generically (device_id,
timestamp, named numeric fields), and only the device-specific *generation* logic
in `iomt_simulator/telemetry.py` needs to know that a ventilator's readings are
different from an infusion pump's.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class TelemetryReading(BaseModel):
    device_id: str
    timestamp: datetime
    readings: dict[str, float] = Field(
        description="Named numeric readings, e.g. {'heart_rate_bpm': 72.4, 'spo2_percent': 97.8} "
        "for an ECG monitor, or {'flow_rate_ml_per_hr': 100.2} for an infusion pump. Field names "
        "are device-type-specific; consumers key off device_type from the device registry, not "
        "off this schema, to know which fields to expect."
    )
