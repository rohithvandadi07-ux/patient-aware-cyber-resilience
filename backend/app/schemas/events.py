"""L1/L2 — Network and security event schemas.

Distinct from `TelemetryReading` (which carries device vitals/mechanical
readings): these carry what happened on the network or at the device's command
interface — the raw material the detection engine (L3) scores, and what the
Investigation Agent's `get_network_events` tool (L4, Phase 4) will read.

`NetworkEvent` is deliberately generic (not one schema per attack type) so the
ScenarioRunner can emit a wide variety of scripted scenarios without a schema
change each time; `event_type` and `payload` carry the specifics.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class NetworkEvent(BaseModel):
    device_id: str
    timestamp: datetime
    event_type: str = Field(
        description="e.g. 'command_received', 'connection_attempt', 'auth_failure', "
        "'spoofed_command' — free-form but consistent within the simulator/detection pair "
        "that reads it."
    )
    source: str = Field(
        description="Origin of the event, e.g. a synthetic IP, 'scenario_runner', or a device ID."
    )
    payload: dict[str, str] = Field(
        default_factory=dict,
        description="Event-type-specific details, e.g. {'command': 'set_tidal_volume', 'value': '50'} "
        "for a spoofed command injection.",
    )
    is_attack_injection: bool = Field(
        default=False,
        description="True only for events deliberately injected by the ScenarioRunner for a "
        "controlled test/experiment — lets tests and the detection-evaluation pipeline "
        "distinguish ground truth from what the detector actually flags.",
    )
