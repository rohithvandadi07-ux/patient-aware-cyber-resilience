"""In-memory stores for network events and telemetry readings, queryable by
device_id.

Architecture spec Section 8: telemetry and network/security events belong in
TimescaleDB hypertables at full scale -- that's Phase 9's concern. Right now,
`ScenarioRunner.run()` (Phase 2) returns a `ScenarioResult` that nothing keeps:
each call's events/telemetry live only in that call's return value and vanish
once it's out of scope. For the Investigation Agent's `get_network_events` and
`get_telemetry` tools (Section 11) to return real evidence rather than
fabricated readings, something has to actually persist what a scenario run
produced -- these two stores are that, in-memory, until Phase 9 swaps them for
TimescaleDB-backed repositories with the same query shape.
"""

from app.schemas.events import NetworkEvent
from app.schemas.telemetry import TelemetryReading


class NetworkEventStore:
    def __init__(self) -> None:
        self._events: list[NetworkEvent] = []

    def record_many(self, events: list[NetworkEvent]) -> None:
        self._events.extend(events)

    def query(self, device_id: str | None = None) -> list[NetworkEvent]:
        if device_id is None:
            return list(self._events)
        return [e for e in self._events if e.device_id == device_id]

    def clear(self) -> None:
        self._events.clear()


class TelemetryStore:
    def __init__(self) -> None:
        self._readings: list[TelemetryReading] = []

    def record_many(self, readings: list[TelemetryReading]) -> None:
        self._readings.extend(readings)

    def query(self, device_id: str | None = None) -> list[TelemetryReading]:
        if device_id is None:
            return list(self._readings)
        return [r for r in self._readings if r.device_id == device_id]

    def clear(self) -> None:
        self._readings.clear()
