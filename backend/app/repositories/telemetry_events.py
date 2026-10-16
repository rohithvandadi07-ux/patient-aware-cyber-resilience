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

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.db import session_scope
from app.models.orm import NetworkEventORM, TelemetryReadingORM
from app.schemas.events import NetworkEvent
from app.schemas.telemetry import TelemetryReading


class NetworkEventStore:
    def __init__(self) -> None:
        self._events: list[NetworkEvent] = []

    def record_many(self, events: list[NetworkEvent]) -> None:
        self._events.extend(events)

    def query(
        self, device_id: str | None = None, since: datetime | None = None, until: datetime | None = None
    ) -> list[NetworkEvent]:
        """Events for one device (or all), optionally within [since, until]."""
        return [
            e
            for e in self._events
            if (device_id is None or e.device_id == device_id)
            and (since is None or e.timestamp >= since)
            and (until is None or e.timestamp <= until)
        ]

    def clear(self) -> None:
        self._events.clear()


class TelemetryStore:
    def __init__(self) -> None:
        self._readings: list[TelemetryReading] = []

    def record_many(self, readings: list[TelemetryReading]) -> None:
        self._readings.extend(readings)

    def query(
        self, device_id: str | None = None, since: datetime | None = None, until: datetime | None = None
    ) -> list[TelemetryReading]:
        """Readings for one device (or all), optionally within [since, until]."""
        return [
            r
            for r in self._readings
            if (device_id is None or r.device_id == device_id)
            and (since is None or r.timestamp >= since)
            and (until is None or r.timestamp <= until)
        ]

    def clear(self) -> None:
        self._readings.clear()


class PostgresNetworkEventStore:
    """`NetworkEventStore` backed by the `network_events` table (a TimescaleDB
    hypertable when the extension is available -- `app.core.db.create_hypertables`).
    Same methods and ordering as the in-memory store: results come back in
    insertion order."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record_many(self, events: list[NetworkEvent]) -> None:
        with session_scope(self._session_factory) as session:
            session.add_all(
                NetworkEventORM(
                    device_id=e.device_id,
                    timestamp=e.timestamp,
                    event_type=e.event_type,
                    source=e.source,
                    payload=dict(e.payload),
                    is_attack_injection=e.is_attack_injection,
                )
                for e in events
            )

    def query(
        self, device_id: str | None = None, since: datetime | None = None, until: datetime | None = None
    ) -> list[NetworkEvent]:
        stmt = select(NetworkEventORM).order_by(NetworkEventORM.id)
        if device_id is not None:
            stmt = stmt.where(NetworkEventORM.device_id == device_id)
        if since is not None:
            stmt = stmt.where(NetworkEventORM.timestamp >= since)
        if until is not None:
            stmt = stmt.where(NetworkEventORM.timestamp <= until)
        with session_scope(self._session_factory) as session:
            return [
                NetworkEvent(
                    device_id=r.device_id,
                    timestamp=r.timestamp,
                    event_type=r.event_type,
                    source=r.source,
                    payload=r.payload,
                    is_attack_injection=r.is_attack_injection,
                )
                for r in session.scalars(stmt)
            ]

    def clear(self) -> None:
        with session_scope(self._session_factory) as session:
            session.execute(delete(NetworkEventORM))


class PostgresTelemetryStore:
    """`TelemetryStore` backed by the `telemetry_readings` table (hypertable
    when available)."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record_many(self, readings: list[TelemetryReading]) -> None:
        with session_scope(self._session_factory) as session:
            session.add_all(
                TelemetryReadingORM(
                    device_id=r.device_id, timestamp=r.timestamp, readings=dict(r.readings)
                )
                for r in readings
            )

    def query(
        self, device_id: str | None = None, since: datetime | None = None, until: datetime | None = None
    ) -> list[TelemetryReading]:
        stmt = select(TelemetryReadingORM).order_by(TelemetryReadingORM.id)
        if device_id is not None:
            stmt = stmt.where(TelemetryReadingORM.device_id == device_id)
        if since is not None:
            stmt = stmt.where(TelemetryReadingORM.timestamp >= since)
        if until is not None:
            stmt = stmt.where(TelemetryReadingORM.timestamp <= until)
        with session_scope(self._session_factory) as session:
            return [
                TelemetryReading(device_id=r.device_id, timestamp=r.timestamp, readings=r.readings)
                for r in session.scalars(stmt)
            ]

    def clear(self) -> None:
        with session_scope(self._session_factory) as session:
            session.execute(delete(TelemetryReadingORM))
