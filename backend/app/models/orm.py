"""SQLAlchemy ORM models backing the Postgres repository implementations
(`Settings.repository_backend == "postgres"`).

**Scope, read before adding a table here.** Architecture spec Section 8
names several storage categories; this module covers the plain relational
tables, plus the two time-series tables (see "Time-series tables" below):

- Incidents (`incidents` -- Section 8's "Device registry, incidents,
  approvals, users | PostgreSQL" row, the incidents half of it).
- Agent traces (`agent_traces` -- Section 8's "needed for independent agent
  testing ... and for the dashboard's Agent Activity view" row).
- The two L6/L7 response-lifecycle tables Phase 9 introduced
  (`proposed_responses`, `executed_responses`).
- Recovery results (`recovery_results`), Phase 7's addition.
- The blockchain outbox (`outbox_entries` -- Section 8's "Blockchain outbox
  + confirmed transaction IDs | PostgreSQL table, polled by a worker" row).

**Time-series tables** (`network_events`, `telemetry_readings`; backed by
`PostgresNetworkEventStore`/`PostgresTelemetryStore` in `app/repositories/
telemetry_events.py`) -- Section 8's TimescaleDB-hypertable row. They are
ordinary tables with a composite `(id, timestamp)` primary key and a
`(device_id, timestamp)` index. When the TimescaleDB extension is present,
`create_hypertables` (`app/core/db.py`) converts them to hypertables on
`timestamp`; otherwise they stay plain tables and the reason is logged and
exposed as `app.state.hypertable_status`. The hypertable branch has NOT been
exercised against a real TimescaleDB server in this repo's test runs (only
plain PostgreSQL is available to CI), and no retention or compression policy
is configured -- those remain deployment decisions.

**What this deliberately does NOT cover, and why:**

- **The IoMT simulator's `DeviceRegistry`** (`app/iomt_simulator/
  registry.py`). This is live, in-process simulation state (each
  device's current operational state, mutated by `ScenarioRunner` as a
  scenario plays out) -- not a persisted catalog a server restart should
  survive. Section 8's "Device registry ... PostgreSQL" row was written
  with FK integrity in mind ("foreign keys enforce that an incident always
  references a real device"), which is a different thing than persisting
  a simulator's runtime state; conflating the two would misrepresent what
  either one actually is. `incident.device_id` stays a plain string column
  here, not a foreign key, because there is no real `devices` table to key
  against yet -- a disclosed, narrower version of Section 8's original
  intent, not the full thing silently declared done.
- **A real migration tool (Alembic).** See `app/core/db.py`'s own
  docstring for why `create_all` is adequate for now and isn't presented as
  more than that.
- **Async drivers / a full async rewrite of every call site.** See
  `app/core/db.py`'s docstring for the sync-driver tradeoff this pass
  deliberately chose instead, and why.

Every table uses a plain `String` primary/foreign key (matching the schemas'
own `str` id fields) rather than inventing a surrogate integer id the rest
of the codebase doesn't use, except where the in-memory store was already
list-shaped (`agent_traces`, `recovery_results`, `executed_responses`,
`outbox_entries` all allow more than one row per `incident_id`, exactly
like their in-memory equivalents) -- there, an autoincrementing `id` is the
real primary key and `incident_id` is an indexed, non-unique column.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class IncidentORM(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    device_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    chain_tx_id: Mapped[str | None] = mapped_column(String, nullable=True, default=None)


class AgentTraceORM(Base):
    __tablename__ = "agent_traces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    agent_name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    input_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    output_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    error: Mapped[str | None] = mapped_column(String, nullable=True)


class RecoveryResultORM(Base):
    __tablename__ = "recovery_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    response_id: Mapped[str] = mapped_column(String, nullable=False)
    containment_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    residual_threats: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recovery_succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reinvestigation_required: Mapped[bool] = mapped_column(Boolean, nullable=False)


class ProposedResponseORM(Base):
    """One row per incident -- `ProposedResponseRepository.put()` replaces
    rather than accumulates, so a `put()` on an existing `incident_id` is a
    real SQL `UPDATE`, mirrored by the repository implementation below, not
    an insert that would violate this primary key."""

    __tablename__ = "proposed_responses"

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    chosen_action: Mapped[str] = mapped_column(String, nullable=False)
    requires_human_approval: Mapped[bool] = mapped_column(Boolean, nullable=False)
    policy_rule_id: Mapped[str] = mapped_column(String, nullable=False)
    rationale: Mapped[str] = mapped_column(String, nullable=False)
    # Added after the table first shipped: `create_all` does not alter an existing
    # table, so a database created before this column needs
    #   ALTER TABLE proposed_responses ADD COLUMN alternatives JSON;
    # (nullable, so old rows read back as "no alternatives").
    alternatives: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True, default=None)


class ExecutedResponseORM(Base):
    __tablename__ = "executed_responses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    action_taken: Mapped[str] = mapped_column(String, nullable=False)
    executed_by: Mapped[str] = mapped_column(String, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    chain_tx_id: Mapped[str | None] = mapped_column(String, nullable=True, default=None)


class OutboxEntryORM(Base):
    __tablename__ = "outbox_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_type: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    chain_tx_id: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NetworkEventORM(Base):
    """One row per `NetworkEvent`. Time-series: when the TimescaleDB extension
    is available, `create_hypertables` (app/core/db.py) converts this table to
    a hypertable partitioned on `timestamp`. A hypertable's unique indexes must
    include the partitioning column, hence the composite primary key."""

    __tablename__ = "network_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    device_id: Mapped[str] = mapped_column(String, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    is_attack_injection: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (Index("ix_network_events_device_ts", "device_id", "timestamp"),)


class TelemetryReadingORM(Base):
    """One row per `TelemetryReading`; same hypertable treatment as above.
    `readings` stays a JSON object because its field names are
    device-type-specific (see `app/schemas/telemetry.py`)."""

    __tablename__ = "telemetry_readings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    device_id: Mapped[str] = mapped_column(String, nullable=False)
    readings: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False)

    __table_args__ = (Index("ix_telemetry_readings_device_ts", "device_id", "timestamp"),)
