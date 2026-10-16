# repositories

Database access layer, one repository per aggregate (devices, incidents, agent
traces, approvals, blockchain outbox, etc.). Services call repositories; routers
never touch the database directly.

Status: in-memory implementations exist for what Phase 4's agent layer needed
(`incidents.py`, `agent_traces.py`, `telemetry_events.py`, `log_capture.py`),
Phase 7 added (`recovery_results.py`), and Phase 9 added (`responses.py` —
`ProposedResponseRepository` + `ExecutedResponseRepository`, the two new
stores the `/responses/proposed` and `/responses/executed` API routers need
to hold a `PolicyDecision`/`ExecutedResponse` across a request boundary).

**Post-Phase-15 update:** `incidents.py`, `agent_traces.py`,
`recovery_results.py`, and `responses.py` each now also define a real,
Postgres-backed `Postgres*` class alongside their original in-memory one —
same public methods, same return types, backed by a real table
(`app/models/orm.py`) via a sync SQLAlchemy session (`app/core/db.py`)
instead of a dict/list. `Settings.repository_backend` ("memory" by default,
"postgres" to use the real tables — see `app/core/config.py`) picks which
one `app/core/app_factory.py`'s `_register_state` actually constructs.
`log_capture.py` was never named in Section 8 as persisted storage and stays
in-memory only.

**Final-completion update:** `telemetry_events.py` now also defines
`PostgresNetworkEventStore` and `PostgresTelemetryStore` (record / record_many /
query by device and time range / clear), backed by the `network_events` and
`telemetry_readings` tables. When the TimescaleDB extension is installed,
`app/core/db.py`'s `create_hypertables` converts them to hypertables; otherwise
they remain plain tables, and the outcome is exposed as
`app.state.hypertable_status`. The hypertable branch has not been run against a
real TimescaleDB server here, and no retention/compression policy is set. The
in-memory stores gained the same `query(device_id, since, until)` method so both
backends share one interface. See `app/models/orm.py`'s module docstring for the
full scope disclosure, and `docs/postgres-migration.md` for the earlier
verification numbers.

`app/iomt_simulator/registry.py`'s `DeviceRegistry` (Phase 2) still follows
the original in-memory-only pattern and predates this directory — it is
live simulation state, not a persisted catalog, so it is out of scope for
the Postgres migration too (same docstring, same reasoning).
