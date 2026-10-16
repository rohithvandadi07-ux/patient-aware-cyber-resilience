# models

New post-Phase-15 package. SQLAlchemy ORM models (`orm.py`) backing the
real Postgres repository implementations (`Settings.repository_backend ==
"postgres"`, see `app/core/config.py` and `app/core/db.py`). Everything
else in this codebase's `app/schemas/*.py` is a Pydantic model — the API's
request/response shape and the in-memory repositories' storage shape — and
stays exactly that; `orm.py`'s `Mapped`/`mapped_column` classes exist only
to give the `Postgres*` repository classes (`app/repositories/*.py`,
`app/blockchain/outbox.py`) something real to read and write, and are
never returned directly from an API route or imported outside this
migration's own repository code.

## Scope

Eight tables (six relational plus the two time-series ones below), matching the repositories that got a real Postgres
implementation in this migration:

- `incidents` — `IncidentORM`
- `agent_traces` — `AgentTraceORM`
- `recovery_results` — `RecoveryResultORM`
- `proposed_responses` — `ProposedResponseORM`
- `executed_responses` — `ExecutedResponseORM`
- `outbox_entries` — `OutboxEntryORM`

`orm.py`'s own module docstring has the full disclosure (quoted in brief
here, read it there for the real detail): the IoMT simulator's
`DeviceRegistry` (live simulation state, not a persisted catalog) is
deliberately NOT covered, not an oversight. The two time-series tables
`network_events` (`NetworkEventORM`) and `telemetry_readings`
(`TelemetryReadingORM`) are covered; they become TimescaleDB hypertables when
the extension is present (unverified against a real TimescaleDB server).
`proposed_responses` also gained a nullable `alternatives` JSON column; a
database created earlier needs `ALTER TABLE proposed_responses ADD COLUMN
alternatives JSON;`. There is also no Alembic migration here — `app/core/db.py`'s
`create_all_tables` is additive-only `CREATE TABLE IF NOT EXISTS`, adequate
while this project controls the schema completely and has no production
data in it.

## Why this exists as a separate package from `app/schemas/`

The Pydantic schemas in `app/schemas/*.py` define the shapes every API
route, agent, and in-memory repository already agreed on since Phase 1 —
changing them to also be SQLAlchemy models would entangle two different
concerns (wire/validation shape vs. table shape) that have different
constraints (e.g. `RiskScore.response_impact`'s `dict[str, ImpactLevel]`
has no obvious single-column SQL representation, nor does every schema
need a surrogate key). Keeping them separate means each `Postgres*`
repository method does one explicit conversion at its boundary (a
`_x_from_row()` helper, same pattern in every file) rather than asking one
class to serve two different jobs implicitly.
