# core

Cross-cutting foundation: settings management (environment-variable driven, never
hardcoded), structured logging configuration, and the FastAPI application factory.

Everything in this package is infrastructure, not domain logic. No cybersecurity,
agent, risk, or policy code belongs here.

Status: `config.py`/`logging.py` implemented Phase 1; `app_factory.py` grew in
every phase since as each new resource router/service needed wiring. Phase 9
is the largest single addition: `_register_state` now seeds every Phase 4-8
in-memory repository/store as an `app.state` singleton (not just the Phase 2
device registry), plus a `FabricClient` (mock or subprocess, per
`Settings.fabric_client_mode` — see `config.py`'s Phase 9 addition) and an
`OutboxWorker`; `_register_routers` registers all 12 of Section 15's
resource routers. See `app/api/README.md` for what each router actually does.

Phase 10 addition: `_register_middleware` wires `CORSMiddleware` with an
explicit origin allowlist from `Settings.cors_allowed_origins` (default
`["http://localhost:5173", "http://127.0.0.1:5173"]`, the Vite dev server —
never a wildcard; credentials are not allowed cross-origin since this API
has no cookie-based auth to carry). The SOC dashboard (`frontend/`) runs on
its own origin, so this is required for the browser to let it call this API
at all, not an optional hardening step — see `tests/test_cors.py`.
`cors_allowed_origins` accepts either a JSON array or a comma-separated
string from the environment (`CORS_ALLOWED_ORIGINS`).

**Post-Phase-15 addition: `db.py`.** Sync SQLAlchemy engine/session
plumbing (`Base`, `build_engine`, `build_session_factory`,
`create_all_tables`, `session_scope`) for the real Postgres-backed
repositories added after Phase 15 (`app/repositories/*.py`'s `Postgres*`
classes, `app/models/orm.py`). `_register_state` now branches on the new
`Settings.repository_backend` ("memory" default, "postgres" to build a
real engine via `db.py`, create tables, and construct every `Postgres*`
repository instead of its in-memory counterpart) — see `db.py`'s own
docstring for why this uses a sync driver (`psycopg`) rather than the
`asyncpg` already declared in `requirements.txt` since Phase 1, and why
there's no Alembic migration tool yet.

**Final-completion additions.**

- `limits.py` — pure-ASGI `BodySizeLimitMiddleware` (413 when a request body
  exceeds `MAX_REQUEST_BODY_BYTES`) and `RateLimitMiddleware` (fixed window,
  429 with `Retry-After`, keyed by hashed `X-API-Key` else peer IP; `/health`
  exempt; `RATE_LIMIT_PER_MINUTE`). Both are off by default. The limiter keeps
  its counters in process memory, so it is per-worker, not distributed.
- `timing.py` — `StageTimings`, used by the orchestrator to report per-stage
  milliseconds (`CycleResult.stage_timings_ms`).
- `db.py` gained `create_hypertables(engine)`, which converts the two
  time-series tables to TimescaleDB hypertables when the extension exists and
  returns what happened per table; `_register_state` stores it as
  `app.state.hypertable_status`.
