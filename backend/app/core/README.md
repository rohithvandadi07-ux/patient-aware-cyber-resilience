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
