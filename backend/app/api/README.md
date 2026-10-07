# api

FastAPI routers, one module per resource (`devices`, `telemetry`, `events`, `incidents`,
`detections`, `risk_assessments`, `agents`, `responses`, `recovery`, `blockchain_audit`, `health`).

Routers call into the service layer only — never the database or a repository directly.
Every request/response body is a Pydantic schema from `app/schemas/`.

Status: scaffolded (Phase 1). Only `health` is implemented; the rest are added as their
owning layer (detection engine, agents, risk engine, etc.) is built in later phases.
