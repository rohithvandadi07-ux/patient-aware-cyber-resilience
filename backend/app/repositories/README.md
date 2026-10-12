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
Real persistence (PostgreSQL/TimescaleDB per the architecture spec's Section
8) is still not built — Phase 9's actual gate (Section 19) is "all resource
routers exist and are covered by API tests," not a database migration, so
every repository here remains in-memory on purpose, not by oversight. Each
in-memory repository's public method signatures are already shaped like
their eventual repository equivalents, so swapping the backing store later
should be a constructor change for callers, not an API rewrite.
`app/iomt_simulator/registry.py`'s `DeviceRegistry` (Phase 2) follows the
same pattern and predates this directory.
