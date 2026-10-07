# repositories

Database access layer, one repository per aggregate (devices, incidents, agent
traces, approvals, blockchain outbox, etc.). Services call repositories; routers
never touch the database directly.

Status: in-memory implementations exist for what Phase 4's agent layer needs
(`incidents.py`, `agent_traces.py`, `telemetry_events.py`, `log_capture.py`) —
real persistence (PostgreSQL/TimescaleDB per the architecture spec's Section
8) is Phase 9 work. Each in-memory repository's public method signatures are
already shaped like their eventual repository equivalents, so swapping the
backing store later should be a constructor change for callers, not an API
rewrite. `app/iomt_simulator/registry.py`'s `DeviceRegistry` (Phase 2) follows
the same pattern and predates this directory.
