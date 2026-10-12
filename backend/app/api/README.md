# api

FastAPI routers, one module per resource (`devices`, `telemetry`, `events`, `incidents`,
`detections`, `risk_assessments`, `agents`, `responses`, `recovery`, `blockchain_audit`, `health`) —
matching Section 15's brief list exactly, plus `dependencies.py` (every shared `Depends()` function,
one per `app.state` singleton `app/core/app_factory.py` registers).

Every request/response body is a Pydantic schema from `app/schemas/` — including for the two
resources (`agents`' `AgentTrace`, `blockchain_audit`'s `OutboxEntry`) whose underlying repository
object is a plain dataclass, not already a Pydantic model; those routers define a small
`*Out` Pydantic view model and convert, rather than letting a dataclass cross the API boundary
directly (Section 15: "no raw dicts crossing the API boundary" — the same principle, extended).

## Status: Phase 9 complete — all 12 routers exist and are covered by API tests

- `devices` (Phase 2) and `detections` (Phase 3) predate this phase; `detections` gained a Phase 9
  addition (see below).
- `health` (Phase 1).
- `telemetry` / `events` (Phase 9, new): read-only GET over `app/repositories/telemetry_events.py`'s
  `TelemetryStore`/`NetworkEventStore`. No write endpoint — these are populated by
  `/detections/run-scenario`, never injected directly by an API client.
- `incidents` (Phase 9, new): list/get over `IncidentRepository`, plus `POST` — the first thing
  outside a test fixture that actually calls `IncidentRepository.create` for real, and enqueues the
  new incident's blockchain provenance.
- `detections` (Phase 9 addition): `/detections/run-scenario` now also records its scenario's
  telemetry/events into the shared stores and turns every `DetectionEvent` into a real `Incident` +
  blockchain outbox entry — Section 7 steps 2–3, genuinely wired, not just described.
- `risk_assessments` (Phase 9, new): stateless `POST` wrapper over `RuleBasedRiskModel.calculate_risk`
  (Phase 5). No persistence — `RiskScore` isn't one of Section 8's named stored aggregates.
- `agents` (Phase 9, new): **read-only** — lists `AgentTraceRecorder`'s traces (Section 16: "the Agent
  Activity panel reads directly from the agent-trace table"). Deliberately no run-an-agent endpoint:
  no real `LLMClient` backend exists yet (`app/agents/llm_client.py`'s own docstring calls this an
  open, deferred decision), so the five agents (`investigate`, `assess_threat`, etc.) stay callable
  only as plain Python functions, for whichever later phase wires a real backend and an orchestrator.
- `responses` (Phase 9, new): `/responses/proposed` wraps `PolicyEngine.evaluate` (Phase 6) and holds
  the resulting `PolicyDecision` in a new `ProposedResponseRepository`
  (`app/repositories/responses.py`) until it's acted on; `/responses/executed` wraps
  `ResponseOrchestrator.execute` (Phase 6/7) against that stored decision, handling the
  approval-required/rejected/mismatched-incident error cases as proper HTTP statuses (409/400/404/501)
  rather than swallowing them, and records the result in the new `ExecutedResponseRepository`.
- `recovery` (Phase 9, new): wraps `RecoveryOrchestrator.process_result` (Phase 7); 409 (not 500) for
  the self-contradictory `RecoveryResult` case, since the evidence is still recorded even then.
- `blockchain_audit` (Phase 9, new): read-only listing over `OutboxRepository` (Section 16's
  "Blockchain Audit" section — `chain_tx_id IS NULL` stays visible as pending, never hidden), plus a
  manual `POST .../process` that drains pending entries once via `OutboxWorker.process_once()`. Not a
  background loop — `app_factory.py` deliberately doesn't start one; see its own docstring.

New in Phase 9, used across several of the routers above: `app/blockchain/hashing.py`
(`hash_payload` — real SHA-256 over whatever evidence is being committed; every hash crossing into a
`*Provenance` schema before Phase 9 was a literal placeholder string in a test, never computed from a
real object).

## Phase 10 addition: one real incident through all of this, end to end

`backend/tests/test_lifecycle_integration.py` drives one real incident through
every router above in sequence over the real HTTP API — detection, the five
agents (called directly, not through a router; see that test's own docstring
for why and for its disclosed use of `MockLLMClient`), risk assessment, policy
decision, response execution, recovery, and blockchain audit draining — and
asserts the incident actually reaches `resolved` with a fully confirmed audit
trail. This doesn't change anything documented above (still no run-an-agent
endpoint, still no orchestrator); it's the test that proves the routers above
actually chain together correctly for one incident, which no single router's
own test suite can show on its own. The Phase 10 SOC dashboard
(`frontend/src/routes/IncidentDetail.tsx`) is built to render exactly this
sequence's data, panel by panel.

## What's still explicitly NOT here

Authentication/authorization (designed-for, not implemented — Section 15 names this Phase 9 too, but
the phase's actual gate, Section 19, is "all resource routers exist and are covered by API tests," not
auth; adding a real auth layer un-asked would be scope invention, not integration). No Postgres swap —
every repository behind these routers is still in-memory (`app/repositories/*.py`,
`app/blockchain/outbox.py`); Section 8 names Postgres/TimescaleDB as the eventual store, but no phase
gate through Phase 9 requires that migration yet. No automatic agent orchestration or background
outbox-draining loop — both remain the explicitly deferred decisions named in `app/agents/README.md`
and `app/blockchain/README.md` respectively.
