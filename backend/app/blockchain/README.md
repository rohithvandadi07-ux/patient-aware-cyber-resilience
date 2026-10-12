# blockchain

L9 of the architecture. The Fabric client and the asynchronous outbox worker that
commit the six provenance event types (`recordIncident`, `recordDecision`,
`recordApproval`, `recordResponse`, `recordRecovery`, `verifyEvidence`) to the
Hyperledger Fabric network in `../../../blockchain/network/`. Never sits on the
response-execution hot path — writes are queued and confirmed asynchronously.

## Status

Implemented, unit-tested (34 tests as of Phase 8, more added in Phase 9 —
see below — no live network needed), and — see
`../../../blockchain/README.md` for the Phase 8 integration test — proven
against the real network and real chaincode in `blockchain/network/` and
`blockchain/chaincode/`.

Phase 9 addition: `hashing.py`'s `hash_payload` is the first real computation
of the hash strings every `*Provenance` schema (`app/schemas/blockchain.py`)
and `FabricClient` method expects (`evidence_hash`, `risk_score_hash`,
`residual_threats_hash`) — before this phase, every caller (including this
package's own tests) passed a literal placeholder string. The `/incidents`,
`/responses/proposed`, `/responses/executed`, and `/recovery` API routers
(`app/api/`) are the first real callers of `outbox.py`'s `enqueue_*`
helpers outside a test — that module's own docstring named "the response
orchestrator, recovery orchestrator, policy engine, approval endpoint" as
the intended callers, and Phase 9 is what actually wires them in. Also new:
`OutboxRepository.list_all()`, for `/blockchain/audit`'s unfiltered listing.

`app/core/app_factory.py` registers an `OutboxWorker` on `app.state`
(backed by `MockFabricClient` by default, or a real `SubprocessFabricClient`
when `Settings.fabric_client_mode="subprocess"` and the native-Fabric
network is actually running) but does **not** start `run_forever()` as a
background task — draining stays a manual `POST /blockchain/audit/process`
call. Running the drain loop unattended for the life of the process is a
deployment/lifespan concern Phase 9's own gate (Section 19: "all resource
routers exist and are covered by API tests") does not require.

## Layout

- `fabric_client.py` — the `FabricClient` `Protocol` (one async method per
  chaincode write operation, plus `verify_evidence`), `FabricTxResult`, the
  exception hierarchy (`FabricInvocationError` vs. `TransientFabricError`),
  and `SubprocessFabricClient`, the real implementation. This backend has no
  Fabric Go/Node SDK binding, so `SubprocessFabricClient` shells out to
  `blockchain/network/scripts/invoke.sh`/`query.sh` — the same interface a
  human operator uses, already proven end-to-end. Not a shortcut: adding a
  full gRPC-based SDK client for one consumer would be more new surface area
  than wrapping the already-proven scripts.
- `mock_fabric_client.py` — `MockFabricClient`, a `FabricClient` test double
  with no network and no subprocess. It mirrors the real chaincode's own
  validation rules (write-once `recordIncident`, append-only
  decision/approval/response/recovery requiring an existing incident,
  evidence-hash indexing) in Python, so tests using it exercise real
  behavior, not a canned-success stub. Keeping this in sync with
  `blockchain/chaincode/lib/provenanceContract.js`'s rules is manual — flagged
  in both files' docstrings.
- `outbox.py` — `OutboxRepository` (in-memory; default) and, since the
  post-Phase-15 Postgres migration, `PostgresOutboxRepository` (same public
  methods, backed by the real `outbox_entries` table in `app/models/orm.py`,
  selected via `Settings.repository_backend="postgres"`), plus typed
  `enqueue_*` helpers, one per schema in `app/schemas/blockchain.py` — those
  helpers take a repository instance as their first argument and call only
  `.enqueue(...)`, so they work unchanged against either repository.
- `outbox_worker.py` — `OutboxWorker.process_once()` drains pending entries
  and dispatches each to the matching `FabricClient` method. Retries a
  `TransientFabricError` (the multi-org endorsement timing race documented in
  `fabric_client.py` and in the project's `claude/architecture-decisions.md`)
  with exponential backoff up to a configurable `max_attempts`; any other
  `FabricInvocationError` (bad input, or the chaincode correctly rejecting an
  out-of-order or duplicate call) is marked `FAILED` immediately, since
  retrying it would just fail the same way forever. `run_forever()` is what a
  real deployment runs as a background task; tests call `process_once()`
  directly so they don't need a real sleep loop.
- `tests/` — unit tests for all of the above (outbox repository semantics,
  mock client validation rules, worker retry/dispatch logic, and the
  subprocess client's pure output-parsing helpers). None of these need a
  live Fabric network.

## What's NOT here yet

**Update, post-Phase-15:** the `chain_tx_id` column described below now
exists for real on `incidents`/`proposed_responses` (well, `decisions`
proper was never its own table — see `app/models/orm.py`) and
`executed_responses` via the Postgres migration (`Settings.
repository_backend="postgres"`; see `app/repositories/README.md`), and
`outbox_entries` is a real table too when that mode is on. Defaults to
`"memory"` everywhere, same as before, so nothing below is claimed as the
default behavior — opt in explicitly to get it.

`OutboxRepository`'s public shape (`enqueue`/`list_pending`/
`mark_confirmed`/`mark_failed`) was already written to survive that swap
without an API change, the same way `RecoveryResultRepository` and the
others were — `PostgresOutboxRepository` (this migration) is exactly that
swap, not a rewrite.
