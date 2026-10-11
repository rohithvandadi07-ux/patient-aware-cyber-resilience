# blockchain

L9 of the architecture. The Fabric client and the asynchronous outbox worker that
commit the six provenance event types (`recordIncident`, `recordDecision`,
`recordApproval`, `recordResponse`, `recordRecovery`, `verifyEvidence`) to the
Hyperledger Fabric network in `../../../blockchain/network/`. Never sits on the
response-execution hot path — writes are queued and confirmed asynchronously.

## Status

Implemented, unit-tested (34 tests, no live network needed), and — see
`../../../blockchain/README.md` for the Phase 8 integration test — proven
against the real network and real chaincode in `blockchain/network/` and
`blockchain/chaincode/`.

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
- `outbox.py` — `OutboxRepository` (in-memory, same pattern as every other
  repository in this codebase — `app/repositories/*.py` — pending a Phase 9
  Postgres swap with the same shape) plus typed `enqueue_*` helpers, one per
  schema in `app/schemas/blockchain.py`.
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

A real Postgres-backed `chain_tx_id` column on the off-chain `incidents`/
`decisions`/etc. tables — those tables don't exist yet either; every
repository in this codebase (including `OutboxRepository` here) is
in-memory pending Phase 9's real persistence layer, by explicit, consistent
project decision (see `app/repositories/*.py` and
`claude/architecture-decisions.md`). `OutboxRepository`'s public shape
(`enqueue`/`list_pending`/`mark_confirmed`/`mark_failed`) is already
written to survive that swap without an API change, the same way
`RecoveryResultRepository` and the others were.
