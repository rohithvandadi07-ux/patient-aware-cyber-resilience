# Blockchain layer: measurements on a real Hyperledger Fabric network

Generated 2026-10-16T18:34:03.362759+00:00. Real Fabric v2.5.9 binaries, two organisations (Hospital, SecurityOps) with one peer each, one Raft orderer, the real provenance chaincode, driven through the backend's own `SubprocessFabricClient`. No mocks. Method and limits are in `backend/app/evaluation/run_blockchain_evaluation.py`.

## Scope of the claim

- Machine: 2 CPUs, one host. Peers, orderer and chaincode all share it.
- **One Raft consenter**: this network has no orderer fault tolerance. Nothing below speaks to availability or to Byzantine or malicious-orderer behaviour.
- Every call spawns the Fabric CLI, and the orderer batch timeout is 1 s, so these are latencies of THIS deployment, not of Fabric. One CLI spawn alone costs about 65 ms here.
- One run on one machine; no repeated trials, so no confidence intervals.

## Integrity checks (pass/fail)

| Check | Result | Observed |
|---|---|---|
| duplicate incident id is rejected (write-once record) | PASS | ponse: status:500 message:"incident 'EVAL-I-183403' already has a recordIncident entry -- the initial incident record cannot be overwritten" |
| decision for an unknown incident is rejected | PASS | ident 'EVAL-NEVER-RECORDED' has no recordIncident entry -- call recordIncident before recording a decision, approval, response, or recovery" |
| invalid response-action category is rejected | PASS | n, isolate_non_critical, isolate_critical, quarantine_segment, activate_backup, restart_service, failover, shutdown], got 'launch_missiles'" |
| verify_evidence accepts the recorded evidence hash | PASS | sha256 e2f817ebb91b2cf1... found on ledger |
| verify_evidence rejects evidence altered by one field | PASS | sha256 dc6f20f559df66bf... not on ledger |
| Hospital and SecurityOps peers return the same answer | PASS | hospital='true' securityops='true' |
| two simultaneous writers of one incident id: exactly one is reported committed, and only that record is on the ledger | PASS | reported committed: ['A']; on ledger: A=True, B=False |
| a transaction endorsed by one organisation only is invalidated (MAJORITY policy) | PASS | status ENDORSEMENT_POLICY_FAILURE, no state written |

## Ledger tamper evidence

All 142 blocks (194 transactions) were fetched from the Hospital peer and re-verified with an independent implementation of Fabric's block hashing (header hash chain plus data hash, recomputed from the raw block bytes).

- Genuine chain: verified, every link intact.
- Edit one byte of one transaction in block 70 (on a copy): DETECTED at block 70 (data hash does not match the block's transactions).
- Same edit, with the attacker also recomputing that block's own data hash so the block looks self-consistent: DETECTED at block 71 (previous_hash does not match the prior block's header).

### Does the ledger agree with what the client reported?

Every transaction id the backend's client reported as committed during this run was looked up in the fetched blocks: 188 reported, 188 VALID on the ledger, 0 missing, 0 invalid.
Validation outcomes recorded on the ledger overall: ENDORSEMENT_POLICY_FAILURE 1, MVCC_READ_CONFLICT 1, VALID 192. Invalid transactions stay on the chain, flagged, and never change state; the ones here were produced on purpose by the one-organisation-endorsement and simultaneous-writer checks.

This shows edits are detectable by anyone who re-verifies the chain. It does not claim a peer's files cannot be edited, and it checks a copy of the chain, not the live peers.

## Latency (sequential, milliseconds)

| Operation | n | p50 | p95 | max |
|---|---|---|---|---|
| Fabric CLI spawn alone (`peer version`), the floor | 20 | 65 | 188 | 239 |
| Write: `record_incident`, until both peers have committed it | 40 | 1114 | 1139 | 1147 |
| After a write returns: time until a query sees it (polled every 100 ms) | 20 | 87 | 112 | 127 |
| Read: `verify_evidence` | 40 | 89 | 108 | 115 |
| Full 5-transaction incident lifecycle | 10 | 5578 | 5610 | 5617 |
|   lifecycle step: incident | 10 | 1112 | 1131 | 1134 |
|   lifecycle step: decision | 10 | 1121 | 1131 | 1131 |
|   lifecycle step: approval | 10 | 1115 | 1128 | 1132 |
|   lifecycle step: response | 10 | 1115 | 1134 | 1134 |
|   lifecycle step: recovery | 10 | 1111 | 1126 | 1127 |

Transient endorsement-race retries needed (the documented timing artifact): writes 0, lifecycle 0.

## Concurrency

| Concurrent clients | Submitted | Committed | Failed | Wall (s) | Committed tx/s | p50 (ms) | p95 (ms) |
|---|---|---|---|---|---|---|---|
| 1 | 24 | 24 | 0 | 26.7 | 0.90 | 1111 | 1128 |
| 2 | 24 | 24 | 0 | 13.5 | 1.78 | 1124 | 1145 |
| 4 | 24 | 24 | 0 | 7.2 | 3.36 | 1193 | 1237 |
| 8 | 24 | 24 | 0 | 4.0 | 5.99 | 1321 | 1373 |

## A defect this evaluation found, now fixed

The first run of this evaluation exposed that `invoke.sh` called `peer chaincode invoke` without `--waitForEvent`. The client therefore returned success once a transaction was endorsed and handed to the orderer, not once it was committed: an immediate duplicate `recordIncident` was reported as accepted (the ledger itself kept the first record), the next call could be endorsed against a peer that had not yet applied the previous block (the 'transient endorsement race' the outbox worker was already retrying), and, worse, a transaction invalidated at commit would still have been reported as committed, so the outbox could mark a provenance record CONFIRMED that never reached the ledger. `invoke.sh` now waits for both peers' commit events and exits non-zero for an invalidated transaction. The latencies in this report are measured with the fix; the checks above, including the simultaneous-writer check, and the integration tests in `backend/tests/test_blockchain_integration.py` guard against a regression.

## Reading this honestly

- A write takes about one second mostly because the orderer's batch timeout is 1 s and the client waits for both peers to commit; the write rate is also bounded by CLI process spawning on a small shared machine. A Fabric SDK client with persistent connections, and a tuned batch timeout, would change these numbers; they are not a Fabric benchmark.
- The system writes only a handful of provenance transactions per incident, and incidents are rare compared with flows, so per-incident latency is the relevant figure, not peak throughput.
- Provenance is written through the outbox, off the detection and response path, so these latencies do not delay containment.
