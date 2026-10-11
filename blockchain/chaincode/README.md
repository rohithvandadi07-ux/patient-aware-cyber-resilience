# blockchain/chaincode

Node.js chaincode (`fabric-contract-api`/`fabric-shim`) implementing the six
provenance operations from the architecture spec, Section 14, unchanged as
names: `recordIncident`, `recordDecision`, `recordApproval`,
`recordResponse`, `recordRecovery`, `verifyEvidence`. Stores hashes and
structured metadata only -- never raw telemetry, logs, or patient
identifiers. Deployed via `../network/` (see that directory's README for
why this is Node.js rather than Go, and how it's launched without Docker).

Source: `index.js` (entry point), `lib/provenanceContract.js` (the
contract). Tests: `test/` (hand-built fake stub, no live network --
see below).

## Status

Implemented and tested two ways:

1. **Unit tests** (`npm test`, 14 tests, all passing) against a hand-built
   fake `ChaincodeStub` (`test/fakeContext.js`) -- no Fabric network
   needed. These cover every validation branch (empty/invalid fields,
   unknown enum values, recording against a nonexistent incident,
   re-recording an incident, the optional `residual_threats_hash`), plus
   an explicit composite-key prefix-collision regression test
   (`INC-1` vs `INC-10`).
2. **Real end-to-end run** against the actual network in `../network/`:
   packaged with `package-chaincode.sh`, installed/approved/committed with
   `deploy-chaincode.sh`, then all six operations invoked for real via
   `invoke.sh`/`query.sh` for a sample incident (`INC-E2E-1`) -- including
   `verifyEvidence` against both a `recordIncident` evidence hash and a
   `recordRecovery` residual-threats hash, and `getProvenanceTrail`
   returning the accumulated decision/approval/response/recovery history.
   Both peers independently launched and registered the chaincode process
   and agreed on the resulting world state.

## Schema used for each operation's arguments

Chaincode arguments are always strings; the shapes below are this
project's own off-chain Pydantic mirror
(`backend/app/schemas/blockchain.py`), written before this chaincode and
followed exactly here so the two layers can't drift:

| Operation | Args (in order) |
|---|---|
| `recordIncident` | `incident_id, device_id, attack_type, evidence_hash, timestamp` (ISO-8601) |
| `recordDecision` | `incident_id, risk_score_hash, policy_rule_id, recommended_action` (one of `ResponseActionCategory`, see `backend/app/schemas/enums.py`) |
| `recordApproval` | `incident_id, approver_identity, decision` (`approved`/`rejected`), `timestamp` |
| `recordResponse` | `incident_id, action_taken` (`ResponseActionCategory`), `executed_by, timestamp` |
| `recordRecovery` | `incident_id, recovery_verified` (`"true"`/`"false"`), `residual_threats_hash` (empty string `""` means not provided -- there's no native null for a chaincode string arg) |
| `verifyEvidence` | `evidence_hash` -> returns a boolean |

`recommended_action`/`action_taken`'s allowed values and `decision`'s
allowed values are hardcoded in `lib/provenanceContract.js` as a duplicate
of `backend/app/schemas/enums.py`'s `ResponseActionCategory`/
`ApprovalDecision` (JS can't import a Python enum). **If you add, rename,
or remove a value in `enums.py`, update `provenanceContract.js` too, or
this chaincode will start rejecting valid categories or silently accepting
retired ones.**

## Design decisions beyond the brief's bare signatures

The brief gives six function signatures and one line each of description;
it doesn't specify multiplicity, overwrite behavior, or exactly what
`verifyEvidence` checks against. The choices made here (and why) are
documented in `lib/provenanceContract.js`'s class docstring, not hidden in
code:

- `recordIncident` is **write-once** per `incident_id` -- re-recording the
  same ID is rejected, not overwritten. The point of a provenance ledger
  is that the initial record can't quietly change.
- `recordDecision`/`recordApproval`/`recordResponse`/`recordRecovery` are
  **append-only per incident** (an incident can legitimately be
  re-risk-assessed, re-approved, re-responded-to, and re-verified multiple
  times over its lifecycle -- this matches the agent/policy/recovery loop
  built in Phases 4-7) and all **require the incident to already exist**.
  Each append uses a Fabric composite key
  (`createCompositeKey(eventType, [incidentId, txId])`), which is also what
  makes `getProvenanceTrail` below possible.
- `verifyEvidence` checks a hash against every hash this contract has ever
  committed as evidence -- both `recordIncident`'s `evidence_hash` and
  `recordRecovery`'s `residual_threats_hash` (when provided) -- not only
  the initial incident hash. This is this project's own extension of the
  brief's one-line description, flagged as a decision rather than quoted
  as spec text.
- `getIncident(incident_id)` and `getProvenanceTrail(incident_id)` are
  read-only convenience functions **beyond** the six named operations,
  added for test and future audit-dashboard use (`/blockchain/audit`,
  Section 15). The six-operation list itself is unchanged.

## Running the tests

```bash
cd blockchain/chaincode
npm install
npm test
```
