# Permissioned blockchain provenance

Two backends behind one interface. This document states plainly which one
produced which numbers, because conflating them would be dishonest.

---

## 1. What goes on the ledger — and why so little

**On-chain:** identifiers, hashes, verdicts, timestamps, engine fingerprints.
**Off-chain:** raw telemetry, logs, evidence bodies, synthetic patient
context, model artefacts — referenced by hash.

This is not a storage optimisation. A permissioned ledger is replicated to
every organisation on the channel and is, by design, immutable — so anything
written to it **cannot be deleted, corrected, or withheld from a peer
organisation**. Putting patient context on such a ledger would be a serious
architectural error even with synthetic data, because the design would not
survive contact with real data.

The hash-reference pattern means the ledger proves *what was decided, and
that the evidence has not changed*, while the evidence itself stays under
ordinary access control.

### Enforced in three places

Defence in depth, because a single check is one careless commit away from
permanent patient data on every peer:

| Layer | Mechanism |
|---|---|
| Domain model | `ProvenanceRecord.payload_for_ledger()` strips bulk fields |
| Client adapter | `validate_payload()` **rejects** forbidden keys and records over 4 KB |
| Chaincode | the endorsing peer rejects the same keys on-chain |

Rejected, never silently filtered. Filtering would hide a design error in
the caller, and the next forbidden field added might not be on the deny
list. The chaincode check matters most: the endorsing peer is the last place
that can say no.

The approval justification is **hashed rather than stored** — it is free
text that may name staff, and an immutable replicated ledger is the wrong
home for it. The hash still proves it has not changed.

---

## 2. The five mandated records

| Record | Committed by | Carries |
|---|---|---|
| `INCIDENT_RECORDED` | SecurityOps | evidence bundle hash, detector result hash |
| `DECISION_RECORDED` | SecurityOps | both risk scores, selected action, **the cyber-only counterfactual**, risk-profile fingerprint |
| `APPROVAL_RECORDED` | Hospital | status, approver, justification **hash**, policy fingerprint |
| `RESPONSE_RECORDED` | SecurityOps | executed action, policy verdict and matched rule, attempt number |
| `RECOVERY_RECORDED` | Audit | outcome, checks passed, residual risk, checks hash |

Two details worth noting.

**The counterfactual is committed.** The decision record carries what a
cyber-risk-only defender would have chosen, so a reader can later verify
that the system considered — and declined — the drastic action. That is the
contribution's evidence, and it is independently checkable rather than
asserted in a paper.

**Engine fingerprints are committed.** A provenance entry recording a
decision but not the parameter set that produced it cannot be audited: the
same inputs under a different risk profile would yield a different decision.
So `formulation_version@risk-fingerprint` and
`policy_version@policy-fingerprint` go on-chain with the decision.

---

## 3. Organisations and separation of duties

| Org | Originates | Reads |
|---|---|---|
| **Hospital** | approvals — a clinician's authorisation is the hospital's act, not the SOC's | all |
| **SecurityOps** | incidents, decisions, responses | all |
| **Audit** | recovery outcomes | all |

Endorsement requires a **MAJORITY**, not `ANY`. SecurityOps alone cannot
commit a record attesting to its own decisions. Without that, one
compromised or mistaken organisation could write whatever history it liked,
and the ledger would be theatre.

Audit can read everything without being able to originate a security
decision. An auditor who depends on the audited party for the record is not
an auditor.

---

## 4. The two backends

### `local` — hash-chained file ledger (default)

Each block commits to its predecessor's hash. Altering any committed record
invalidates every block after it, and `verify_chain()` names the exact block
that broke.

**It is:** append-only, content-addressed, integrity-verifiable, durable
(JSON-lines), runnable in CI and on a laptop with no infrastructure.

**It is not:** a distributed ledger. No consensus, no Byzantine fault
tolerance, no independent validation by a second organisation. A party with
write access to the file can rewrite the chain from genesis.

Two safety behaviours worth noting: a ledger that fails verification **on
load** refuses to accept appends, because building new blocks on a chain
already known to be broken would make the tampering harder to locate; and
re-committing an existing provenance id is refused outright.

### `fabric` — Hyperledger Fabric via the Gateway API

Provides the trust model the local ledger cannot: endorsement, ordering,
MSP-based identity, and replication to organisations that did not originate
the record.

---

## 5. Honest statement of what has been executed

**This is the section a reviewer should read first.**

| Component | Status |
|---|---|
| Local ledger | **Executed.** 59 tests, in CI, including tamper detection |
| Chaincode logic | **Compiled and executed** against a stub contract API: 16 assertions, `scripts/verify_chaincode.sh` |
| Chaincode on a live network | **Not executed.** No Fabric deployment available in the development environment |
| Fabric adapter logic | **Executed** against a stub gateway: payload hygiene, receipt construction, error translation |
| Fabric adapter against a live network | **Not executed.** `connect_fabric()` deliberately raises rather than returning a half-configured client |
| Network config (`configtx`, `crypto-config`, compose) | **Written and YAML-validated.** Not deployed |

Consequences, stated rather than buried:

1. **Every blockchain metric in the paper is labelled with its backend.**
   Local-ledger latency is sub-millisecond; Fabric latency is typically
   tens to hundreds of milliseconds under endorsement and ordering. They
   differ by orders of magnitude, and presenting one as the other would be
   fabrication.
2. **Fabric-dependent tests carry the `fabric` marker and skip visibly**
   rather than being silently absent, so the gap appears in the test report.
3. **`connect_fabric()` raises.** A client that looks connected and fails
   later with an obscure SDK error is worse than a refusal — and one that
   appears to succeed is worse still, because it invites someone to believe
   Fabric results were produced when they were not.

The alternative — reporting hash-chain numbers as Fabric numbers — is the
kind of shortcut that gets a paper retracted.

---

## 6. Chaincode verification without the SDK

The Go module proxy is not reachable in every environment, so `go build`
against the real `fabric-contract-api-go` is not always possible. Shipping
Go that has never been compiled is not acceptable, so
`blockchain/fabric/chaincode/provenance/verify/` provides a minimal
stand-in for the subset of the contract API the chaincode uses.

```bash
bash scripts/verify_chaincode.sh    # gofmt check, go vet, 16 assertions
```

**Verifies:** payload validation, on-chain rejection of patient data and
oversized records, the append-only guard, attribution taken from the
transaction context rather than client input, event-type matching, evidence
verification (including that a missing record is *not* a pass), composite-key
history queries, and that a stored record carries no forbidden key.

**Does not verify:** endorsement, ordering, consensus, MSP validation, or
real gateway behaviour.

---

## 7. Evidence verification: two layers, two attacks

| Attack | Caught by |
|---|---|
| Evidence **body altered** | per-item `verify()` — recomputes each hash from its payload |
| Evidence **added or removed** | bundle hash — committed at incident creation |
| Body altered **and re-hashed** | bundle hash — the evidence_hash field changed |
| **Ledger itself** tampered | `verify_chain()` — hash-chain break |

The layers close each other's gaps, which is why both exist. A test for each
of the four attacks is in `tests/unit/test_blockchain.py`.

> A test asserting the wrong layer initially failed here. The code was
> correct; the test conflated the two checks. Fixing it properly meant
> adding the add/remove and re-hash cases that were missing.

---

## 8. Running Fabric

```bash
# 1. Generate development crypto material. cryptogen is a DEVELOPMENT tool:
#    it creates every private key in one place, which a real deployment must
#    never do - each organisation runs its own CA. Output is gitignored.
cd blockchain/fabric/network
cryptogen generate --config=crypto-config.yaml --output=../organizations

# 2. Channel artefacts
configtxgen -profile PACRGenesis -channelID system-channel \
            -outputBlock ../channel-artifacts/genesis.block
configtxgen -profile PACRChannel -outputCreateChannelTx \
            ../channel-artifacts/pacrchannel.tx -channelID pacrchannel

# 3. Bring up the network (requires COUCHDB_PASSWORD in .env - the compose
#    file refuses to start without it rather than defaulting to a weak value)
docker compose -f docker-compose-fabric.yml up -d

# 4. Package, install, approve and commit the chaincode on all three orgs
#    (standard Fabric lifecycle; see the Fabric documentation)

# 5. Point the platform at it
export PROVENANCE_BACKEND=fabric
export FABRIC_CERT_PATH=/secure/...   # outside the repository
```

`.gitignore` excludes `crypto-config/`, `organizations/`,
`channel-artifacts/`, `wallet/`, `*.block`, `*.tx` and every key and
certificate pattern. No identity material belongs in version control.

---

## 9. Reported metrics

| Metric | Source |
|---|---|
| Transaction latency (mean, p95) | measured per write, per backend |
| Throughput | records per second over an experiment run |
| Verification time | full-chain verification, reported with record count |
| Storage overhead | bytes per record — bounded by the 4 KB cap |
| Integrity verification | pass/fail plus the first invalid block index |

Every row carries the backend that produced it.

---

## 10. Threats to validity

1. **Local-ledger metrics are not Fabric metrics.** Stated everywhere they
   appear.
2. **Chaincode is logic-verified, not network-verified.** The stub exercises
   the contract's own code, not Fabric's.
3. **No adversarial testing of Fabric's trust model.** We do not demonstrate
   Byzantine resistance; we rely on Fabric's own guarantees and cite them.
4. **Three organisations on one host is not a trust boundary.** A real
   deployment would place them in separate administrative domains. The
   development network demonstrates the *topology*, not the isolation.
