# Chaincode logic verification harness

## Why this exists

The Fabric SDK cannot be fetched in every environment (the Go module proxy
may be unreachable), so `go build` against the real
`fabric-contract-api-go` is not always possible. Shipping Go that has never
been compiled is not acceptable, so this harness provides a minimal
stand-in for the subset of the Fabric contract API the chaincode uses, which
lets the chaincode's **own logic** be compiled and executed anywhere.

## What it does and does not verify

**Verifies** (16 assertions): payload validation, on-chain rejection of
patient data and oversized records, the append-only guard, attribution taken
from the transaction context rather than client input, event-type matching,
evidence verification including that a missing record is *not* a pass,
composite-key history queries, and that a stored record carries no
forbidden key.

**Does not verify**: Fabric's endorsement, ordering, consensus, MSP
validation, or real gateway behaviour. Those require a live network — see
[`../../../../../docs/blockchain.md`](../../../../../docs/blockchain.md).

## Run

```bash
cd blockchain/fabric/chaincode/provenance/verify
go run .
```

Expected: `16 passed, 0 failed`. The harness panics on any failure, so it is
usable as a CI gate where Go is available but the Fabric SDK is not.

## Keeping it in step

`provenance.go` here is a **copy** of the chaincode with its import path
rewritten. Regenerate it after changing the chaincode:

```bash
cd blockchain/fabric/chaincode/provenance
cp provenance.go verify/provenance.go
sed -i 's|"github.com/hyperledger/fabric-contract-api-go/contractapi"|"ccverify/contractapi"|' verify/provenance.go
sed -i 's|^func main() {|func unusedMain() {|' verify/provenance.go
```

`scripts/verify_chaincode.sh` does this and runs the harness.
