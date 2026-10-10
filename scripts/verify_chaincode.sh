#!/usr/bin/env bash
# Regenerate the chaincode verification copy and run the logic harness.
#
# Verifies the chaincode's own logic without the Fabric SDK, which is not
# fetchable in every environment. It does NOT verify Fabric's endorsement,
# ordering or consensus - see docs/blockchain.md.
set -euo pipefail

CC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../blockchain/fabric/chaincode/provenance" && pwd)"
VERIFY_DIR="$CC_DIR/verify"

if ! command -v go >/dev/null 2>&1; then
  echo "go is not installed; skipping chaincode verification" >&2
  exit 0
fi

cp "$CC_DIR/provenance.go" "$VERIFY_DIR/provenance.go"
sed -i.bak \
  's|"github.com/hyperledger/fabric-contract-api-go/contractapi"|"ccverify/contractapi"|' \
  "$VERIFY_DIR/provenance.go"
sed -i.bak 's|^func main() {|func unusedMain() {|' "$VERIFY_DIR/provenance.go"
rm -f "$VERIFY_DIR/provenance.go.bak"

cd "$VERIFY_DIR"
gofmt -l . | tee /tmp/gofmt-out
if [ -s /tmp/gofmt-out ]; then
  echo "chaincode is not gofmt-clean" >&2
  exit 1
fi
go vet ./...
go run .
