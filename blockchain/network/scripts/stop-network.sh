#!/bin/bash
# Stops the orderer, both peers, and any chaincode processes the external
# builder launched for them. Does not touch the ledger -- use reset.sh for
# a clean wipe.
#
# Usage: ./stop-network.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

# pkill -f has been unreliable in this project's reference sandbox (it can
# report success, or fail silently, without the process actually dying --
# see network/README.md, Adaptation 2, note on process cleanup). Find PIDs
# explicitly and verify after killing.
PATTERNS=(
    "$FABRIC_BIN_DIR/bin/orderer"
    "$FABRIC_BIN_DIR/bin/peer node start"
    "fabric-chaincode-node start"
)

for pattern in "${PATTERNS[@]}"; do
    pids=$(pgrep -f "$pattern" || true)
    if [ -n "$pids" ]; then
        echo "==> Killing: $pattern ($pids)"
        kill -9 $pids 2>/dev/null || true
    fi
done

sleep 1
for pattern in "${PATTERNS[@]}"; do
    remaining=$(pgrep -f "$pattern" || true)
    if [ -n "$remaining" ]; then
        echo "WARNING: still running after kill -9: $pattern ($remaining)" >&2
    fi
done

echo "==> done"
