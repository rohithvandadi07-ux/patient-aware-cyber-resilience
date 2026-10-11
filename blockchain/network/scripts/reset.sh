#!/bin/bash
# Full clean reset: stops the network and wipes every bit of ledger state,
# including the orderer's Raft WAL.
#
# IMPORTANT: the etcdraft WAL/snapshot data lives at the hardcoded path
# /var/hyperledger/production/orderer/etcdraft/wal/<channel>, independent
# of ORDERER_FILELEDGER_LOCATION. Wiping only run/ (the redirected ledger
# dir) and regenerating a fresh genesis block leaves stale Raft state
# behind, and the orderer panics on restart with a block-hash mismatch.
# This script wipes both. See network/README.md, Adaptation 2.
#
# Usage: ./reset.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

./stop-network.sh

echo "==> Wiping run/ and channel-artifacts/"
rm -rf "$RUN_DIR" "$CHANNEL_ARTIFACTS_DIR"

echo "==> Wiping /var/hyperledger/production (etcdraft WAL -- see header comment)"
rm -rf /var/hyperledger/production

echo "==> done -- run ./generate.sh then ./start-network.sh for a fresh network"
