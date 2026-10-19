#!/bin/bash
# Fetches one block of pacr-channel from the Hospital PEER (not the orderer) into a
# file. A block from the orderer has no per-transaction validation flags; the peer
# adds them at commit, so only a peer's copy shows which transactions were VALID.
#
# Usage: ./fetch-block.sh <block number | oldest | newest> <output file>
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
require_fabric_binaries

FABRIC_CFG_PATH="$PEERCFG_DIR" \
CORE_PEER_LOCALMSPID="$HOSPITAL_MSPID" \
CORE_PEER_MSPCONFIGPATH="$HOSPITAL_ADMIN_MSP" \
CORE_PEER_ADDRESS="$HOSPITAL_PEER_ADDR" \
CORE_PEER_TLS_ENABLED=true \
CORE_PEER_TLS_ROOTCERT_FILE="$HOSPITAL_PEER_TLS/ca.crt" \
"$FABRIC_BIN_DIR/bin/peer" channel fetch "$1" "$2" -c "$CHANNEL_NAME" >/dev/null 2>&1
