#!/bin/bash
# Prints the channel's current block height (as seen by the given org's peer;
# default hospital) on stdout.
#
# Usage: ./ledger-height.sh [hospital|securityops]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
require_fabric_binaries

ORG="${1:-hospital}"
if [ "$ORG" = "securityops" ]; then
    MSPID="$SECURITYOPS_MSPID"; ADMIN_MSP="$SECURITYOPS_ADMIN_MSP"
    PEER_ADDR="$SECURITYOPS_PEER_ADDR"; PEER_TLS_CA="$SECURITYOPS_PEER_TLS/ca.crt"
else
    MSPID="$HOSPITAL_MSPID"; ADMIN_MSP="$HOSPITAL_ADMIN_MSP"
    PEER_ADDR="$HOSPITAL_PEER_ADDR"; PEER_TLS_CA="$HOSPITAL_PEER_TLS/ca.crt"
fi

FABRIC_CFG_PATH="$PEERCFG_DIR" \
CORE_PEER_LOCALMSPID="$MSPID" \
CORE_PEER_MSPCONFIGPATH="$ADMIN_MSP" \
CORE_PEER_ADDRESS="$PEER_ADDR" \
CORE_PEER_TLS_ENABLED=true \
CORE_PEER_TLS_ROOTCERT_FILE="$PEER_TLS_CA" \
"$FABRIC_BIN_DIR/bin/peer" channel getinfo -c "$CHANNEL_NAME" 2>&1 \
    | sed -n 's/.*"height":\([0-9]*\).*/\1/p'
