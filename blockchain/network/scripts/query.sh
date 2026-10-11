#!/bin/bash
# Evaluates a (read-only) query against committed chaincode on pacr-channel,
# from the Hospital peer by default.
#
# Usage: ./query.sh <chaincode_name> '<json args, e.g. {"Args":["Fn","a"]}>' [org]
# org is "hospital" (default) or "securityops".
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
require_fabric_binaries

CC_NAME="$1"
ARGS_JSON="$2"
ORG="${3:-hospital}"

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
"$FABRIC_BIN_DIR/bin/peer" chaincode query -C "$CHANNEL_NAME" -n "$CC_NAME" -c "$ARGS_JSON"
