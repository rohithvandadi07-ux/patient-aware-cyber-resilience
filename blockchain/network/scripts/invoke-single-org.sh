#!/bin/bash
# Submits an invoke endorsed by ONE org's peer only (the other org does not
# endorse). With the channel's MAJORITY endorsement policy over two orgs this
# must be rejected at validation; the blockchain evaluation uses it to show the
# policy is actually enforced, not just configured.
#
# Usage: ./invoke-single-org.sh <chaincode_name> '<json args>' [hospital|securityops]
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
"$FABRIC_BIN_DIR/bin/peer" chaincode invoke \
    -o "$ORDERER_ADDR" --ordererTLSHostnameOverride "$ORDERER_HOST" --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL_NAME" -n "$CC_NAME" \
    --peerAddresses "$PEER_ADDR" --tlsRootCertFiles "$PEER_TLS_CA" \
    --waitForEvent \
    -c "$ARGS_JSON"
