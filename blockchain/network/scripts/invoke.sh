#!/bin/bash
# Submits an invoke transaction (endorsed by both orgs) against committed
# chaincode on pacr-channel.
#
# Usage: ./invoke.sh <chaincode_name> '<json args, e.g. {"Args":["Fn","a","b"]}>'
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
require_fabric_binaries

CC_NAME="$1"
ARGS_JSON="$2"

FABRIC_CFG_PATH="$PEERCFG_DIR" \
CORE_PEER_LOCALMSPID="$HOSPITAL_MSPID" \
CORE_PEER_MSPCONFIGPATH="$HOSPITAL_ADMIN_MSP" \
CORE_PEER_ADDRESS="$HOSPITAL_PEER_ADDR" \
CORE_PEER_TLS_ENABLED=true \
CORE_PEER_TLS_ROOTCERT_FILE="$HOSPITAL_PEER_TLS/ca.crt" \
"$FABRIC_BIN_DIR/bin/peer" chaincode invoke \
    -o "$ORDERER_ADDR" --ordererTLSHostnameOverride "$ORDERER_HOST" --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL_NAME" -n "$CC_NAME" \
    --peerAddresses "$HOSPITAL_PEER_ADDR" --tlsRootCertFiles "$HOSPITAL_PEER_TLS/ca.crt" \
    --peerAddresses "$SECURITYOPS_PEER_ADDR" --tlsRootCertFiles "$SECURITYOPS_PEER_TLS/ca.crt" \
    -c "$ARGS_JSON"
