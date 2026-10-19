#!/bin/bash
# Submits an invoke transaction (endorsed by both orgs) against committed
# chaincode on pacr-channel, and WAITS until both peers have committed it.
#
# `--waitForEvent` matters: without it `peer chaincode invoke` returns as soon as
# the transaction is endorsed and handed to the orderer, so a transaction that is
# later invalidated at commit (MVCC conflict, endorsement-policy failure) would be
# reported to the caller as a success, and the next call could be endorsed against
# a peer that has not yet applied the previous block. With it, the command exits
# non-zero with "transaction invalidated with status (...)" for an invalid
# transaction, so the backend's outbox only marks provenance CONFIRMED for
# transactions that really are on the ledger.
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
    --waitForEvent --waitForEventTimeout 60s \
    -c "$ARGS_JSON"
