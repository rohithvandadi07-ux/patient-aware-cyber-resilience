#!/bin/bash
# Installs a packaged chaincode on both peers, approves it for both orgs,
# and commits the definition to the channel. Idempotent-ish: re-running
# with a bumped --sequence for an already-approved version is fine; Fabric
# will reject a sequence that's not actually next (the error message says
# the current next sequence, which is the usual way to discover it).
#
# Usage: ./deploy-chaincode.sh <package.tgz> <name> <version> <sequence>
# Example: ./deploy-chaincode.sh /tmp/provenance.tgz provenance 1.0 1
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
require_fabric_binaries

PACKAGE="$1"
CC_NAME="$2"
CC_VERSION="$3"
CC_SEQUENCE="$4"

PEER="$FABRIC_BIN_DIR/bin/peer"

# Re-running install for a package already installed on this peer is not
# an error worth aborting over -- it's the common case when re-running this
# script (e.g. after deploy failed partway through on a previous attempt).
# Fabric reports that case as a non-zero-exit error rather than success, so
# this tolerates it explicitly instead of letting `set -e` abort the whole
# deploy, and extracts the package ID from either message shape.
install_on() {
    local mspid="$1" peer_addr="$2" peer_tls_ca="$3" admin_msp="$4"
    local out
    out=$(FABRIC_CFG_PATH="$PEERCFG_DIR" \
        CORE_PEER_LOCALMSPID="$mspid" \
        CORE_PEER_MSPCONFIGPATH="$admin_msp" \
        CORE_PEER_ADDRESS="$peer_addr" \
        CORE_PEER_TLS_ENABLED=true \
        CORE_PEER_TLS_ROOTCERT_FILE="$peer_tls_ca" \
        "$PEER" lifecycle chaincode install "$PACKAGE" 2>&1) || true
    echo "$out" >&2
    if ! echo "$out" | grep -q "package identifier:\|already successfully installed"; then
        echo "ERROR: chaincode install failed on $mspid:" >&2
        echo "$out" >&2
        exit 1
    fi
    echo "$out" | grep -oP "package identifier: \K\S+|package ID '\K[^']+" | head -1
}

approve_on() {
    local mspid="$1" peer_addr="$2" peer_tls_ca="$3" admin_msp="$4" package_id="$5"
    FABRIC_CFG_PATH="$PEERCFG_DIR" \
    CORE_PEER_LOCALMSPID="$mspid" \
    CORE_PEER_MSPCONFIGPATH="$admin_msp" \
    CORE_PEER_ADDRESS="$peer_addr" \
    CORE_PEER_TLS_ENABLED=true \
    CORE_PEER_TLS_ROOTCERT_FILE="$peer_tls_ca" \
    "$PEER" lifecycle chaincode approveformyorg \
        -o "$ORDERER_ADDR" --ordererTLSHostnameOverride "$ORDERER_HOST" --tls --cafile "$ORDERER_CA" \
        --channelID "$CHANNEL_NAME" --name "$CC_NAME" --version "$CC_VERSION" \
        --sequence "$CC_SEQUENCE" --package-id "$package_id"
}

echo "==> Installing on HospitalOrg"
PACKAGE_ID=$(install_on "$HOSPITAL_MSPID" "$HOSPITAL_PEER_ADDR" "$HOSPITAL_PEER_TLS/ca.crt" "$HOSPITAL_ADMIN_MSP")

echo "==> Installing on SecurityOpsOrg"
install_on "$SECURITYOPS_MSPID" "$SECURITYOPS_PEER_ADDR" "$SECURITYOPS_PEER_TLS/ca.crt" "$SECURITYOPS_ADMIN_MSP" >/dev/null

echo "==> Package ID: $PACKAGE_ID"

echo "==> Approving for HospitalOrg"
approve_on "$HOSPITAL_MSPID" "$HOSPITAL_PEER_ADDR" "$HOSPITAL_PEER_TLS/ca.crt" "$HOSPITAL_ADMIN_MSP" "$PACKAGE_ID"

echo "==> Approving for SecurityOpsOrg"
approve_on "$SECURITYOPS_MSPID" "$SECURITYOPS_PEER_ADDR" "$SECURITYOPS_PEER_TLS/ca.crt" "$SECURITYOPS_ADMIN_MSP" "$PACKAGE_ID"

echo "==> Checking commit readiness"
FABRIC_CFG_PATH="$PEERCFG_DIR" \
CORE_PEER_LOCALMSPID="$HOSPITAL_MSPID" \
CORE_PEER_MSPCONFIGPATH="$HOSPITAL_ADMIN_MSP" \
CORE_PEER_ADDRESS="$HOSPITAL_PEER_ADDR" \
CORE_PEER_TLS_ENABLED=true \
CORE_PEER_TLS_ROOTCERT_FILE="$HOSPITAL_PEER_TLS/ca.crt" \
"$PEER" lifecycle chaincode checkcommitreadiness \
    --channelID "$CHANNEL_NAME" --name "$CC_NAME" --version "$CC_VERSION" --sequence "$CC_SEQUENCE" --output json

echo "==> Committing chaincode definition"
FABRIC_CFG_PATH="$PEERCFG_DIR" \
CORE_PEER_LOCALMSPID="$HOSPITAL_MSPID" \
CORE_PEER_MSPCONFIGPATH="$HOSPITAL_ADMIN_MSP" \
CORE_PEER_ADDRESS="$HOSPITAL_PEER_ADDR" \
CORE_PEER_TLS_ENABLED=true \
CORE_PEER_TLS_ROOTCERT_FILE="$HOSPITAL_PEER_TLS/ca.crt" \
"$PEER" lifecycle chaincode commit \
    -o "$ORDERER_ADDR" --ordererTLSHostnameOverride "$ORDERER_HOST" --tls --cafile "$ORDERER_CA" \
    --channelID "$CHANNEL_NAME" --name "$CC_NAME" --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
    --peerAddresses "$HOSPITAL_PEER_ADDR" --tlsRootCertFiles "$HOSPITAL_PEER_TLS/ca.crt" \
    --peerAddresses "$SECURITYOPS_PEER_ADDR" --tlsRootCertFiles "$SECURITYOPS_PEER_TLS/ca.crt"

echo "==> $CC_NAME@$CC_VERSION (sequence $CC_SEQUENCE) committed. package ID: $PACKAGE_ID"
