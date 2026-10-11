#!/bin/bash
# Shared configuration for every network/scripts/*.sh script. Source this,
# don't execute it directly.
#
# Override any of these by exporting them before calling a script, e.g.:
#   FABRIC_BIN_DIR=/opt/fabric/bin ./start-network.sh
set -euo pipefail

# Directory containing the native Fabric binaries (peer, orderer, cryptogen,
# configtxgen, osnadmin). This project runs Fabric from downloaded
# GitHub-release binaries rather than Docker (Docker Hub is blocked in the
# reference sandbox this was built in -- see ../README.md, Adaptation 0).
# Fabric's own "config" subdirectory (its stock orderer.yaml/core.yaml)
# ships alongside the binaries in the official binary release, and this
# project's own peercfg/core.yaml.template is this project's edited copy of
# that stock core.yaml.
: "${FABRIC_BIN_DIR:=/home/claude/fabric-dist}"

NETWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$NETWORK_DIR/run"
CRYPTO_DIR="$NETWORK_DIR/crypto-config"
CHANNEL_ARTIFACTS_DIR="$NETWORK_DIR/channel-artifacts"
PEERCFG_DIR="$NETWORK_DIR/peercfg"
LOG_DIR="$NETWORK_DIR/logs"

CHANNEL_NAME="pacr-channel"
CHANNEL_PROFILE="PACRChannel"

ORDERER_DOMAIN="orderer.pacr.local"
ORDERER_HOST="orderer1.$ORDERER_DOMAIN"
ORDERER_ADDR="127.0.0.1:7050"
ORDERER_ADMIN_ADDR="127.0.0.1:7053"
ORDERER_TLS_DIR="$CRYPTO_DIR/ordererOrganizations/$ORDERER_DOMAIN/orderers/$ORDERER_HOST/tls"
ORDERER_CA="$CRYPTO_DIR/ordererOrganizations/$ORDERER_DOMAIN/orderers/$ORDERER_HOST/msp/tlscacerts/tlsca.$ORDERER_DOMAIN-cert.pem"

HOSPITAL_DOMAIN="hospital.pacr.local"
HOSPITAL_PEER_HOST="peer0.$HOSPITAL_DOMAIN"
HOSPITAL_MSPID="HospitalMSP"
HOSPITAL_PEER_ADDR="127.0.0.1:7051"
HOSPITAL_CC_ADDR="127.0.0.1:7052"
HOSPITAL_OPS_ADDR="127.0.0.1:9444"
HOSPITAL_PEER_MSP="$CRYPTO_DIR/peerOrganizations/$HOSPITAL_DOMAIN/peers/$HOSPITAL_PEER_HOST/msp"
HOSPITAL_PEER_TLS="$CRYPTO_DIR/peerOrganizations/$HOSPITAL_DOMAIN/peers/$HOSPITAL_PEER_HOST/tls"
HOSPITAL_ADMIN_MSP="$CRYPTO_DIR/peerOrganizations/$HOSPITAL_DOMAIN/users/Admin@$HOSPITAL_DOMAIN/msp"

SECURITYOPS_DOMAIN="securityops.pacr.local"
SECURITYOPS_PEER_HOST="peer0.$SECURITYOPS_DOMAIN"
SECURITYOPS_MSPID="SecurityOpsMSP"
SECURITYOPS_PEER_ADDR="127.0.0.1:8051"
SECURITYOPS_CC_ADDR="127.0.0.1:8052"
SECURITYOPS_OPS_ADDR="127.0.0.1:9445"
SECURITYOPS_PEER_MSP="$CRYPTO_DIR/peerOrganizations/$SECURITYOPS_DOMAIN/peers/$SECURITYOPS_PEER_HOST/msp"
SECURITYOPS_PEER_TLS="$CRYPTO_DIR/peerOrganizations/$SECURITYOPS_DOMAIN/peers/$SECURITYOPS_PEER_HOST/tls"
SECURITYOPS_ADMIN_MSP="$CRYPTO_DIR/peerOrganizations/$SECURITYOPS_DOMAIN/users/Admin@$SECURITYOPS_DOMAIN/msp"

# The sandbox's outbound-HTTPS agent proxy only recognizes literal
# 127.0.0.1/localhost as local; every Fabric node in this network is
# addressed that way already (see ../README.md, Adaptation 1), so the
# proxy would otherwise intercept loopback traffic between Fabric
# components. Scripts that talk to the network unset it defensively.
unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy 2>/dev/null || true

require_fabric_binaries() {
    for bin in peer orderer cryptogen configtxgen osnadmin; do
        if [ ! -x "$FABRIC_BIN_DIR/bin/$bin" ]; then
            echo "ERROR: $FABRIC_BIN_DIR/bin/$bin not found or not executable." >&2
            echo "Set FABRIC_BIN_DIR to a directory containing Fabric's bin/ and config/" >&2
            echo "(download the native binaries from a Fabric GitHub release -- this" >&2
            echo "project does not use docker-compose/test-network.sh; see" >&2
            echo "../README.md, Adaptation 0, for why)." >&2
            exit 1
        fi
    done
}

mkdir -p "$LOG_DIR"
