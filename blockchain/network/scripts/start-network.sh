#!/bin/bash
# Starts the orderer and both peers (as background processes, native
# binaries, no Docker), joins the orderer and both peers to the channel.
# Run ./generate.sh first. Safe to re-run against an already-generated
# network as long as ./reset.sh was run in between if you want a clean
# ledger.
#
# Usage: ./start-network.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
require_fabric_binaries

wait_for_port() {
    local addr="$1" tries=0
    local host="${addr%%:*}" port="${addr##*:}"
    while ! (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 60 ]; then
            echo "ERROR: timed out waiting for $addr" >&2
            return 1
        fi
        sleep 0.5
    done
    exec 3>&- 2>/dev/null || true
}

start_orderer() {
    echo "==> Starting orderer"
    (
        export FABRIC_CFG_PATH="$FABRIC_BIN_DIR/config"
        export ORDERER_GENERAL_LISTENADDRESS=127.0.0.1
        export ORDERER_GENERAL_LISTENPORT=7050
        export ORDERER_GENERAL_LOCALMSPID=OrdererMSP
        export ORDERER_GENERAL_LOCALMSPDIR="$ORDERER_TLS_DIR/../msp"
        export ORDERER_GENERAL_BOOTSTRAPMETHOD=none
        export ORDERER_CHANNELPARTICIPATION_ENABLED=true
        export ORDERER_ADMIN_TLS_ENABLED=true
        export ORDERER_ADMIN_TLS_CLIENTAUTHREQUIRED=true
        export ORDERER_ADMIN_TLS_CERTIFICATE="$ORDERER_TLS_DIR/server.crt"
        export ORDERER_ADMIN_TLS_PRIVATEKEY="$ORDERER_TLS_DIR/server.key"
        export ORDERER_ADMIN_TLS_ROOTCAS="[$ORDERER_TLS_DIR/ca.crt]"
        export ORDERER_ADMIN_TLS_CLIENTROOTCAS="[$ORDERER_TLS_DIR/ca.crt]"
        export ORDERER_ADMIN_LISTENADDRESS="$ORDERER_ADMIN_ADDR"
        export ORDERER_GENERAL_TLS_ENABLED=true
        export ORDERER_GENERAL_TLS_CERTIFICATE="$ORDERER_TLS_DIR/server.crt"
        export ORDERER_GENERAL_TLS_PRIVATEKEY="$ORDERER_TLS_DIR/server.key"
        export ORDERER_GENERAL_TLS_ROOTCAS="[$ORDERER_TLS_DIR/ca.crt]"
        export ORDERER_FILELEDGER_LOCATION="$RUN_DIR/orderer/ledger"
        export ORDERER_OPERATIONS_LISTENADDRESS=127.0.0.1:9440
        mkdir -p "$ORDERER_FILELEDGER_LOCATION"
        setsid nohup "$FABRIC_BIN_DIR/bin/orderer" >"$LOG_DIR/orderer.log" 2>&1 < /dev/null &
        disown
    )
    wait_for_port "$ORDERER_ADMIN_ADDR"
}

start_peer() {
    local org_label="$1" mspid="$2" peer_addr="$3" cc_addr="$4" ops_addr="$5" \
        peer_msp="$6" peer_tls="$7" data_dir="$8"
    echo "==> Starting peer ($org_label)"
    (
        export FABRIC_CFG_PATH="$PEERCFG_DIR"
        export CORE_PEER_ID="$org_label"
        export CORE_PEER_ADDRESS="$peer_addr"
        export CORE_PEER_LISTENADDRESS="$peer_addr"
        export CORE_PEER_CHAINCODEADDRESS="$cc_addr"
        export CORE_PEER_CHAINCODELISTENADDRESS="$cc_addr"
        export CORE_PEER_GOSSIP_BOOTSTRAP="$peer_addr"
        export CORE_PEER_GOSSIP_EXTERNALENDPOINT="$peer_addr"
        export CORE_PEER_GOSSIP_USELEADERELECTION=true
        export CORE_PEER_GOSSIP_ORGLEADER=false
        export CORE_PEER_LOCALMSPID="$mspid"
        export CORE_PEER_MSPCONFIGPATH="$peer_msp"
        export CORE_PEER_TLS_ENABLED=true
        export CORE_PEER_TLS_CERT_FILE="$peer_tls/server.crt"
        export CORE_PEER_TLS_KEY_FILE="$peer_tls/server.key"
        export CORE_PEER_TLS_ROOTCERT_FILE="$peer_tls/ca.crt"
        export CORE_PEER_FILESYSTEMPATH="$data_dir"
        export CORE_LEDGER_STATE_STATEDATABASE=goleveldb
        export CORE_OPERATIONS_LISTENADDRESS="$ops_addr"
        export CORE_PEER_PROFILE_ENABLED=false
        mkdir -p "$CORE_PEER_FILESYSTEMPATH"
        setsid nohup "$FABRIC_BIN_DIR/bin/peer" node start \
            >"$LOG_DIR/peer-$org_label.log" 2>&1 < /dev/null &
        disown
    )
    wait_for_port "$peer_addr"
}

join_channel_as_peer() {
    local mspid="$1" peer_addr="$2" peer_tls_ca="$3" admin_msp="$4"
    FABRIC_CFG_PATH="$PEERCFG_DIR" \
    CORE_PEER_LOCALMSPID="$mspid" \
    CORE_PEER_MSPCONFIGPATH="$admin_msp" \
    CORE_PEER_ADDRESS="$peer_addr" \
    CORE_PEER_TLS_ENABLED=true \
    CORE_PEER_TLS_ROOTCERT_FILE="$peer_tls_ca" \
    "$FABRIC_BIN_DIR/bin/peer" channel join -b "$CHANNEL_ARTIFACTS_DIR/$CHANNEL_NAME.block"
}

start_orderer

echo "==> Joining channel at the orderer (osnadmin)"
"$FABRIC_BIN_DIR/bin/osnadmin" channel join \
    --channelID "$CHANNEL_NAME" \
    --config-block "$CHANNEL_ARTIFACTS_DIR/$CHANNEL_NAME.block" \
    -o "$ORDERER_ADMIN_ADDR" \
    --ca-file "$ORDERER_TLS_DIR/ca.crt" \
    --client-cert "$ORDERER_TLS_DIR/server.crt" \
    --client-key "$ORDERER_TLS_DIR/server.key"

start_peer HospitalOrg "$HOSPITAL_MSPID" "$HOSPITAL_PEER_ADDR" "$HOSPITAL_CC_ADDR" \
    "$HOSPITAL_OPS_ADDR" "$HOSPITAL_PEER_MSP" "$HOSPITAL_PEER_TLS" "$RUN_DIR/peer0-hospital/data"

start_peer SecurityOpsOrg "$SECURITYOPS_MSPID" "$SECURITYOPS_PEER_ADDR" "$SECURITYOPS_CC_ADDR" \
    "$SECURITYOPS_OPS_ADDR" "$SECURITYOPS_PEER_MSP" "$SECURITYOPS_PEER_TLS" "$RUN_DIR/peer0-securityops/data"

echo "==> Joining Hospital peer to channel"
join_channel_as_peer "$HOSPITAL_MSPID" "$HOSPITAL_PEER_ADDR" "$HOSPITAL_PEER_TLS/ca.crt" "$HOSPITAL_ADMIN_MSP"

echo "==> Joining SecurityOps peer to channel"
join_channel_as_peer "$SECURITYOPS_MSPID" "$SECURITYOPS_PEER_ADDR" "$SECURITYOPS_PEER_TLS/ca.crt" "$SECURITYOPS_ADMIN_MSP"

echo "==> Network up. Logs in $LOG_DIR"
