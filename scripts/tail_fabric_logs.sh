#!/usr/bin/env bash
# Tails the real log files the native-binary Fabric network
# (blockchain/network/) writes while running, started by
# blockchain/network/scripts/start-network.sh. See blockchain/network/README.md
# for how that network is brought up and torn down -- this script only
# reads its logs, it never starts/stops anything.
#
# Usage:
#   ./scripts/tail_fabric_logs.sh              # tail all three logs together
#   ./scripts/tail_fabric_logs.sh orderer      # tail just the orderer
#   ./scripts/tail_fabric_logs.sh peer-HospitalOrg
#   ./scripts/tail_fabric_logs.sh peer-SecurityOpsOrg

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$REPO_ROOT/blockchain/network/logs"

if [ ! -d "$LOG_DIR" ]; then
  echo "No log directory at $LOG_DIR -- the network hasn't been started yet." >&2
  echo "Run blockchain/network/scripts/start-network.sh first (see blockchain/network/README.md)." >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  files=("$LOG_DIR"/orderer.log "$LOG_DIR"/peer-HospitalOrg.log "$LOG_DIR"/peer-SecurityOpsOrg.log)
  existing=()
  for f in "${files[@]}"; do
    [ -f "$f" ] && existing+=("$f")
  done
  if [ "${#existing[@]}" -eq 0 ]; then
    echo "No log files found in $LOG_DIR yet." >&2
    exit 1
  fi
  exec tail -n 20 -F "${existing[@]}"
else
  target="$LOG_DIR/$1.log"
  if [ ! -f "$target" ]; then
    echo "No such log file: $target" >&2
    echo "Available logs in $LOG_DIR:" >&2
    ls "$LOG_DIR"/*.log 1>&2 2>/dev/null || echo "  (none)" >&2
    exit 1
  fi
  exec tail -n 50 -F "$target"
fi
