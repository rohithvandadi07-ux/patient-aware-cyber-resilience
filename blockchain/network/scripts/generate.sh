#!/bin/bash
# Generates crypto material, the channel genesis block, and the rendered
# peer core.yaml. Safe to re-run: wipes and regenerates everything it owns.
#
# Usage: ./generate.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh
require_fabric_binaries

echo "==> Rendering peer core.yaml from template"
# core.yaml.template is Fabric's own stock sample core.yaml (shipped with
# the binary release) with one line replaced: the externalBuilders path,
# which must be an absolute path and so can't be known until NETWORK_DIR
# is. core.yaml itself is still just the committed template; only the
# rendered copy (peercfg/core.yaml, gitignored) is environment-specific.
sed "s#__EXTERNAL_BUILDER_PATH__#$NETWORK_DIR/builders/ccaas#" \
    "$PEERCFG_DIR/core.yaml.template" > "$PEERCFG_DIR/core.yaml"

echo "==> Wiping previous crypto material and channel artifacts"
rm -rf "$CRYPTO_DIR" "$CHANNEL_ARTIFACTS_DIR"
mkdir -p "$CHANNEL_ARTIFACTS_DIR"

echo "==> cryptogen generate"
"$FABRIC_BIN_DIR/bin/cryptogen" generate --config="$NETWORK_DIR/crypto-config.yaml" --output="$CRYPTO_DIR"

echo "==> configtxgen: channel genesis block ($CHANNEL_NAME)"
FABRIC_CFG_PATH="$NETWORK_DIR" "$FABRIC_BIN_DIR/bin/configtxgen" \
    -profile "$CHANNEL_PROFILE" \
    -outputBlock "$CHANNEL_ARTIFACTS_DIR/$CHANNEL_NAME.block" \
    -channelID "$CHANNEL_NAME"

echo "==> done"
