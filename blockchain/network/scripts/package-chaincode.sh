#!/bin/bash
# Packages a Node.js chaincode source directory into the external-node
# package format this network's builder (../builders/ccaas) understands:
# metadata.json + code.tar.gz, bundled together.
#
# Deliberately excludes node_modules from code.tar.gz -- installing
# dependencies is the external builder's `build` step's job (npm ci),
# not something baked into the package.
#
# Usage: ./package-chaincode.sh <chaincode_source_dir> <label> <output.tgz>
# Example:
#   ./package-chaincode.sh ../../chaincode provenance_1.0 /tmp/provenance.tgz
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

SOURCE_DIR="$1"
LABEL="$2"
OUTPUT="$3"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/content"
# rsync-free copy, excluding node_modules/test artifacts/local caches.
(cd "$SOURCE_DIR" && tar cf - \
    --exclude='./node_modules' \
    --exclude='./.git' \
    --exclude='./coverage' \
    .) | (cd "$WORK/content" && tar xf -)

(cd "$WORK/content" && tar czf "$WORK/code.tar.gz" .)
printf '{"type":"external-node","label":"%s"}' "$LABEL" > "$WORK/metadata.json"

(cd "$WORK" && tar czf "$OUTPUT" metadata.json code.tar.gz)

echo "==> wrote $OUTPUT (label=$LABEL)"
