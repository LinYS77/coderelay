#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

export GOTOOLCHAIN=${CODERELAY_GO_TOOLCHAIN:-go1.26.5}
TOOL_VERSION=v1.10.0
VERSION=${CODERELAY_VERSION:-1.0.0-phase5.4}
BINARY=${CODERELAY_GO_OUTPUT:-dist/coderelay}
OUTPUT=${CODERELAY_SBOM_OUTPUT:-${BINARY}.cdx.json}

if [[ ! -x "$BINARY" ]]; then
  printf 'binary is missing or not executable: %s\n' "$BINARY" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$OUTPUT")"
OUTPUT_DIR=$(dirname -- "$OUTPUT")
OUTPUT_NAME=$(basename -- "$OUTPUT")
go run "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@${TOOL_VERSION}" \
  bin \
  -json \
  -output-version 1.6 \
  -version "$VERSION" \
  -output "$OUTPUT" \
  "$BINARY"

grep -q '"bomFormat": "CycloneDX"' "$OUTPUT"
grep -q '"specVersion": "1.6"' "$OUTPUT"
grep -q '"components"' "$OUTPUT"
(
  cd -- "$OUTPUT_DIR"
  sha256sum "$OUTPUT_NAME" > "${OUTPUT_NAME}.sha256"
  sha256sum -c "${OUTPUT_NAME}.sha256"
)
printf 'CycloneDX SBOM: %s\n' "$OUTPUT"
