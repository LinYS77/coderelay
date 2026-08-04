#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

export GOTOOLCHAIN=${CODERELAY_GO_TOOLCHAIN:-go1.26.5}
VERSION=${CODERELAY_VERSION:-1.0.0-phase5.3}
GOOS=${GOOS:-linux}
GOARCH=${GOARCH:-amd64}
OUTPUT=${CODERELAY_GO_OUTPUT:-dist/coderelay}

OUTPUT_DIR=$(dirname -- "$OUTPUT")
OUTPUT_NAME=$(basename -- "$OUTPUT")
mkdir -p "$OUTPUT_DIR"
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
  go build \
  -trimpath \
  -buildvcs=false \
  -tags netgo,osusergo \
  -ldflags "-s -w -X github.com/LinYS77/coderelay/internal/version.Value=${VERSION}" \
  -o "$OUTPUT" \
  ./cmd/coderelay

(
  cd -- "$OUTPUT_DIR"
  sha256sum "$OUTPUT_NAME" > "${OUTPUT_NAME}.sha256"
)
if [[ "$GOOS" == "$(go env GOOS)" && "$GOARCH" == "$(go env GOARCH)" ]]; then
  "$OUTPUT" --version
else
  printf 'built %s/%s; execution skipped on %s/%s\n' "$GOOS" "$GOARCH" "$(go env GOOS)" "$(go env GOARCH)"
fi
(
  cd -- "$OUTPUT_DIR"
  sha256sum -c "${OUTPUT_NAME}.sha256"
)
