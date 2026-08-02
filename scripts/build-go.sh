#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

export GOTOOLCHAIN=${CODERELAY_GO_TOOLCHAIN:-go1.26.5}
VERSION=${CODERELAY_VERSION:-1.0.0-phase2}
GOOS=${GOOS:-linux}
GOARCH=${GOARCH:-amd64}
OUTPUT=${CODERELAY_GO_OUTPUT:-dist/coderelay-go}

mkdir -p "$(dirname -- "$OUTPUT")"
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
  go build \
  -trimpath \
  -tags netgo,osusergo \
  -ldflags "-s -w -X github.com/LinYS77/coderelay/internal/version.Value=${VERSION}" \
  -o "$OUTPUT" \
  ./cmd/coderelay

sha256sum "$OUTPUT" > "${OUTPUT}.sha256"
if [[ "$GOOS" == "$(go env GOOS)" && "$GOARCH" == "$(go env GOARCH)" ]]; then
  "$OUTPUT" --version
else
  printf 'built %s/%s; execution skipped on %s/%s\n' "$GOOS" "$GOARCH" "$(go env GOOS)" "$(go env GOARCH)"
fi
sha256sum -c "${OUTPUT}.sha256"
