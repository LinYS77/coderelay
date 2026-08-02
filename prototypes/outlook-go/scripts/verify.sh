#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

export GOTOOLCHAIN=${CODERELAY_PHASE0_TOOLCHAIN:-go1.26.5}

TOOLBIN=""
OUT=""
cleanup() {
  [[ -z "$OUT" ]] || rm -f "$OUT"
  [[ -z "$TOOLBIN" ]] || rm -rf "$TOOLBIN"
}
trap cleanup EXIT

printf '%s\n' "[0/6] toolchain: $(go env GOVERSION)"

printf '%s\n' '[1/6] gofmt'
UNFORMATTED=$(gofmt -l .)
if [[ -n "$UNFORMATTED" ]]; then
  printf '%s\n' "$UNFORMATTED" >&2
  exit 1
fi

printf '%s\n' '[2/6] go vet'
go vet ./...

printf '%s\n' '[3/6] tests'
go test -count=1 ./...

printf '%s\n' '[4/6] race tests'
go test -race -count=1 ./...

printf '%s\n' '[5/6] reachable vulnerability scan'
if ! command -v govulncheck >/dev/null 2>&1; then
  TOOLBIN=$(mktemp -d "${TMPDIR:-/tmp}/coderelay-phase0-tools.XXXXXX")
  GOBIN="$TOOLBIN" go install golang.org/x/vuln/cmd/govulncheck@v1.5.0
  GOVULNCHECK="$TOOLBIN/govulncheck"
else
  GOVULNCHECK=$(command -v govulncheck)
fi
"$GOVULNCHECK" ./...

printf '%s\n' '[6/6] CGO=0 static build'
OUT=$(mktemp "${TMPDIR:-/tmp}/coderelay-outlook-phase0.XXXXXX")
CGO_ENABLED=0 go build -trimpath -o "$OUT" ./cmd/outlook-phase0

printf '%s\n' 'Phase 0 local gate: PASS'
