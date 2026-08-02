#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

export GOTOOLCHAIN=${CODERELAY_GO_TOOLCHAIN:-go1.26.5}
export GOMAXPROCS=1
OUT=${CODERELAY_PROFILE_DIR:-/tmp/coderelay-phase5-pprof}
BENCHTIME=${CODERELAY_PROFILE_TIME:-10s}
mkdir -p "$OUT"
chmod 700 "$OUT"

CPU="$OUT/cpu.prof"
HEAP="$OUT/heap.prof"
CPU_TOP="$OUT/cpu-top.txt"
HEAP_TOP="$OUT/heap-top.txt"

go test ./internal/api \
  -run '^$' \
  -bench '^BenchmarkPhase5TOTPHandler$' \
  -benchtime "$BENCHTIME" \
  -count 1 \
  -cpuprofile "$CPU" \
  -memprofile "$HEAP"

test -s "$CPU"
test -s "$HEAP"
go tool pprof -top -nodecount=30 "$CPU" > "$CPU_TOP"
go tool pprof -top -nodecount=30 -sample_index=alloc_space "$HEAP" > "$HEAP_TOP"

printf 'CPU profile:  %s\n' "$CPU"
printf 'Heap profile: %s\n' "$HEAP"
printf 'CPU top:      %s\n' "$CPU_TOP"
printf 'Heap top:     %s\n' "$HEAP_TOP"
