#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

umask 077
export GOTOOLCHAIN=${CODERELAY_PHASE0_TOOLCHAIN:-go1.26.5}

exec go run ./cmd/outlook-phase0 real "$@"
