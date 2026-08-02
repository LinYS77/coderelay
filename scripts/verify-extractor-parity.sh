#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

PYTHON=${PYTHON:-python3}
export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.26.5}

"$PYTHON" scripts/export-extractor-golden.py --check
"$PYTHON" -m pytest -q tests/test_extractor_golden.py
go test -count=1 -run '^TestGoExtractorMatchesPythonGolden$' ./internal/extractor
