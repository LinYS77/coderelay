#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv-build}"

"$PYTHON_BIN" -m venv --clear "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
if [[ -f requirements.lock ]]; then
  "$VENV_DIR/bin/python" -m pip install -r requirements.lock
  "$VENV_DIR/bin/python" -m pip install --no-deps .
else
  "$VENV_DIR/bin/python" -m pip install '.[dev]'
fi
"$VENV_DIR/bin/python" -m PyInstaller --clean --noconfirm coderelay.spec
(
  cd dist
  sha256sum coderelay > coderelay.sha256
)

printf '\nBuilt executable: %s/dist/coderelay\n' "$PWD"
printf 'Checksum file: %s/dist/coderelay.sha256\n' "$PWD"
"$PWD/dist/coderelay" --version
