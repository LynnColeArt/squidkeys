#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="${ROOT_DIR}/.tmp"
REFERENCE_REPO="${TMP_DIR}/SquidKeys-original"
VENV_DIR="${TMP_DIR}/python-compat-venv"

mkdir -p "${TMP_DIR}"

PYTHON_SOURCE="${SQUIDKEYS_PYTHON_SOURCE:-${REFERENCE_REPO}/src}"
if [[ ! -f "${PYTHON_SOURCE}/key_store/store.py" ]]; then
  if [[ ! -d "${REFERENCE_REPO}/.git" ]]; then
    git clone --depth 1 https://github.com/LynnColeArt/SquidKeys-python.git "${REFERENCE_REPO}"
  fi
  PYTHON_SOURCE="${REFERENCE_REPO}/src"
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  python3 -m venv "${VENV_DIR}"
fi

"${VENV_DIR}/bin/python" -m pip install --quiet --upgrade pip
"${VENV_DIR}/bin/python" -m pip install --quiet cryptography duckdb

export SQUIDKEYS_PYTHON_BIN="${VENV_DIR}/bin/python"
export SQUIDKEYS_PYTHON_SOURCE="${PYTHON_SOURCE}"

cd "${ROOT_DIR}"
go test ./... -count=1 -run 'Test(PythonWritesGoReads|GoWritesPythonReads|PythonRewrapsGoReads|GoRewrapsPythonReads)$'
