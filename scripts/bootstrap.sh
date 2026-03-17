#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${PYTHON:-python3}"

if [[ ! -d "${VENV_DIR}" ]]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

python -m pip install --upgrade pip
python -m pip install -e "${ROOT_DIR}[dev]"

if [[ ! -f "${ROOT_DIR}/config/settings.yaml" || ! -f "${ROOT_DIR}/config/review_rules.yaml" || ! -f "${ROOT_DIR}/.env" ]]; then
  cp-review init --target-dir "${ROOT_DIR}"
fi

cp-review doctor --config "${ROOT_DIR}/config/settings.yaml" --offline

cat <<EOF

Bootstrap complete.

Next steps:
  1. Update ${ROOT_DIR}/.env with read-only API credentials
  2. Review ${ROOT_DIR}/config/settings.yaml
  3. Run: cp-review run --config ${ROOT_DIR}/config/settings.yaml

EOF
