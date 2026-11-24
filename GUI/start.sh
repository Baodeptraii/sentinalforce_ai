#!/usr/bin/env bash
set -euo pipefail
GUI_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
GUI_PYTHON="$GUI_ROOT/.venv/bin/python"
if [[ ! -x "$GUI_PYTHON" ]]; then
  printf '%s\n' 'Thiếu GUI/.venv/bin/python. Chuẩn bị virtualenv GUI theo README.' >&2
  exit 1
fi
cd -- "$GUI_ROOT"
export SURVEY_CONFIG_FILE="$GUI_ROOT/config.json"
export PYTHONPATH="$(dirname "$GUI_ROOT")${PYTHONPATH:+:$PYTHONPATH}"
exec "$GUI_PYTHON" -B "$GUI_ROOT/app.py" "$@"
