#!/usr/bin/env bash
# Run from the user's terminal with Internet access. Never prints or sources .env.
set -euo pipefail
umask 077

TASK_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TASK_ROOT="$(dirname -- "$TASK_SCRIPT_DIR")"
cd -- "$TASK_ROOT"
mkdir -p reports/implementation .cache/pip
export PIP_CACHE_DIR="$TASK_ROOT/.cache/pip"
export PIP_RETRIES=0
export PIP_TIMEOUT=30

# Captures only commands' normal output; no set -x or key values.
if [[ -f reports/implementation/setup.log ]]; then
    cp reports/implementation/setup.log reports/implementation/setup.previous.log
fi
exec > >(tee reports/implementation/setup.log) 2>&1
trap 'printf "\nSetup stopped at line %s; see reports/implementation/setup.log\n" "$LINENO"' ERR

if [[ ! -x .venv/bin/python ]]; then
    python3 -m venv --system-site-packages .venv
fi
TASK_PYTHON="$TASK_ROOT/.venv/bin/python"

printf '\n[1/5] Install CPU PyTorch\n'
if "$TASK_PYTHON" -c 'import torch; assert torch.version.cuda is None; print("CPU PyTorch already installed:", torch.__version__)'; then
    :
else
    "$TASK_PYTHON" -m pip install --index-url https://download.pytorch.org/whl/cpu torch
fi
printf '\n[2/5] Install Scenario Agent dependencies\n'
# Build with the explicitly installed backend, rather than a separate isolated
# environment that may resolve/import a different setuptools implementation.
"$TASK_PYTHON" -m pip install --upgrade pip 'setuptools>=68' wheel 'packaging>=24.2'
"$TASK_PYTHON" -m pip install --no-build-isolation -e .
printf '\n[3/5] Check configuration and prepare corpus\n'
"$TASK_PYTHON" -m scenario_agent doctor
"$TASK_PYTHON" -m scenario_agent prepare-corpus
printf '\n[4/5] Download E5 and build FAISS index\n'
"$TASK_PYTHON" -m scenario_agent build-index
printf '\n[5/5] Test and refresh the DOCX report\n'
"$TASK_PYTHON" scripts/build_implementation_report.py
"$TASK_PYTHON" -m pip freeze > requirements.resolved.txt
printf '\nSetup completed. No Gemini generation or CALDERA execution was requested.\n'
printf 'Next: .venv/bin/python -m scenario_agent run --text '\''Khảo sát người dùng Windows trên endpoint để đánh giá SOC, tối đa 1 test.'\''\n'
