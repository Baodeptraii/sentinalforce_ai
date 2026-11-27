#!/usr/bin/env bash
set -euo pipefail
umask 077
TASK_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TASK_ROOT="$(dirname -- "$TASK_SCRIPT_DIR")"
cd -- "$TASK_ROOT"
mkdir -p outputs/setup .cache/pip
export PIP_CACHE_DIR="$TASK_ROOT/.cache/pip"
export PIP_RETRIES=0
export PIP_TIMEOUT=30
exec > >(tee outputs/setup/setup.log) 2>&1
trap 'printf "\nSetup stopped at line %s; see outputs/setup/setup.log\n" "$LINENO"' ERR
if [[ ! -x .venv/bin/python ]]; then
    python3 -m venv .venv
fi
TASK_PYTHON="$TASK_ROOT/.venv/bin/python"
TASK_TORCH_REQUIREMENT="$(awk '/^torch==/{print; exit}' requirements.lock.txt)"
printf '\n[1/5] Install packaging tools and CPU PyTorch\n'
"$TASK_PYTHON" -m pip install --upgrade pip 'setuptools>=68' wheel 'packaging>=24.2'
if "$TASK_PYTHON" -c 'import sys,importlib.util; sys.exit(1) if importlib.util.find_spec("torch") is None else None; import torch; assert torch.version.cuda is None; assert "torch=="+torch.__version__ == sys.argv[1]; print("CPU PyTorch:",torch.__version__)' "$TASK_TORCH_REQUIREMENT"; then
    :
else
    "$TASK_PYTHON" -m pip install --index-url https://download.pytorch.org/whl/cpu "$TASK_TORCH_REQUIREMENT"
fi
printf '\n[2/5] Install the local package\n'
"$TASK_PYTHON" -m pip install -r requirements.lock.txt
"$TASK_PYTHON" -m pip install --no-deps --no-build-isolation -e .
printf '\n[3/5] Verify bundled sources and index\n'
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 "$TASK_PYTHON" scripts/verify_bundle.py --hybrid
printf '\n[4/5] Run offline tests\n'
"$TASK_PYTHON" -m unittest discover -s tests -v
printf '\n[5/5] Record the installed environment\n'
"$TASK_PYTHON" -m pip freeze > requirements.resolved.txt
printf '\nSetup completed. No Gemini generation or CALDERA operation was requested.\n'
