#!/usr/bin/env bash
set -euo pipefail
TASK_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TASK_AGENT_ROOT="${1:-/home/soc/build_scenario_agent}"
python3 "$TASK_SCRIPT_DIR/install_evaluation.py" "$TASK_AGENT_ROOT"
TASK_OUTPUT="$TASK_AGENT_ROOT/outputs/verification_live_$(date +%Y%m%d_%H%M%S)"
set +e
"$TASK_AGENT_ROOT/.venv/bin/python" -B "$TASK_AGENT_ROOT/evaluation/run_verification.py" \
    --agent-root "$TASK_AGENT_ROOT" --output-dir "$TASK_OUTPUT" --live --live-only
TASK_RESULT=$?
set -e
printf '\nEvaluation exit code: %s (0=pass, 1=failed checks, 2=blocked/incomplete).\n' "$TASK_RESULT"
printf 'Results: %s/SUMMARY.md\n' "$TASK_OUTPUT"
exit "$TASK_RESULT"
