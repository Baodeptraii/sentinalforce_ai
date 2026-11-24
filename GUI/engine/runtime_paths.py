import os
import sys
from pathlib import Path


def scenario_root(config):
    configured = config.get('scenario_root') if isinstance(config, dict) else None
    return Path(configured).expanduser().resolve() if configured else Path(__file__).resolve().parents[2] / 'scenario_agent'


def python_executable(root):
    root = Path(root)
    candidates = [root / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'), Path(sys.executable)]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def ensure_runtime(root):
    root = Path(root)
    if not root.is_dir() or not (root / 'scenario_agent').is_dir():
        raise ValueError('Scenario runtime unavailable.')
    return root, python_executable(root)


def resolve_runtime(config):
    root = scenario_root(config)
    return ensure_runtime(root)

# ponytail: keep path selection in one module; add platform-specific launch policy only when deployment needs isolation.
