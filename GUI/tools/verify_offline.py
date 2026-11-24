"""Portable offline checks. No Gemini requests or victim/CALDERA operations."""
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    commands = [[sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v']]
    candidates = ([shutil.which('node')] if shutil.which('node') else []) + [str(p) for p in (Path.home()/'.nvm/versions/node').glob('*/bin/node')]
    node = None
    for candidate in candidates:
        version = subprocess.run([candidate, '-p', 'process.versions.node'], capture_output=True, text=True, timeout=5)
        if version.returncode == 0 and int(version.stdout.strip().split('.')[0]) >= 20:
            node = candidate; break
    if not node:
        raise SystemExit('Node >=20 required for UI tests. Select an installed runtime; no installation performed.')
    commands.append([node, '--test', 'tests/scenario-ui.test.cjs', 'tests/flow-core.test.cjs'])
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, timeout=120)
        if result.returncode: raise SystemExit(result.returncode)


if __name__ == '__main__': main()
