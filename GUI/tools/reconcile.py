"""Inspect CALDERA state using GET only, then resolve a local cleanup journal."""
import argparse
import json
from pathlib import Path
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine.survey import api_for, load_config, now
from engine.runner import save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id', help='32-character survey run ID under GUI/outputs')
    args = parser.parse_args()
    if len(args.run_id) != 32 or any(c not in '0123456789abcdef' for c in args.run_id):
        parser.error('Invalid run ID')
    directory = ROOT / 'outputs' / args.run_id
    path = directory / 'caldera/summary.json'
    summary = json.loads(path.read_text())
    api = api_for(load_config()); api.deadline = time.monotonic() + 30
    agent = api.call('agents/' + quote(summary['paw'], safe=''))
    if agent.get('group') != summary.get('original_group'):
        raise SystemExit('Agent group differs from original_group; inspect CALDERA. No remote changes made.')
    operations = api.call('operations')
    related = [op for op in operations if op.get('id') == summary.get('operation_id') or op.get('group') == summary.get('temporary_group') or any(a.get('paw') == summary['paw'] for a in op.get('host_group', []))]
    if any(op.get('state') not in ('finished', 'out_of_time') for op in related):
        raise SystemExit('Endpoint has an unfinished operation; inspect CALDERA. No remote changes made.')
    summary.update(group_restored=True, cleanup_required=False, recovery_required=False,
                   reconciliation={'checked_at': now(), 'mode': 'read_only_api', 'operation_states': [op.get('state') for op in related]})
    save(path, summary)
    # Keep the watchdog evidence, mark its resolution rather than delete it.
    marker = directory / 'recovery_required.json'
    if marker.exists():
        evidence = json.loads(marker.read_text()); evidence['resolved_at'] = now(); save(marker, evidence)
    print('Local journal reconciled. No CALDERA operation or agent was modified.')


if __name__ == '__main__': main()
