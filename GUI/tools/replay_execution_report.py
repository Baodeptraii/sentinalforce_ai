#!/usr/bin/env python3
"""Explicit bounded Wazuh refresh or cached export. Never invokes CALDERA dispatch."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import execution_telemetry as telemetry

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('execution_id')
parser.add_argument('--refresh', action='store_true', help='Read Wazuh using saved historical execution window')
args = parser.parse_args()
if args.refresh:
    telemetry.collect(args.execution_id)
report = telemetry.read(args.execution_id)
print(json.dumps({key: report.get(key) for key in ('execution_id', 'operation_id', 'counts_v2',
    'command_status', 'behavior_status', 'operations')}, ensure_ascii=False, indent=2))
