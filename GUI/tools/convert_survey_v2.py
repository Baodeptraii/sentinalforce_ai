#!/usr/bin/env python3
"""Convert a historical run offline into a new directory."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine.survey_output_v2 import convert, bundle_v2, select_context, Context, Profile, Handoff

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--bundle', action='store_true')
    parser.add_argument('--example-subject', action='append')
    args = parser.parse_args()
    context = convert(args.source, args.destination)
    if args.bundle: args.destination.with_suffix('.zip').write_bytes(bundle_v2(args.destination))
    if args.example_subject:
        args.destination.with_suffix('.example.json').write_text(json.dumps(select_context(context, ['web', 'authentication'], args.example_subject), ensure_ascii=False, indent=2))
    print(json.dumps({'destination': str(args.destination), 'facts': len(context['observations']), 'gaps': len(context['gaps'])}))
