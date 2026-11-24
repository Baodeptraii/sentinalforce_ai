#!/usr/bin/env python3
"""Review expired *rotated audit* files. Never prune executions, outputs or source logs."""
import argparse,json,re,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
    args=argparse.ArgumentParser(description=__doc__);args.add_argument('--apply',action='store_true');options=args.parse_args()
    config=json.loads((ROOT/'telemetry_report.json').read_text())
    days=min(3650,max(1,int(config.get('retention_days',30))))
    if options.apply and not config.get('retention_delete_enabled',False):raise SystemExit('Deletion disabled; review retention config first.')
    directory=ROOT/'audit'
    if any(p.is_symlink() for p in (directory,*directory.parents)):raise SystemExit('Symlink refused')
    candidates=[p for p in directory.glob('events-*.jsonl') if re.fullmatch(r'events-[a-f0-9]{32}\.jsonl',p.name) and not p.is_symlink() and p.is_file() and time.time()-p.stat().st_mtime>days*86400]
    for path in candidates:
        if options.apply:path.unlink()
    print(json.dumps({'dry_run':not options.apply,'retention_days':days,'count':len(candidates),'files':[p.name for p in candidates]}))

if __name__=='__main__':main()
