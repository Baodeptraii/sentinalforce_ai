#!/usr/bin/env python3
"""Read/export/watch an execution report; optional refresh collects Wazuh only."""
import argparse
import json
import re
import time
from pathlib import Path
from urllib.request import Request, urlopen


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('execution_id')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--refresh',action='store_true',help='Ask the GUI collector to query Wazuh')
    parser.add_argument('--watch',action='store_true',help='Display saved changes until complete/degraded')
    parser.add_argument('--output',type=Path,help='Write the latest JSON report here')
    args=parser.parse_args()
    if not re.fullmatch('[a-f0-9]{32}',args.execution_id):parser.error('Invalid execution ID')
    if not 1<=args.port<=65535:parser.error('Invalid port')
    base='http://127.0.0.1:'+str(args.port)
    path=base+'/api/executions/'+args.execution_id+'/telemetry'
    def get(url):
        with urlopen(url,timeout=15) as response:return json.load(response)
    if args.refresh:
        token=get(base+'/api/meta')['token']
        request=Request(path+'/refresh',data=b'{}',headers={'Content-Type':'application/json','X-Survey-Token':token},method='POST')
        get(request)
        time.sleep(1)
    previous=None
    while True:
        report=get(path)
        stamp=report.get('generated_at')
        if stamp!=previous:
            if args.output:
                args.output.parent.mkdir(parents=True,exist_ok=True)
                args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            print(json.dumps({'execution_id':args.execution_id,'updated_at':stamp,
                'state':report.get('execution_state'),'collection':report['collection'].get('status'),
                'counts':report.get('counts_v2'),'assessment':report.get('assessment')},ensure_ascii=False),flush=True)
            previous=stamp
        if not args.watch or report['collection'].get('status') in ('complete','degraded'):break
        time.sleep(2)


if __name__=='__main__':main()
