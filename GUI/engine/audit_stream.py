"""Append-only metadata audit. Never accepts command/output, headers or free text."""
import fcntl
import hashlib
import json
import os
import re
import socket
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = threading.RLock()
ID = re.compile(r'^[\w.:/@+ -]{0,180}$', re.ASCII)
FIELDS = ('run_id','scenario_id','execution_id','operation_id','link_id','ability_id','target','paw','phase','status')


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')


def emit(component, *, root=None, max_bytes=5_000_000, **values):
    """Bounded, allowlisted metadata only; failure propagates to caller for visibility."""
    if component not in ('survey','scenario','execution','collector','marker'):
        raise ValueError('Unknown audit component')
    directory = Path(root) if root is not None else ROOT/'audit'
    if any(p.is_symlink() for p in (directory,*directory.parents)):
        raise ValueError('Audit symlink refused')
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    data = {key: values.get(key) for key in FIELDS}
    for key, value in data.items():
        if value is not None and (not isinstance(value,str) or not ID.fullmatch(value)):
            raise ValueError('Invalid audit identifier: '+key)
    refs = values.get('evidence_refs', [])
    if len(refs)>100 or any(not isinstance(x,str) or not ID.fullmatch(x) or '..' in x for x in refs):
        raise ValueError('Invalid audit evidence reference')
    event = {'schema_version':'soc_audit_v1', 'event_id':str(uuid.uuid4()),
             'timestamp':now(), 'host':socket.gethostname(), 'component':component,
             **data, 'evidence_refs':refs, 'evidence_sha256':values.get('evidence_sha256'),
             'test_marker':bool(values.get('test_marker')), 'redacted':True, 'truncated':False}
    digest = event['evidence_sha256']
    if digest is not None and not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('Invalid evidence hash')
    encoded = (json.dumps({'soc':event},ensure_ascii=True,separators=(',',':'))+'\n').encode()
    with LOCK:
        lockfile=directory/'.lock'
        if lockfile.is_symlink():raise ValueError('Audit lock symlink refused')
        fd=os.open(lockfile,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            path=directory/'events.jsonl'
            if path.is_symlink():raise ValueError('Audit stream symlink refused')
            if path.exists() and path.stat().st_size+len(encoded)>max_bytes:
                path.rename(directory/('events-'+uuid.uuid4().hex+'.jsonl'))
            fd=os.open(path,os.O_CREAT|os.O_APPEND|os.O_WRONLY|os.O_NOFOLLOW,0o640)
            with os.fdopen(fd,'ab') as stream:
                stream.write(encoded);stream.flush();os.fsync(stream.fileno())
    return event


def transition(component, record, previous=None):
    """Only status/phase/link transitions. No prompts, errors, outputs or credentials."""
    fields=('state','status','stage','phase','operation_id')
    signature=lambda row: [row.get(k) for k in fields]+[
        (s.get('index'),s.get('state'),s.get('link_id')) for s in row.get('steps',[])]
    if previous is not None and signature(previous)==signature(record):return None
    values={'phase':record.get('phase') or record.get('stage') or record.get('state'),
            'status':record.get('state') or record.get('status'),
            'target':record.get('target',{}).get('ip') or record.get('request',{}).get('target_ip'),
            'paw':record.get('target',{}).get('paw'), 'operation_id':record.get('operation_id')}
    identifier=record.get('id')
    values[{'survey':'run_id','scenario':'scenario_id','execution':'execution_id'}[component]]=identifier
    if component=='execution':values['scenario_id']=record.get('scenario_job_id')
    values['evidence_refs']=[f'{component}/{identifier}'] if identifier else []
    try:
        settings=json.loads((ROOT/'telemetry_report.json').read_text())
        maximum=min(100_000_000,max(10_000,int(settings.get('audit_max_bytes',5_000_000))))
    except (ValueError,OSError):maximum=5_000_000
    return emit(component,max_bytes=maximum,**values)
