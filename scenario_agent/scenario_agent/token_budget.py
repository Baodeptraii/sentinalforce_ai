"""Shared stdlib-only budget ledger for Scenario and Survey. Never stores prompts/keys."""
import contextlib
import hashlib
import json
import math
import os
import sqlite3
import time
import uuid
from pathlib import Path

VERSION='soc_llm_budget_v1'
DEFAULTS={'parse_input':49152,'ground_behaviors_input':73728,'build_plan_input':81920,'survey_input':32768,
          'parse_output':2048,'ground_behaviors_output':4096,'build_plan_output':12288,'survey_output':1000,
          'run_tokens':180000,'run_requests':8,'run_seconds':1800,'window_tokens':100000,'window_requests':6,'window_seconds':60,
          'lease_seconds':660}


def settings():
    path=Path(os.getenv('SOC_LLM_BUDGET_CONFIG','/home/soc/DATN/GUI/llm_budget.json'))
    values=json.loads(path.read_text()) if path.is_file() else {}
    if not isinstance(values,dict) or any(k not in DEFAULTS for k in values):raise ValueError('Unknown shared LLM budget config field')
    result={k:int(os.getenv('SOC_LLM_'+k.upper(),str(values.get(k,v)))) for k,v in DEFAULTS.items()}
    if any(v<1 for v in result.values()):raise ValueError('SOC_LLM limits must be positive')
    return result


def estimate(parts):
    sizes={k:len((v if isinstance(v,str) else json.dumps(v,ensure_ascii=False,separators=(',',':'))).encode()) for k,v in parts.items()}
    total=sum(sizes.values())
    return {'kind':'estimated_utf8_allowance','components_bytes':sizes,'payload_bytes':total,
            'input_tokens_estimated_lower':math.ceil(total/6),'input_tokens_reserved':total+512,
            'limitation':'UTF-8 byte allowance +512 overhead, not a tokenizer or exact token count; Unicode/schema overhead may differ.'}


class BudgetWait(RuntimeError):
    def __init__(self,reason,retry_at=None,details=None):
        self.reason=reason;self.retry_at=retry_at;self.details=details or {}
        super().__init__('LLM budget: '+reason)


def usage_fields(value,provider='gemini'):
    def field(obj,name):return obj.get(name) if isinstance(obj,dict) else getattr(obj,name,None)
    if provider=='gemini':
        names={'input_tokens':'prompt_token_count','output_tokens':'candidates_token_count','cached_tokens':'cached_content_token_count',
               'thinking_tokens':'thoughts_token_count','total_tokens':'total_token_count'}
        return {key:(v if type(v:=field(value,name)) is int and v>=0 else None) for key,name in names.items()}
    result={key:(v if type(v:=field(value,name)) is int and v>=0 else None) for key,name in
            {'input_tokens':'prompt_tokens','output_tokens':'completion_tokens','total_tokens':'total_tokens'}.items()}
    result['cached_tokens']=field(field(value,'prompt_tokens_details') or {},'cached_tokens')
    result['thinking_tokens']=field(field(value,'completion_tokens_details') or {},'reasoning_tokens')
    return {k:v if type(v) is int and v>=0 else None for k,v in result.items()}


class Ledger:
    def __init__(self,path=None,clock=time.time):
        self.path=Path(path or os.getenv('SOC_LLM_BUDGET_DB',str(Path.home()/'.cache/datn-llm/budget.sqlite')))
        self.clock=clock
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.db() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS calls(
              id TEXT PRIMARY KEY, namespace TEXT, model TEXT, run TEXT, phase TEXT, fingerprint TEXT,
              created REAL, lease REAL, status TEXT, reserved INTEGER, charged INTEGER, metadata TEXT);
              CREATE INDEX IF NOT EXISTS calls_scope ON calls(namespace,model,created);
              CREATE INDEX IF NOT EXISTS calls_run ON calls(run);
              CREATE TABLE IF NOT EXISTS cooldown(namespace TEXT, model TEXT, until REAL, PRIMARY KEY(namespace,model));
              CREATE TABLE IF NOT EXISTS counts(model TEXT, fingerprint TEXT, tokens INTEGER, at REAL, PRIMARY KEY(model,fingerprint));''')
    @contextlib.contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=15,isolation_level=None)
        db.row_factory=sqlite3.Row
        try:yield db
        finally:db.close()
    def reserve(self,model,run,phase,fingerprint,input_tokens,output_tokens,metadata=None):
        config=settings();now=self.clock();namespace=os.getenv('SOC_LLM_BUDGET_GROUP','soc-shared-project')
        model=model.removeprefix('models/');amount=input_tokens+output_tokens
        if input_tokens>config.get(phase+'_input',config['build_plan_input']):raise BudgetWait('phase_input_limit',details={'input_tokens_reserved':input_tokens,'limit':config.get(phase+'_input')})
        if amount>config['window_tokens']:raise BudgetWait('request_exceeds_window',details={'reserved':amount})
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute("UPDATE calls SET status='abandoned_unknown' WHERE status='inflight' AND lease<=?",(now,))
                rows=[dict(r) for r in db.execute('SELECT * FROM calls WHERE namespace=? AND model=? AND (run=? OR status=\'inflight\' OR created>?)',(namespace,model,run,now-config['window_seconds']))]
                same=[r for r in rows if r['run']==run and r['fingerprint']==fingerprint and r['phase']==phase and r['status'] in ('inflight','success')]
                if same:raise BudgetWait('duplicate_inflight_or_completed',retry_at=max(r['lease'] for r in same) if any(r['status']=='inflight' for r in same) else None)
                run_rows=[r for r in rows if r['run']==run]
                if len(run_rows)>=config['run_requests']:raise BudgetWait('run_request_limit')
                if sum(r['charged'] for r in run_rows)+amount>config['run_tokens']:raise BudgetWait('run_token_limit')
                seconds=sum((now-r['created']) if r['status']=='inflight' else (json.loads(r['metadata']).get('duration_seconds') or 0) for r in run_rows)
                if seconds>=config['run_seconds']:raise BudgetWait('run_time_limit')
                cooldown=db.execute('SELECT until FROM cooldown WHERE namespace=? AND model=?',(namespace,model)).fetchone()
                if cooldown and cooldown['until']>now:
                    latest=next((json.loads(r['metadata']).get('error') for r in reversed(rows) if json.loads(r['metadata']).get('error')),{})
                    raise BudgetWait('provider_cooldown',cooldown['until'],{'previous_provider_error':latest})
                active=[r for r in rows if r['status']=='inflight' or r['created']>now-config['window_seconds']]
                if len(active)>=config['window_requests'] or sum(r['charged'] for r in active)+amount>config['window_tokens']:
                    retry=max(now+1,min((r['lease'] if r['status']=='inflight' else r['created']+config['window_seconds']) for r in active))
                    raise BudgetWait('shared_window_limit',retry)
                identifier=uuid.uuid4().hex
                info={**(metadata or {}),'schema_version':VERSION,'phase':phase,'model':model,'run_id':run,'attempt':len([r for r in run_rows if r['phase']==phase])+1,
                      'input_tokens_reserved':input_tokens,'output_tokens_limit':output_tokens,'usage':usage_fields(None)}
                db.execute('INSERT INTO calls VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                    (identifier,namespace,model,run,phase,fingerprint,now,now+config['lease_seconds'],'inflight',amount,amount,json.dumps(info)))
                db.execute('COMMIT');return identifier
            except Exception:
                db.execute('ROLLBACK');raise
    def finish(self,identifier,status,usage=None,error=None,duration=None,retry_after=None):
        usage=usage or usage_fields(None)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM calls WHERE id=?',(identifier,)).fetchone()
            info=json.loads(row['metadata']);info.update(status=status,usage=usage,error=error,duration_seconds=duration,
                usage_complete=type(usage.get('total_tokens')) is int)
            charged=usage['total_tokens'] if type(usage.get('total_tokens')) is int else row['reserved']
            db.execute('UPDATE calls SET status=?,charged=?,metadata=? WHERE id=?',(status,charged,json.dumps(info),identifier))
            if retry_after:
                until=self.clock()+retry_after
                db.execute('INSERT INTO cooldown VALUES(?,?,?) ON CONFLICT(namespace,model) DO UPDATE SET until=MAX(until,excluded.until)',(row['namespace'],row['model'],until))
            db.execute('COMMIT')
    def metrics(self,run):
        with self.db() as db:
            rows=list(db.execute('SELECT * FROM calls WHERE run=? ORDER BY created',(run,)))
        calls=[dict(json.loads(r['metadata']),request_id=r['id'],status=r['status'],charged_tokens=r['charged'],created_at_epoch=r['created']) for r in rows]
        known=[c['usage']['total_tokens'] for c in calls if type(c['usage'].get('total_tokens')) is int]
        return {'schema_version':VERSION,'run_id':run,'requests':len(calls),'actual_total_tokens':sum(known) if known else None,'actual_total_complete':bool(calls) and len(known)==len(calls),
                'unknown_usage_requests':sum(c['usage'].get('total_tokens') is None for c in calls),'charged_tokens':sum(r['charged'] for r in rows),'calls':calls,
                'limitation':'Internal ledger sees participating apps only; actual total excludes unknown calls and is not billing/AI Studio TPM.'}
    def remaining_seconds(self,run):
        with self.db() as db:rows=list(db.execute('SELECT * FROM calls WHERE run=?',(run,)))
        used=sum((self.clock()-r['created']) if r['status']=='inflight' else (json.loads(r['metadata']).get('duration_seconds') or 0) for r in rows)
        return max(1,settings()['run_seconds']-used)

    def seed_legacy(self,run,model,worker_log):
        # Only import response/HTTP markers, never prompt/provider message text.
        import re
        if not Path(worker_log).is_file():return
        content=Path(worker_log).read_text(errors='replace')[-200000:]
        phases=re.findall(r'\[Gemini\] (parse|ground_behaviors|build_plan): (?:HTTP \d+; attempt=|response received)',content)
        if not phases:return
        namespace=os.getenv('SOC_LLM_BUDGET_GROUP','soc-shared-project');model=model.removeprefix('models/');limits=settings()
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM calls WHERE run=?',(run,)).fetchone():db.execute('ROLLBACK');return
            stamp=Path(worker_log).stat().st_mtime
            for n,phase in enumerate(phases):
                amount=limits[phase+'_input']+limits[phase+'_output']
                info={'schema_version':VERSION,'phase':phase,'model':model,'run_id':run,'attempt':n+1,'request_kind':'legacy_unmetered',
                      'usage':usage_fields(None),'usage_complete':False,'historical_request_observed':True,
                      'limitation':'Legacy marker proves a response attempt, not token consumption. Charged conservative current phase allowance; timestamp is worker.log mtime.'}
                db.execute('INSERT INTO calls VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(uuid.uuid4().hex,namespace,model,run,phase,'legacy:'+str(n),stamp,stamp,
                        'legacy_unknown',amount,amount,json.dumps(info)))
            db.execute('COMMIT')

    def count_get(self,model,fingerprint):
        with self.db() as db:row=db.execute('SELECT tokens,at FROM counts WHERE model=? AND fingerprint=?',(model,fingerprint)).fetchone()
        return row['tokens'] if row and self.clock()-row['at']<86400 else None
    def count_put(self,model,fingerprint,tokens):
        with self.db() as db:db.execute('INSERT OR REPLACE INTO counts VALUES(?,?,?,?)',(model,fingerprint,tokens,self.clock()))


@contextlib.contextmanager
def run_lock(root,run_id):
    import fcntl
    path=Path(root)/'.llm-locks'/hashlib.sha256(run_id.encode()).hexdigest();path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a') as f:
        try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:raise BudgetWait('run_already_active',time.time()+30) from None
        yield


def provider_details(error,headers=None):
    """Only structured retry/quota fields; never headers, prompts or arbitrary error bodies."""
    code=getattr(error,'code',None)
    payload=getattr(error,'response_json',None) or {}
    if isinstance(error,dict):payload=error
    elif not payload and isinstance(getattr(error,'details',None),dict):payload=error.details
    if not isinstance(payload,dict):payload={}
    body=payload.get('error',payload)
    details=body.get('details',[]) if isinstance(body,dict) else []
    if not details:details=getattr(error,'details',[]) or []
    result={'http_status':code if type(code) is int else body.get('code') if isinstance(body,dict) else None,
            'provider_status':str(getattr(error,'status',None) or body.get('status','UNKNOWN'))[:80],
            'retry_after_seconds':None,'quota_violations':[]}
    for row in details if isinstance(details,list) else []:
        if not isinstance(row,dict):continue
        if str(row.get('@type','')).endswith('RetryInfo'):
            delay=row.get('retryDelay')
            try:
                seconds=float(delay.removesuffix('s')) if isinstance(delay,str) else float(delay.get('seconds',0))+float(delay.get('nanos',0))/1e9
                if 0<=seconds<=86400:result['retry_after_seconds']=math.ceil(seconds)
            except (ValueError,TypeError,AttributeError):pass
        for violation in row.get('violations',[])[:16]:
            if isinstance(violation,dict):result['quota_violations'].append({k:str(violation[k])[:160] for k in ('quotaMetric','quotaId') if k in violation})
    raw=(headers or {}).get('Retry-After') or (headers or {}).get('retry-after')
    if raw:
        try:delay=max(0,float(raw))
        except (ValueError,TypeError):
            try:
                from email.utils import parsedate_to_datetime
                delay=max(0,parsedate_to_datetime(raw).timestamp()-time.time())
            except (ValueError,TypeError,OverflowError):delay=0
        result['retry_after_seconds']=max(result['retry_after_seconds'] or 0,min(86400,math.ceil(delay)))
    return result


def safe_provider_summary(message):
    """Categorize diagnostics without persisting provider-echoed prompt fragments."""
    lower=str(message or '').lower()
    if 'thought_signature' in lower:return 'Provider rejected tool metadata: thought_signature missing/invalid.'
    if 'high demand' in lower or 'overload' in lower:return 'Provider reports temporary high demand/overload.'
    if 'quota' in lower or 'rate limit' in lower:return 'Provider quota/rate limit; inspect structured quota/retry fields.'
    if 'schema' in lower:return 'Provider rejected response schema; raw diagnostic omitted.'
    return 'Provider request failed; inspect HTTP/provider status and structured retry/quota fields.'
