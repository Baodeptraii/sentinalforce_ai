"""Bounded evidence collection and deterministic reports, independent of execution dispatch."""
import fcntl
import hashlib
import html
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from . import wazuh_connector, execution_contracts, telemetry_identity
from .audit_stream import now
from .scenario_execution import safe_text

ROOT=Path(__file__).resolve().parents[1]
LOCK=threading.RLock()
THREADS={}
TERMINAL={"completed","failed","stopped","blocked"}
ACTIVE={"confirmed","registering","creating_operation","running","stop_requested","recovery_required"}
PUBLIC={'report.json','report.md','telemetry_state.json'}
SAFE=re.compile(r'^[\w .:/@+{}()\[\]\\-]{0,240}$',re.ASCII)


def text(value):
    # Strict projection, not a best-effort credential regex on arbitrary log text.
    return str(value) if value is not None and SAFE.fullmatch(str(value)) else None


def timestamp(value):
    date=datetime.fromisoformat(value.replace('Z','+00:00'))
    if date.tzinfo is None:raise ValueError('Timezone required')
    return date.astimezone(timezone.utc)


def iso(value):return value.isoformat().replace('+00:00','Z')


def recorded_identity(prior, record):
    """Reuse a per-execution observation, never today's directory as historical proof."""
    saved=prior.get('identity_attestation')
    if saved:
        if saved.get('execution_id')==record['id'] and saved.get('target')==record['target']['ip']:
            return saved
        return None
    policy=prior.get('identity_policy',{})
    agent=prior.get('identity') or {}
    if policy.get('kind')!='live_api' or not policy.get('verified') or not agent.get('id'):
        return None
    try:
        captured=datetime.fromtimestamp(prior['last_attempt_epoch'],timezone.utc)
        start=timestamp(record.get('confirmed_at') or record['created_at'])-timedelta(seconds=300)
        end=timestamp(record.get('updated_at') or record['created_at'])+timedelta(seconds=1200)
        if start<=captured<=end and agent.get('ip')==record['target']['ip']:
            return {'agent':agent,'target':agent['ip'],'execution_id':record['id'],
                    'captured_at':iso(captured),'origin':'persisted_live_api_observation'}
    except (KeyError,TypeError,ValueError,OverflowError):pass
    return None


def config():
    return json.loads((ROOT/'telemetry_report.json').read_text())


def directory(identifier):
    if not re.fullmatch('[a-f0-9]{32}',identifier):raise ValueError('Invalid execution ID')
    path=ROOT/'telemetry_reports'/identifier
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('Symlink refused')
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    return path


def load(path,default=None):
    if path.is_symlink():raise ValueError('Symlink refused')
    if not path.exists():return default
    if path.stat().st_size>8_000_000:raise ValueError('Artifact too large')
    return json.loads(path.read_text())


def save(path,value):
    if path.is_symlink():raise ValueError('Symlink refused')
    temp=path.with_name(path.name+'.tmp')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        stream.write(value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,indent=2));stream.flush();os.fsync(stream.fileno())
    os.replace(temp,path)


def window_for(record,settings,previous=None):
    if previous:return previous
    start=timestamp(record.get('confirmed_at') or record['created_at'])
    end=(datetime.now(timezone.utc) if record.get('state') in ACTIVE else
         timestamp(record.get('updated_at') or record['created_at']))
    lookback=min(300,max(0,int(settings.get('lookback_seconds',30))))
    skew=min(300,max(0,int(settings.get('clock_skew_seconds',10))))
    grace=min(900,max(0,int(settings.get('ingest_grace_seconds',120))))
    maximum=min(86400,max(60,int(settings.get('max_window_seconds',3600))))
    first=start-timedelta(seconds=lookback+skew)
    last=end+timedelta(seconds=skew)
    oversized=(last-first).total_seconds()>maximum
    # Never silently narrow an execution: refuse oversized windows.
    return {'start':iso(first),'end':iso(last),'ingest_deadline':iso(last+timedelta(seconds=grace)), 'policy':'event_window_v2',
            'lookback_seconds':lookback,'clock_skew_seconds':skew,'ingest_grace_seconds':grace,
            'oversized':oversized}


def normalize(hit,record):
    source=hit.get('_source',{});data=source.get('data') or {};soc=data.get('soc') or {};web=data.get('soc_web') or {}
    system=(data.get('win') or {}).get('system') or {};eventdata=(data.get('win') or {}).get('eventdata') or {}
    matched=[];step=None;method='host_time_candidate';confidence='none';ambiguous=True
    # Explicit execution ID is authoritative only when operation IDs do not conflict.
    if soc.get('execution_id')==record['id'] and (not soc.get('operation_id') or soc.get('operation_id')==record.get('operation_id')):
        matched=['execution_id'];method='explicit_execution_id';confidence='high';ambiguous=False
        if soc.get('operation_id')==record.get('operation_id') and record.get('operation_id'):matched.append('operation_id')
        for row in record.get('steps',[]):
            if row.get('link_id') and row['link_id']==soc.get('link_id'):
                step=row['index'];matched.append('link_id')
    elif soc.get('operation_id') and soc['operation_id']==record.get('operation_id'):
        # A conflicting execution ID must never win via a weaker operation match.
        if not soc.get('execution_id'):
            matched=['operation_id'];method='explicit_operation_id';confidence='high';ambiguous=False
    # PID is useful only with the dispatch interval, target identity (checked by collector),
    # unique step and absence of overlapping executions. Never infer behavior from a PID.
    if ambiguous and not soc.get('execution_id') and not soc.get('operation_id') and not record.get('_overlapping_execution'):
        def pid(value):
            try:return int(str(value),16 if str(value).lower().startswith('0x') else 10)
            except (ValueError,TypeError):return None
        observed=pid(eventdata.get('newProcessId') or (eventdata.get('processId') if str(system.get('eventID'))=='1' else None))
        candidates=[]
        if observed is not None:
            for row in record.get('steps',[]):
                if pid(row.get('process_id'))!=observed or not row.get('collected_at') or not row.get('finished_at'):continue
                try:
                    event_time=timestamp(system.get('systemTime') or source.get('timestamp',''))
                    if timestamp(row['collected_at'])-timedelta(seconds=5)<=event_time<=timestamp(row['finished_at'])+timedelta(seconds=5):candidates.append(row)
                except (ValueError,TypeError,AttributeError):pass
        if len(candidates)==1:
            matched=['agent.id','agent.ip','caldera_link.pid','step_dispatch_interval']
            method='process_id_and_dispatch_interval';confidence='medium';ambiguous=False;step=candidates[0]['index']
    # Request marker must be explicitly registered by this execution, not inferred from a URL.
    marker=web.get('marker')
    if not soc.get('execution_id') and not soc.get('operation_id') and marker and marker in record.get('telemetry_markers',[]) and re.fullmatch('[a-f0-9-]{36}',str(marker)):
        matched=['registered_request_marker'];method='request_marker';confidence='high';ambiguous=False
    test=bool(soc.get('test_marker') or web.get('test_marker'))
    rule=source.get('rule') or {}
    return {'source_event_id':text(soc.get('event_id') or web.get('event_id')),'document_id':text(hit.get('_id')),'index':text(hit.get('_index')),
            'timestamp':text(source.get('timestamp') or source.get('@timestamp')),
            'source_timestamp':text(system.get('systemTime') or soc.get('timestamp') or web.get('timestamp')),
            'agent':{k:text((source.get('agent') or {}).get(k)) for k in ('id','name','ip')},
            'rule':{'id':text(rule.get('id')),'level':rule.get('level') if type(rule.get('level')) is int else None,
                    'mitre_ids':sorted({v for v in (rule.get('mitre') or {}).get('id',[]) if isinstance(v,str) and re.fullmatch(r'T[0-9]{4}(?:\.[0-9]{3})?',v)}),
                    'description':safe_text(str(rule.get('description','')),limit=500),'description_sha256':hashlib.sha256(str(rule.get('description','')).encode()).hexdigest()},
            'source':{'channel':text(system.get('channel')),'event_id':text(system.get('eventID')),
                      'record_id':text(system.get('eventRecordID')),'computer':text(system.get('computer')),
                      'location':text(source.get('location')),'component':text(soc.get('component'))},
            'process':{k:text(eventdata.get(k)) for k in ('processId','parentProcessId','processGuid','parentProcessGuid')},
            'correlation':{'method':method,'matched_fields':matched,'confidence':confidence,'ambiguous':ambiguous,'step_index':step},
            'test_marker':test,'redacted':True,'truncated':len(str(rule.get('description','')))>500}


def build_report(record,state,events):
    matched=[e for e in events if not e['correlation']['ambiguous'] and not e['test_marker']]
    alerts=[e for e in matched if e['rule']['id'] and str(e.get('index','')).startswith('wazuh-alerts-')]
    error=state.get('error')
    telemetry='partial' if matched else ('unavailable' if error else 'unknown')
    detection='matched_alert' if alerts else ('not_evaluable' if error else 'unknown')
    steps=[]
    preview={s['index']:s for s in record.get('preflight',{}).get('steps',[])}
    for step in record.get('steps',[]):
        p=preview.get(step['index'],{})
        evidence=[{'document_id':e['document_id'],'index':e['index']} for e in matched if e['correlation']['step_index']==step['index']]
        steps.append({'index':step['index'],'name':text(step.get('name')),'link_id':step.get('link_id'),
                      'command_status':command_status(step.get('state')),'exit_code':step.get('exit_code'),
                      'started_at':step.get('collected_at'),'finished_at':step.get('finished_at'),
                      'source_ability_id':p.get('source_ability_id'),
                      'command_sha256':hashlib.sha256(str(p.get('command','')).encode()).hexdigest() if p.get('command') else None,
                      'source_provenance':safe_structure(p.get('source',p.get('sources'))),
                      'prerequisites':safe_structure(p.get('prerequisites')),
                      'behavior_status':'unknown','telemetry_status':'partial' if evidence else 'unknown',
                      'detection_status':'matched_alert' if any(e['correlation']['step_index']==step['index'] for e in alerts) else 'unknown',
                      'evidence_refs':evidence})
    limitations=['Exit code 0 không tự chứng minh hành vi. Không có alert không chứng minh missed_detection.',
                 'Host/time chỉ tạo ứng viên; tương quan cần ID/marker hoặc PID + interval duy nhất không chồng execution.',
                 'Audit của controller không chứng minh telemetry/hành vi trên endpoint.',
                 'Không backfill tự động; bản cũ thiếu link/marker giữ unknown.',
                 'Thời gian index ingest không do API này cung cấp; window/grace không chứng minh độ trễ ingest thực tế.',
                 'Raw command/output/URL/query/header không được đưa vào báo cáo; xem evidence gốc có kiểm soát quyền.']
    if state.get('mode')=='alerts_only':limitations.append('alerts_only: không quan sát được mọi log không tạo alert; archives chưa xác minh khả dụng.')
    elif state.get('mode')!='alerts_and_archives':limitations.append('Chưa truy vấn được indexer để xác minh lại archive/alerts; snapshot trước là alerts_only.')
    if state.get('truncated'):limitations.append('Đã chạm giới hạn collection/events; coverage không đầy đủ.')
    if state.get('ingest_pending'):limitations.append('Còn trong thời gian chờ ingest; có thể refresh sau deadline.')
    inventory=load(ROOT/'telemetry_host_inventory.json',{'sources':[]})
    report = {'schema_version':'execution_telemetry_report_v1','generated_at':now(),'execution_id':record['id'],
            'operation_id':record.get('operation_id'),'scenario_id':record.get('scenario_job_id'),
            'plan_sha256':record.get('plan_sha256'),'target':safe_structure(record.get('target')),
            'survey_snapshot':safe_structure(record.get('preflight',{}).get('survey')),
            'command_status':command_status(record.get('command_status')),'legacy_command_status':record.get('command_status'),'behavior_status':'unknown',
            'telemetry_status':telemetry,'detection_status':detection,'steps':steps,
            'collection':state,'counts':{'events':len(events),'correlated':len(matched),'alerts':len(alerts),
                                        'test_events':sum(e['test_marker'] for e in events)},
            'evidence':events,'limitations':limitations,'source_coverage':inventory,
            'evidence_provenance':{'execution_record_canonical_sha256':hashlib.sha256(json.dumps({k:v for k,v in record.items() if k not in ('files','_overlapping_execution')},sort_keys=True,ensure_ascii=False).encode()).hexdigest(),
                                   'execution_artifact_refs':artifact_refs(record['id'])},
            'missing_sources':['Per-behavior source coverage/generation not proven by a successful search'],
            'next_checks':['Kiểm tra nguồn sinh event và pipeline; đăng ký marker/ID kiểm chứng riêng cho từng bước.'],
            'legacy_adapter':{'behavior_evidence':'not_evaluated → unknown; existing execution record unchanged',
                              'detection':'unknown retained unless a correlated indexed alert exists'}}
    contract = load(directory(record['id'])/'expected.json')
    if contract is None:
        from . import scenario_execution
        contract = load(scenario_execution.folder(record['id'])/'execution_expected.json') or historical_expected(record)
    execution_contracts.verify_expected(contract,record)
    report['expected_reality'] = execution_contracts.comparison(record, contract, state, events)
    report['expected_contract'] = contract
    report['assessment'] = assessment(report, alerts)
    report['execution_state'] = record.get('state')
    report['counts_v2'] = document_counts(events, state)
    report['operations'] = {'collection_seconds':state.get('duration_seconds'), 'query_count':state.get('query_count'),
        'identity':state.get('identity_policy'), 'api_health':state.get('api_health','unknown'),
        'execution_started_at':record.get('confirmed_at'), 'execution_updated_at':record.get('updated_at'),
        'survey_finished_at':record.get('preflight',{}).get('survey',{}).get('finished_at'),
        'validation_checked_at':record.get('preflight',{}).get('checked_at'),
        'ai_actual_tokens':None, 'ai_estimated_tokens':None}
    report['operations'].update(operational_metrics(record))
    return report


def command_status(value):
    return {'success':'completed','completed':'completed','error':'failed','failed':'failed','dispatched':'dispatched','incomplete':'dispatched'}.get(value,'unknown')


def safe_structure(value):
    # Copy only metadata; all arbitrary sentences/secret-bearing fields are excluded.
    if isinstance(value,dict):return {k:safe_structure(v) for k,v in value.items() if not re.search(r'(?i)command|stdout|stderr|password|passwd|secret|cookie|authorization|credential|token|api.?key',k)}
    if isinstance(value,list):return [safe_structure(v) for v in value]
    if isinstance(value,str):
        clean=safe_text(value,limit=4000)
        return clean if len(value)<=4000 else {'value':clean,'sha256':hashlib.sha256(value.encode()).hexdigest(),'redacted':clean!=value,'truncated':True}
    return value if value is None or isinstance(value,(bool,int,float)) else None


def artifact_refs(identifier):
    from . import scenario_execution
    folder=scenario_execution.folder(identifier)
    refs=[]
    for name in sorted(scenario_execution.FILES):
        path=folder/name
        if path.is_symlink():raise ValueError('Evidence symlink refused')
        if path.is_file():
            if path.stat().st_size>8_000_000:raise ValueError('Execution evidence exceeds budget')
            refs.append({'file':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    return refs


def markdown(report):
    def md(value):
        text=json.dumps(value,ensure_ascii=False) if isinstance(value,(dict,list)) else str(value)
        return html.escape(text).replace('|',r'\|').replace('`',r'\`').replace('\n',' ')
    lines=['# Báo cáo execution '+report['execution_id'],'',
           'Sinh lúc: '+report['generated_at'],
           'Target: '+md(report['target']),
           'Scenario: '+md(report['scenario_id'])+'; plan SHA-256: '+md(report['plan_sha256']),
           'Operation: '+md(report['operation_id']),
           'Survey snapshot: '+md(report['survey_snapshot']),
           'Lệnh: '+str(report['command_status'])+'; hành vi: '+report['behavior_status']+
           '; telemetry: '+report['telemetry_status']+'; detection: '+report['detection_status'],
           '', 'Chế độ: '+str(report['collection'].get('mode','unknown')),
           'Query window: '+md(report['collection'].get('window')),
           'Đánh giá Python: '+md(report.get('assessment',{})),
           'Counts: '+md(report['counts']), '', '| Bước | Lệnh | Hành vi | Telemetry | Detection |',
           '|---|---|---|---|---|']
    for row in report['steps']:lines.append('| '+ ' | '.join(md(row.get(k,'')) for k in ('index','command_status','behavior_status','telemetry_status','detection_status'))+' |')
    for row in report['steps']:
        lines+=['', 'Bước '+str(row['index'])+': '+md(row['name']),
                '- Timeline: '+md(row['started_at'])+' → '+md(row['finished_at'])+'; link: '+md(row['link_id'])+'; exit: '+md(row['exit_code']),
                '- Nguồn: '+md(row['source_ability_id'])+'; command SHA-256: '+md(row['command_sha256']),
                '- Provenance: '+md(row['source_provenance']), '- Prerequisites: '+md(row['prerequisites']),
                '- Evidence refs: '+md(row['evidence_refs'])]
    lines+=['','## Coverage nguồn (snapshot quản trị, không phải bằng chứng của execution)', '',
            '| Host / nguồn | Configured | Nguồn | Collector | Manager | Indexer |', '|---|---|---|---|---|---|']
    for source in report['source_coverage'].get('sources',[]):
        lines.append('| '+ ' | '.join(md(x) for x in (source['host']+' / '+source['source'],source['configured'],source['observed_at_source'],source['collector'],source['received_by_wazuh'],source['indexed']))+' |')
    alerts=[e for e in report['evidence'] if e['rule']['id'] and not e['correlation']['ambiguous'] and not e['test_marker']]
    lines+=['','## Alert tương quan','']
    for event in alerts[:50]:lines.append('- '+md(event['rule'])+'; doc '+md(event['index'])+'/'+md(event['document_id'])+'; '+md(event['correlation']))
    if len(alerts)>50:lines.append('Hiển thị 50/'+str(len(alerts))+'; toàn bộ refs nằm trong report.json.')
    if not alerts:lines.append('Chưa có alert được tương quan; không kết luận missed_detection.')
    lines+=['','## Giới hạn','']+['- '+v for v in report['limitations']]
    lines+=['','Lỗi connector (đã lọc): '+md(report['collection'].get('error') or 'none'),'',
            'Provenance: '+md(report['evidence_provenance']), '',
            'Kiểm tra tiếp: '+md(report['next_checks'])]
    if report.get('expected_reality'):
        comp=report['expected_reality']
        lines+=['', '## Expected / Reality', '', 'Counts (v2): '+md(report['counts_v2']),
            'Lệnh hoàn tất: '+md(comp['execution_completion']),
            'Telemetry coverage: '+md(comp['telemetry_coverage']), 'Alert coverage: '+md(comp['alert_coverage']),
            'Techniques: '+md(comp['techniques']), 'Mẫu số 0: N/A. Không phải detection efficacy.',
            'Expected origin: '+md(report['expected_contract']['origin'])]
        for row in comp['steps']:
            lines+=['- Bước '+str(row['index'])+': '+md(row)]
        lines+=['', '## Vận hành', md(report['operations'])]
    return '\n'.join(lines)+'\n'


def collect(identifier, connector_factory=wazuh_connector.Connector):
    from . import scenario_execution
    path=directory(identifier)
    fd=os.open(path/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        started=time.monotonic()
        record=scenario_execution.read(identifier);settings=config()
        prior=load(path/'telemetry_state.json',{})
        if prior.get('last_attempt_epoch') and time.time()-prior['last_attempt_epoch']<max(3,min(60,settings.get('poll_interval_seconds',5))):return
        window=window_for(record,settings,prior.get('window') if prior.get('execution_terminal') else None)
        state={'schema_version':'telemetry_collection_v1','status':'collecting','window':window,
               'execution_terminal':record.get('state') in TERMINAL,
               'execution_state':record.get('state'), 'attempt_count':prior.get('attempt_count',0)+1,
               'last_attempt_epoch':time.time(),'mode':prior.get('mode','unknown'),
               'ingest_pending':datetime.now(timezone.utc)<timestamp(window['ingest_deadline']),
               'truncated':False,'error':None,'source_states':{'configured':'unknown','observed_at_source':'unknown',
               'received_by_wazuh':'unknown','indexed':'unknown'},'checkpoint_reused':bool(prior),'tls_trust':settings.get('tls_mode','verified_ca'),
               'last_connector_validation':settings.get('last_validation')}
        save(path/'telemetry_state.json',state)
        events=load(path/'events.json',[])
        try:
            if window['oversized']:raise wazuh_connector.ConnectorError('execution_window_over_budget')
            client=connector_factory(settings)
            binding = telemetry_identity.resolve(ROOT,record['target'],window)
            try:
                identity=client.identity(record['target'])
                # A live directory does not attest the identity during a historical window.
                recent=(datetime.now(timezone.utc)-timestamp(window['end'])).total_seconds() <= 300
                verified=recent and record.get('state') != 'ready'
                state['api_health']='available'
                if binding and any(identity.get(k)!=binding['agent'].get(k) for k in ('id','ip','name')):
                    raise wazuh_connector.ConnectorError('identity_binding_drift')
            except wazuh_connector.ConnectorError as error:
                if error.code=='identity_binding_drift':raise
                state['api_health']=error.code
                identity={'ip':record['target']['ip']};verified=False
            attestation=recorded_identity(prior,record)
            if attestation and attestation.get('target')==record['target']['ip']:
                saved=attestation['agent']
                if identity.get('id') and any(identity.get(k)!=saved.get(k) for k in ('id','ip','name')):
                    raise wazuh_connector.ConnectorError('identity_binding_drift')
                identity=saved;verified=True
            if binding:
                identity=binding['agent'];verified=True
            if verified:
                state['identity_attestation']=attestation or {'agent':identity,'target':record['target']['ip'],
                    'captured_at':now(),'execution_id':identifier,'origin':'historical_binding' if binding else 'live_api'}
            state['identity_policy']={'verified':verified,
                'kind':'historical_binding' if binding else 'execution_snapshot' if attestation else 'live_api' if verified else 'candidate_only',
                'binding':binding, 'live_health_inferred_from_logs':False}
            result=client.collect(identity,window)
            record=dict(record)
            record['_overlapping_execution']=False
            for other in scenario_execution.history(limit=None):
                if other.get('id')==identifier or not other.get('operation_id') or other.get('target',{}).get('ip')!=record.get('target',{}).get('ip'):continue
                try:
                    start=timestamp(other.get('confirmed_at') or other['created_at']);end=timestamp(other.get('updated_at') or other['created_at'])
                    if start<=timestamp(window['end']) and end>=timestamp(window['start']):record['_overlapping_execution']=True
                except (KeyError,ValueError,TypeError):record['_overlapping_execution']=True
            by_id={(e['index'],e['document_id']):e for e in events}
            if not verified:
                for e in by_id.values():
                    e['correlation']={'method':'unverified_identity_candidate','matched_fields':[],
                        'confidence':'none','ambiguous':True,'step_index':None}
            for hit in result.pop('hits'): 
                e=normalize(hit,record)
                if e['document_id'] is None or e['index'] is None:raise wazuh_connector.ConnectorError('invalid_document_identity')
                # Defense in depth: server filters are not sufficient identity verification.
                if e['agent']['ip']!=identity['ip']:continue
                if identity.get('id') and e['agent']['id']!=identity['id']:raise wazuh_connector.ConnectorError('hit_identity_drift')
                if identity.get('name') and e['agent']['name']!=identity['name']:raise wazuh_connector.ConnectorError('hit_identity_drift')
                if not verified:
                    e['correlation']={'method':'unverified_identity_candidate','matched_fields':[],
                        'confidence':'none','ambiguous':True,'step_index':None}
                e['first_observed_by_collector_at']=by_id.get((e['index'],e['document_id']),{}).get('first_observed_by_collector_at') or now()
                by_id[(e['index'],e['document_id'])]=e
            maximum=min(5000,max(1,settings.get('max_events',1000)))
            events=list(by_id.values())
            if len(events)>maximum:result['truncated']=True;events=events[:maximum]
            state.update(result,identity=identity,status='watching_execution' if not state['execution_terminal'] else 'waiting_ingest' if state['ingest_pending'] else 'complete')
            if events:state['source_states'].update(received_by_wazuh='observed',indexed='observed')
        except wazuh_connector.ConnectorError as error:
            state.update(status='degraded',error={'code':error.code,'http_status':error.status})
            if error.code in ('identity_binding_drift','hit_identity_drift'):
                events=[];state['identity_policy']={'verified':False,'kind':'identity_drift'}
        except Exception:
            state.update(status='degraded',error={'code':'local_collection_failure','http_status':None})
        save(path/'events.json',events)
        state.update(completed_at=now(),event_document_ids=[{'index':e['index'],'id':e['document_id']} for e in events],
                     cursor={'strategy':'requery_frozen_window_and_dedup','seen_count':len(events)})
        state['total_query_count']=prior.get('total_query_count',0)+int(getattr(locals().get('client'),'query_count',0) or 0) if isinstance(getattr(locals().get('client'),'query_count',0),int) else prior.get('total_query_count',0)
        state['duration_seconds']=round(time.monotonic()-started,3)
        state['query_count']=getattr(locals().get('client'), 'query_count', None)
        if not isinstance(state['query_count'],int):state['query_count']=None
        expected_path=path/'expected.json'
        if not expected_path.exists():
            contract=load(scenario_execution.folder(identifier)/'execution_expected.json') or historical_expected(record)
            save(expected_path,contract)
        report=build_report(record,state,events)
        # Keep periodic audit snapshots without multiplying full reports every poll.
        snapshot_due=(time.time()-prior.get('last_snapshot_epoch',0)>=60
                      or state['status'] in ('complete','degraded'))
        state['last_snapshot_epoch']=time.time() if snapshot_due else prior.get('last_snapshot_epoch',0)
        if snapshot_due:
            save(path/('snapshot-'+str(time.time_ns())+'.json'),report)
        save(path/'telemetry_state.json',state);save(path/'report.json',report);save(path/'report.md',markdown(report))
        return report


def read(identifier):
    from . import scenario_execution
    record=scenario_execution.read(identifier)  # Validate execution ownership/existence, never dispatch.
    path=directory(identifier)
    report=load(path/'report.json') or build_report(record,{'status':'not_collected','mode':'unknown','error':None},[])
    state=load(path/'telemetry_state.json',{})
    if state.get('status')=='collecting':
        report['collection']['status']='collecting'
        report['collection']['refresh_in_progress']=True
    report['execution_state']=record.get('state')
    return report


def enqueue(identifier):
    """One bounded background watcher per execution; never dispatch CALDERA."""
    from . import scenario_execution
    record=scenario_execution.read(identifier)
    if record.get('state') not in ACTIVE|TERMINAL:
        return {'status':'waiting_confirmation','execution_id':identifier}
    with LOCK:
        if identifier in THREADS and THREADS[identifier].is_alive():
            return {'status':'collecting','execution_id':identifier}
        path=directory(identifier)
        if not (path/'telemetry_state.json').exists():
            state={'status':'queued','mode':'unknown','error':None,'execution_state':record['state']}
            save(path/'telemetry_state.json',state)
            save(path/'report.json',build_report(record,state,[]))
        def worker():
            try:
                failures=0
                deadline=time.monotonic()+min(86400,max(60,int(config().get('max_window_seconds',3600))))+910
                while True:
                    report=collect(identifier)
                    state=(report or {}).get('collection') or load(path/'telemetry_state.json',{})
                    failures=failures+1 if state.get('error') else 0
                    if not config().get('enabled') or state.get('status')=='complete':break
                    if failures>=3 or time.monotonic()>=deadline or state.get('window',{}).get('oversized'):break
                    interval=max(3,min(60,int(config().get('poll_interval_seconds',5))))
                    time.sleep(min(60,interval*(2**failures)))
            except Exception:
                # A reporting failure must never fail execution or cause a redispatch.
                state=load(path/'telemetry_state.json',{})
                state.update(status='degraded',error={'code':'report_worker_failure','http_status':None})
                save(path/'telemetry_state.json',state)
            finally:
                try:
                    state=load(path/'telemetry_state.json',{})
                    state['watcher_active']=False
                    if state.get('status') not in ('complete','degraded'):
                        state.update(status='degraded',error={'code':'collection_budget_exhausted','http_status':None})
                    save(path/'telemetry_state.json',state)
                    latest=scenario_execution.read(identifier)
                    report=build_report(latest,state,load(path/'events.json',[]))
                    save(path/'report.json',report);save(path/'report.md',markdown(report))
                finally:
                    with LOCK:THREADS.pop(identifier,None)
        thread=threading.Thread(target=worker,daemon=True,name='telemetry-'+identifier[:8])
        THREADS[identifier]=thread;thread.start()
    return {'status':'queued','execution_id':identifier}


def initialize():
    """Resume journals and active executions only; no historical backfill/dispatch."""
    from . import scenario_execution
    root=ROOT/'telemetry_reports'
    if root.is_symlink():return
    ids=set()
    for path in list(root.glob('*/telemetry_state.json'))[:100]:
        state=load(path,{})
        if state.get('status') in ('queued','collecting','watching_execution','waiting_ingest'):
            ids.add(path.parent.name)
    for record in scenario_execution.history(limit=None):
        if record.get('state') in ACTIVE:ids.add(record['id'])
    for identifier in sorted(ids)[:100]:
        try:enqueue(identifier)
        except (ValueError,OSError):pass


def assessment(report, alerts):
    """Rule tags are evidence metadata, never a behavioral detection verdict."""
    expected=set(report['expected_reality'].get('techniques',{}).get('expected',[]))
    observed=set(v for e in alerts for v in e['rule'].get('mitre_ids',[]))
    launch=[e for e in alerts if e['source'].get('event_id') in ('1','4688')]
    return {'schema_version':'deterministic_assessment_v1','processor':'python','llm_requests':0,
        'associated_alerts':len(alerts),'process_launch_alerts':len(launch),
        'rule_technique_tags':sorted(observed),'expected_technique_tags':sorted(expected),
        'matching_rule_tags':sorted(expected & observed),'technique_detection':'not_evaluable',
        'explanation':'Alert tương quan cho biết hoạt động liên quan tới execution. Process launch và MITRE tag không tự chứng minh phát hiện kỹ thuật; cần tiêu chí rule/hành vi đã kiểm chứng.'}


def document_counts(events, state):
    alerts = {(e['index'], e['document_id']) for e in events if str(e.get('index','')).startswith('wazuh-alerts-') and e['rule']['id']}
    correlated = {(e['index'], e['document_id']) for e in events if (e['index'], e['document_id']) in alerts and not e['correlation']['ambiguous'] and not e['test_marker']}
    identities = set(); unresolved = 0
    for e in events:
        source=e['source']
        if e.get('source_event_id'):
            identities.add((e['agent']['id'], e['source_event_id']))
        elif all(source.get(k) for k in ('record_id','channel','computer')):
            identities.add((e['agent']['id'],source['computer'],source['channel'],source['record_id'],e.get('source_timestamp')))
        else: unresolved += 1
    success = state.get('status') in ('complete','waiting_ingest','watching_execution') and not state.get('error')
    exact = success and not state.get('truncated')
    return {'candidate_alert_documents':len(alerts) if success or alerts else None,
        'correlated_alert_documents':len(correlated) if state.get('identity_policy',{}).get('verified') and (success or correlated) else None,
        'raw_event_count':len(identities) if exact and state.get('mode')=='alerts_and_archives' and not unresolved else None,
        'observed_unique_source_events':len(identities), 'documents_without_source_identity':unresolved,
        'count_quality':'exact_within_query' if exact else 'lower_bound' if events else 'unavailable',
        'raw_count_scope':'execution query window/filter, not all host logs'}


def operational_metrics(record):
    """Allowlisted local metrics only. Never copy prompts, requests or provider error bodies."""
    job_id=record.get('scenario_job_id','')
    if not re.fullmatch('[a-f0-9]{32}',job_id):return {}
    folder=ROOT/'scenario_outputs'/job_id
    try:
        job=load(folder/'job.json',{})
        tokens=load(folder/'token_metrics.json',{})
        survey=load(folder/'input/survey/metrics.json',{})
        survey_id=record.get('preflight',{}).get('survey',{}).get('survey_run_id','')
        survey_state=load(ROOT/'outputs'/survey_id/'state.json',{}) if re.fullmatch('[a-f0-9]{32}',survey_id or '') else {}
        def duration(start,end):
            try:return max(0,(timestamp(end)-timestamp(start)).total_seconds())
            except (TypeError,ValueError,AttributeError):return None
        usage=survey.get('usage',[])
        return {'survey_seconds':duration(survey_state.get('created_at'),survey_state.get('finished_at')),
            'validation_seconds':record.get('preflight',{}).get('duration_seconds'),
            'scenario_seconds':duration(job.get('created_at'),job.get('finished_at')),
            'execution_seconds':duration(record.get('confirmed_at'),record.get('updated_at')),
            'ai_actual_tokens':tokens.get('actual_total_tokens'),
            'ai_actual_complete':tokens.get('actual_total_complete'),
            'ai_requests':tokens.get('requests'),'ai_unknown_usage_requests':tokens.get('unknown_usage_requests'),
            'ai_estimated_tokens':None,'ai_internal_charge_tokens':tokens.get('charged_tokens'),
            'ai_error_requests':sum(c.get('status') not in ('success','completed','counted') for c in tokens.get('calls',[])),
            'survey_ai_requests':survey.get('api_requests'),
            'survey_ai_actual_tokens':sum(u['total_tokens'] for u in usage) if usage and all(isinstance(u.get('total_tokens'),int) for u in usage) else None,
            'survey_ai_usage_complete':survey.get('usage_complete')}
    except (OSError,ValueError):return {'metrics_status':'unavailable'}


def historical_expected(record):
    """Recover plan techniques only from the exact pinned plan; no result/log inference."""
    import copy
    import yaml
    result=copy.deepcopy(record)
    job=record.get('scenario_job_id','')
    path=ROOT/'scenario_outputs'/job/'scenario_plan.yml'
    if re.fullmatch('[a-f0-9]{32}',job) and path.is_file() and not path.is_symlink() and path.stat().st_size<=2_000_000:
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()==record.get('plan_sha256'):
            plan=yaml.safe_load(raw)
            source={s['step_index']:s for s in plan.get('metadata',{}).get('steps',[])}
            for s in result.get('preflight',{}).get('steps',[]):
                original=source.get(s['index'],{})
                if original.get('ability_id')==s.get('source_ability_id'):
                    s['technique_ids']=original.get('technique_ids',[])
    return execution_contracts.expected(result,historical=True)
