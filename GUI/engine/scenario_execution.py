"""Deterministic, explicit-confirmation execution controller. No LLM or implicit resume."""
import base64
import copy
import hashlib
import ipaddress
import json
import re
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlencode

from . import scenario_bridge as bridge
from .execution_context import is_inventory_command, is_reviewed_inventory, REVIEWED_INVENTORY
from .survey import api_for, now
from .runner import save
from .lifecycle import InstanceLock, pending_recovery, endpoint_activity_path, endpoint_runner_path
from .llm import redact
from .runtime_paths import resolve_runtime

VERSION='caldera_execution_v1'
LOCK=threading.RLock()
THREADS={}
TERMINAL={'completed','failed','stopped','blocked'}
RECOVERY={'confirmed','registering','creating_operation','running','stop_requested','recovery_required'}
FILES={'execution_request.json','execution_preflight.json','execution_manifest.json','operation-summary.json','execution_result.json','execution_validation.json','execution_expected.json'}
SECRET=re.compile(r'(?i)(password|passwd|secret|cookie|authorization|credential|api[_-]?key|access[_-]?token|session[_-]?(?:id|token))')
COMPACT='include=id&include=name&include=state&include=group&include=host_group.paw'


def sha(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def age(timestamp):
    value=datetime.fromisoformat(timestamp.replace('Z','+00:00'))
    if value.tzinfo is None:raise ValueError('Timestamp thiếu múi giờ.')
    return (datetime.now(timezone.utc)-value).total_seconds()


def policy(config):
    p=dict(config.get('scenario_execution') or {})
    return {'preview_ttl_seconds':min(900,max(30,int(p.get('preview_ttl_seconds',300)))),
            'survey_max_age_seconds':min(86400,max(60,int(p.get('survey_max_age_seconds',3600)))),
            'agent_max_age_seconds':min(300,max(30,int(p.get('agent_max_age_seconds',180)))),
            'timeout_seconds':min(3600,max(60,int(p.get('timeout_seconds',900)))),
            'max_output_bytes':min(65536,max(1024,int(p.get('max_output_bytes',16384))))}


def storage():
    root=bridge.ROOT/'executions'
    if any(p.is_symlink() for p in (root,*root.parents)):raise ValueError('Invalid execution storage.')
    return root


def folder(identifier):
    if not isinstance(identifier,str) or not re.fullmatch('[a-f0-9]{32}',identifier):raise ValueError('Invalid execution ID.')
    path=storage()/identifier
    if path.is_symlink():raise ValueError('Execution symlink refused.')
    return path


def read(identifier):
    value=bridge.read(folder(identifier)/'execution_result.json')
    if not value:raise ValueError('Không tìm thấy lượt thực thi.')
    value['files']=sorted(name for name in FILES if (folder(identifier)/name).is_file() and not (folder(identifier)/name).is_symlink())
    return value


def write(value):
    with LOCK:
        previous=bridge.read(folder(value['id'])/'execution_result.json',{})
        if previous.get('stop_requested_at'):
            value['stop_requested_at']=previous['stop_requested_at']
            if value['state'] in ('confirmed','registering','creating_operation','running'):value['state']='stop_requested'
        value['updated_at']=now();save(folder(value['id'])/'execution_result.json',{k:v for k,v in value.items() if k!='files'})
        from . import audit_stream, execution_telemetry
        try:
            audit_stream.transition('execution',value,previous)
            before={r.get('index'):(r.get('state'),r.get('link_id')) for r in previous.get('steps',[])}
            for step in value.get('steps',[]):
                if before.get(step.get('index'))!=(step.get('state'),step.get('link_id')):
                    audit_stream.emit('execution',execution_id=value['id'],scenario_id=value.get('scenario_job_id'),
                        operation_id=value.get('operation_id'),link_id=step.get('link_id'),
                        ability_id=next((m.get('execution_ability_id') for m in value.get('mapping',[]) if m.get('index')==step.get('index')),None),
                        target=value.get('target',{}).get('ip'),paw=value.get('target',{}).get('paw'),
                        phase='step_'+str(step.get('index')),status=step.get('state'),
                        evidence_refs=['execution/'+value['id']])
        except (OSError,ValueError):
            value['audit_status']='unavailable'
            save(folder(value['id'])/'execution_result.json',{k:v for k,v in value.items() if k!='files'})
        # Only new terminal transitions schedule collection; no dispatch and no historical replay.
        if value.get('state') in TERMINAL and previous.get('state') not in TERMINAL and value.get('operation_id'):
            try:execution_telemetry.enqueue(value['id'])
            except (OSError,ValueError):pass



def safe_text(value,limit=65536):
    text=redact(value,limit=limit)
    text=re.sub(r'(?i)((?:password|passwd|secret|cookie|authorization|credential|api[_-]?key|access[_-]?token|session[_-]?(?:id|token))\s*[\"\x27]?\s*[:=]\s*)[^\r\n,;}]+',r'\1[REDACTED]',text)
    text=re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',text)
    return text[:limit]


def clean(value):
    """Persist only bounded, redacted public values; secret-bearing commands are blocked."""
    if isinstance(value,dict):return {k:('[REDACTED]' if SECRET.search(str(k)) else clean(v)) for k,v in value.items()}
    if isinstance(value,list):return [clean(x) for x in value[:200]]
    if isinstance(value,str):return safe_text(value)
    return value


def history(scenario_id=None,limit=100):
    rows=[]
    for p in storage().glob('*/execution_result.json'):
        if p.is_symlink() or p.parent.is_symlink():continue
        item=bridge.read(p,{})
        if item and (scenario_id is None or item['scenario_job_id']==scenario_id):rows.append(item)
    result=sorted(rows,key=lambda v:v['created_at'],reverse=True)
    return result[:limit] if limit else result


def pending(target_ip=None, exclude=None):
    return [r for r in history(limit=None) if r['id']!=exclude and r['state'] in RECOVERY and (target_ip is None or r.get('target',{}).get('ip')==target_ip)]


def initialize():
    # Local journal only. Never POST, PATCH, resume or dispatch on service start.
    for value in history(limit=None):
        if value['state'] in RECOVERY:
            value.update(state='recovery_required',error='GUI khởi động lại. Đối soát; không tự tiếp tục operation.')
            write(value)


def context_for(identifier,config):
    job=bridge.public(identifier)
    if job['status']!='completed':raise ValueError('Kịch bản chưa sinh hoàn tất.')
    root, python = resolve_runtime(config)
    src=bridge.directory(identifier)
    bridge.checked_download(src,'scenario_plan.yml')
    for path in src.rglob('*'):
        if path.is_symlink():raise ValueError('Input/artifact symlink refused.')
    if (src/'scenario_plan.yml').stat().st_size>2_000_000:raise ValueError('Plan quá lớn.')
    try:
        result=subprocess.run([str(python),'-B',str(Path(__file__).with_name('execution_context.py')),str(root),str(src)],capture_output=True,timeout=25)
    except (OSError,subprocess.TimeoutExpired):
        raise ValueError('Không đọc/kiểm tra được Scenario runtime trong thời gian cho phép.') from None
    if result.returncode or len(result.stdout)>4_000_000:raise ValueError('Không kiểm tra được schema/hash/context của plan; cần tạo lại hoặc revalidation.')
    return json.loads(result.stdout)


def get404(api,path):
    try:return api.call(path)
    except HTTPError as error:
        if error.code==404:return None
        raise


def operations(api):
    return api.call('operations?'+COMPACT)


def get_operation(api, identifier, *, reviewed_inventory=False):
    if reviewed_inventory:
        # This CALDERA API omits nested fields requested by dot-separated names.
        fields = 'include=id&include=name&include=state&include=group&include=host_group&include=adversary'
    else:
        fields = COMPACT + '&include=adversary.adversary_id&include=adversary.atomic_ordering'
    return api.call('operations/' + identifier + '?' + fields)


def get_execution_operation(api, value):
    steps = value['preflight']['steps']
    reviewed_inventory = bool(steps) and all(
        (step.get('runner_evidence') or {}).get('privilege_policy') == 'reviewed_local_inventory'
        for step in steps
    )
    return get_operation(api, value['operation_id'], reviewed_inventory=reviewed_inventory)


def execution_command(executor):
    source=executor['command']
    if executor['name']=='psh':
        encoded=base64.b64encode(source.encode('utf-16le')).decode('ascii')
        return 'powershell.exe -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand '+encoded+'; exit $LASTEXITCODE'
    return source


def command_blockers(command,target):
    errors=[]
    if not isinstance(command,str) or not command.strip() or len(command)>16000:return ['Lệnh nguồn rỗng/quá lớn.']
    if SECRET.search(command):errors.append('Lệnh chứa credential/cookie/secret; chưa có kênh cấp secret an toàn.')
    if re.search(r'#\{|PathToAtomicsFolder|<[^>]*(?:target|path|host)[^>]*>',command,re.I):errors.append('Placeholder chưa resolve; không tự thay shell.')
    for url in re.findall(r'https?://[^\s\"\x27<>]+',command,re.I):
        if urlsplit(url).hostname!=target:errors.append('URL nguồn nằm ngoài target đã ghim.')
    for addr in re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',command):
        try:
            if str(ipaddress.ip_address(addr)) not in (target,'127.0.0.1'):errors.append('Địa chỉ nguồn nằm ngoài target đã ghim.')
        except ValueError:errors.append('Địa chỉ nguồn không hợp lệ.')
    # This first adapter intentionally supports only standalone commands, not
    # arbitrary filesystem/process/service mutations whose scope cannot be proven.
    if re.search(r'(?i)\b(remove-item|del|erase|rm|format|shutdown|reboot|stop-service|stop-process|taskkill|copy-item|move-item|new-item|set-content|add-content|out-file|set-itemproperty|invoke-expression|invoke-command|start-process|start-bitstransfer|new-object)\b|\.CreationTime\s*=|\b(?:curl|wget)\b.*(?:--output|\s-o\s)|\b(?:cmd(?:\.exe)?)\b.*\s/[ck]\s|(?:>>|\s>\s)',command):
        errors.append('Tác động ghi/xóa/chạy nội dung hoặc tài nguyên động chưa có adapter phạm vi xác minh; bước này chưa hỗ trợ.')
    readonly=r'(?:Get-Process|Get-Service|Get-NetTCPConnection|Get-NetUDPEndpoint|Get-ComputerInfo|Get-HotFix|Get-NetIPAddress|Get-NetRoute|Get-NetAdapter|Get-DnsClientCache|Get-LocalUser|Get-LocalGroup|Get-Printer|systeminfo|whoami|hostname|ipconfig|netstat|tasklist|uname|id|ps|ss|ip)'
    lines=[line.strip() for line in command.splitlines() if line.strip() and not line.strip().startswith('#')]
    for line in lines:
        http=re.fullmatch(r'(?i)curl(?:\.exe)?\s+(https?://[^\s\"\x27;|&`$<>]+)',line)
        inventory=re.fullmatch(r'(?i)'+readonly+r'(?:\s+[a-z0-9_./:,= -]+)?',line)
        if not http and not inventory:
            errors.append('Cú pháp ngoài tập lệnh discovery/HTTP GET tĩnh đã hỗ trợ; cần adapter có type/phạm vi riêng.')
    if not lines:errors.append('Không có câu lệnh được hỗ trợ.')
    return list(dict.fromkeys(errors))


REVIEWED_INVENTORY_BLOCKERS = {
    'Manual review source effects, baseline, health checks and cleanup/rollback; absence of cleanup commands is not proof none is needed',
    'Required privilege is unspecified in catalog; manual review',
    'Revalidate runner identity, executor availability and privilege before execution',
}


def preflight(identifier,config,api=None,context=None,exclude=None):
    started=time.monotonic()
    ctx=context if context is not None else context_for(identifier,config)
    api=api or api_for(config);rules=policy(config)
    api.deadline=time.monotonic()+45
    plan=ctx['plan'];profile=ctx['profile'];target=profile['address'];scope=ctx['policy']['planning_scope']
    errors=list(ctx['blockers']);warnings=[];rows=[]
    if not any(ipaddress.ip_address(target) in ipaddress.ip_network(n) for n in config['allowed_networks']):errors.append('Target ngoài allowlist.')
    meta=plan['metadata']
    if not ctx['evidence'].get('verified'):errors.append('Thiếu evidence integrity Survey v2.')
    else:
        try:
            if not -60<=age(ctx['evidence']['finished_at'])<=rules['survey_max_age_seconds']:errors.append('Survey quá cũ theo chính sách; khảo sát lại và sinh phiên bản mới.')
        except (ValueError,KeyError):errors.append('Survey thiếu timestamp hợp lệ.')
        if not set(scope).issubset(ctx['evidence'].get('scope',[])):errors.append('Scope khác Survey đã ghim.')
    if pending(target,exclude):errors.append('Endpoint có execution đang chạy/cần phục hồi.')
    if any(r.get('target_ip') in (None,target) for r in pending_recovery(bridge.ROOT/'outputs')):errors.append('Survey có journal cần phục hồi.')
    agents=api.call('agents?include=paw&include=host&include=platform&include=group&include=last_seen&include=trusted&include=executors&include=privilege&include=host_ip_addrs')
    hostname=(profile.get('os',{}).get('hostname') or '').lower()
    matches=[a for a in agents if target in a.get('host_ip_addrs',[]) and a.get('host','').lower()==hostname]
    agent=matches[0] if len(matches)==1 else None
    heartbeat_current = False
    if agent is None:errors.append('Không xác định được duy nhất paw từ IP và hostname đã ghim.')
    else:
        if not agent.get('trusted'):errors.append('Sandcat không trusted.')
        try:
            heartbeat_current = -60 <= age(agent['last_seen']) <= rules['agent_max_age_seconds']
            if not heartbeat_current:errors.append('Heartbeat Sandcat quá cũ.')
        except (ValueError,KeyError):errors.append('Thiếu heartbeat hợp lệ.')
        busy=[op['id'] for op in operations(api) if op['state'] not in ('finished','out_of_time') and (op.get('group') in ('',None,agent.get('group')) or any(a['paw']==agent['paw'] for a in op.get('host_group',[])))]
        if busy:errors.append('Paw đang thuộc operation chưa kết thúc: '+', '.join(busy))
    planners=api.call('planners?include=id&include=name')
    planners=[p for p in planners if p['name']=='atomic']
    planner=planners[0] if len(planners)==1 else None
    if not planner:errors.append('Không xác định được duy nhất planner atomic.')
    api.call('sources?include=id&include=name')
    reviewed_count = 0
    for item in ctx['steps']:
        step=item['step'];record=item['record'];ex=item['executor'];blocked=list(item['blockers'])
        reviewed_inventory = is_reviewed_inventory(record, ex)
        prerequisites = copy.deepcopy(step.get('prerequisites', []))
        runner_evidence = None
        if (record and ex and not item['blockers'] and ctx['evidence'].get('verified')
                and agent and agent.get('trusted') is True and heartbeat_current
                and (reviewed_inventory or is_inventory_command(ex.get('command')))
                and ex['platform'] == agent.get('platform')
                and ex['name'] in agent.get('executors', [])):
            runner_evidence = {
                'source': 'caldera_agent_api', 'paw': agent['paw'],
                'platform': ex['platform'], 'executor': ex['name'],
                'observed_privilege': agent.get('privilege'),
            }
            for condition in prerequisites:
                if (condition.get('status') == 'unknown'
                        and condition.get('condition') == 'survey.executors:' + agent['paw']):
                    condition['status'] = 'verified'
                    condition['verification_source'] = 'caldera_agent_api'
        for condition in prerequisites:
            if condition.get('status')!='verified':blocked.append('Điều kiện chưa xác minh: '+condition['condition'])
        if step.get('parameters'):blocked.append('Tham số chưa có type/binding adapter được chứng minh; không chèn vào shell/facts.')
        if record and ex:
            ability=record['ability'];command=str(ex.get('command') or '')
            if not reviewed_inventory:
                blocked += command_blockers(command, target)
            if re.search(r'https?://',command,re.I) and 'web' not in scope:blocked.append('Bước web ngoài planning scope.')
            observed=[s.get('url') for s in profile.get('services',[]) if s.get('url')]
            observed += [a.get('base_url') for s in profile.get('services',[]) for a in s.get('applications',[]) if a.get('base_url')]
            origins={(urlsplit(u).scheme,urlsplit(u).netloc) for u in observed}
            for u in re.findall(r'https?://[^\s\"\x27<>]+',command,re.I):
                if (urlsplit(u).scheme,urlsplit(u).netloc) not in origins:blocked.append('Web origin/port chưa có trong profile Survey đã ghim.')
            if not re.search(r'https?://',command,re.I) and 'endpoint' not in scope:blocked.append('Bước endpoint ngoài planning scope.')
            if ex.get('code') or ex.get('language') or not command:blocked.append('Executor code/build chưa hỗ trợ.')
            if ex.get('name') not in ('psh','cmd','sh','bash'):blocked.append('Loại executor chưa hỗ trợ.')
            if ex.get('name')!='psh' and '\n' in command:blocked.append('Lệnh nhiều dòng ngoài psh chưa có transport bảo toàn.')
            if ability.get('requirements') or ex.get('payloads') or ex.get('uploads') or ex.get('parsers') or ex.get('variations'):
                blocked.append('Dependency/payload/parser/variation cần adapter riêng; chưa thể xác minh tự động.')
            if ex.get('cleanup'):blocked.append('Cleanup nguồn có tác động chưa có adapter điều kiện/phạm vi; không tự thực thi rollback.')
            if agent:
                if ex['platform']!=agent['platform'] or ex['name'] not in agent['executors']:blocked.append('Agent thiếu platform/executor.')
                privilege=str(ability.get('privilege') or '').lower()
                if privilege in ('elevated','administrator','admin','system','root') and str(agent.get('privilege','')).lower() not in ('elevated','system','root'):blocked.append('Agent thiếu quyền của ability nguồn.')
            live=get404(api,'abilities/'+record['canonical_id'])
            same=False
            if live:
                options=[e for e in live.get('executors',[]) if (e.get('platform'),e.get('name'))==(ex['platform'],ex['name'])]
                same=any(all((e.get(k) or None)==(ex.get(k) or None) for k in ('command','code','payloads','cleanup','parsers','timeout')) for e in options)
            registration='matched' if same else 'missing' if live is None else 'different'
        else:command='';ability={};registration='unresolved'
        required_privilege = ability.get('privilege')
        inventory_supported = (record and record['canonical_id'] not in REVIEWED_INVENTORY and is_inventory_command(command) and ex and ex.get('platform') == 'windows'
            and (ex.get('name') == 'psh' or (ex.get('name') == 'cmd' and not command.strip().lower().startswith('get-'))))
        step_revalidated = (not blocked and not errors and (reviewed_inventory or inventory_supported)
                and scope == ['endpoint'] and runner_evidence is not None
                and str(runner_evidence['observed_privilege']).lower() == 'elevated'
                and required_privilege is None
                and step.get('readiness') in ('needs_information', 'ready')
                and meta.get('readiness') in ('needs_information', 'ready')
                and set(meta.get('blockers', [])) <= REVIEWED_INVENTORY_BLOCKERS)
        if step_revalidated:
            reviewed_count += 1
            # This is a conservative dispatch policy, separate from source metadata.
            required_privilege = 'Elevated'
            runner_evidence['privilege_policy'] = 'reviewed_local_inventory'
        if step.get('readiness') != 'ready' and not step_revalidated:
            blocked.append('Readiness riêng của bước chưa ready; cần revalidation nguồn, không đổi assumed thành verified.')
        for b in blocked:errors.append('Bước '+str(step['step_index'])+': '+b)
        rows.append({'index':step['step_index'],'source_ability_id':step['ability_id'],'name':step['name'],
            'technique_ids':step.get('technique_ids',[]),'executor':step['executor'],'required_privilege':required_privilege,'catalog_privilege':ability.get('privilege'),'timeout_seconds':min(120,int(ex.get('timeout') or 60)) if ex else None,'parameters':clean(step.get('parameters',{})),
            'source':record['provenance'] if record else None,'command':('[REDACTED: secret-bearing source]' if SECRET.search(command) else command),
            'cleanup':clean(ex.get('cleanup',[])) if ex else [],'registration':registration,
            'registration_action':'create_private_verified_copy','impacts':step.get('reason',''),
            'prerequisites':clean(prerequisites),'runner_evidence':runner_evidence,'blockers':blocked})
    if not rows or reviewed_count != len(rows):
        errors.extend('Plan blocker: '+str(b) for b in meta.get('blockers',[]))
        if meta.get('readiness')!='ready':errors.append('Readiness của plan chưa ready; cần phiên bản được revalidation, không dùng completed thay điều kiện thực thi.')
    else:
        warnings.append('Đã duyệt nguồn kiểm kê cục bộ chỉ đọc. Chính sách thực thi yêu cầu agent Elevated.')
    if any(s['executor']['name']=='psh' for s in rows):warnings.append('psh dùng PowerShell EncodedCommand UTF-16LE để bảo toàn script; có thể sinh alert Base64. Source được giữ để đối chiếu.')
    warnings.append('Telemetry/detection chưa xác minh; operation finished không chứng minh SOC phát hiện hay hành vi đã xảy ra.')
    target_info={'id':profile['id'],'ip':target,'host':profile.get('os',{}).get('hostname'),'paw':agent['paw'] if agent else None}
    binding={'plan':sha(plan),'artifacts':ctx['artifacts'],'target':target_info,'scope':scope,'steps':rows,'policy':rules,'planner':planner,'adapter_sha256':sha({name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ('scenario_execution.py','execution_context.py','execution_contracts.py')})}
    return clean({'schema_version':VERSION,'ready':not errors,'checked_at':now(),'duration_seconds':round(time.monotonic()-started,3),'target':target_info,'scope':scope,
        'plan_sha256':next((x['sha256'] for x in ctx['artifacts'] if x['file']=='scenario_plan.yml'),sha(plan)),
        'binding_sha256':sha(binding),'survey':ctx['evidence'],'artifacts':ctx['artifacts'],'steps':rows,
        'planner':planner,'source_mode':'private_empty_no_inherited_facts','blockers':list(dict.fromkeys(errors)),
        'warnings':warnings,'policy':rules,'detection':'unknown','behavior_evidence':'not_evaluated'})


def preview(identifier,config,*,start_on_click=False):
    checked=preflight(identifier,config)
    if start_on_click and checked['ready'] and not (
        checked['scope'] == ['endpoint']
        and checked['steps']
        and all(step.get('runner_evidence') and (
                    is_inventory_command(step['command'])
                    or step['runner_evidence'].get('privilege_policy') == 'reviewed_local_inventory')
                for step in checked['steps'])
    ):
        checked['ready'] = False
        checked['blockers'].append('Chạy bằng một lần bấm chỉ hỗ trợ các bước kiểm kê cục bộ đã được xác minh.')
    execution_id=uuid.uuid4().hex;path=folder(execution_id);path.mkdir(parents=True)
    value={'schema_version':VERSION,'id':execution_id,'scenario_job_id':identifier,'state':'ready' if checked['ready'] else 'blocked',
           'created_at':now(),'target':checked['target'],'plan_sha256':checked['plan_sha256'],'operation_id':None,
           'steps':[{'index':s['index'],'name':s['name'],'state':'not_run'} for s in checked['steps']],
           'preflight':checked,'detection':'unknown','behavior_evidence':'not_evaluated','command_status':'not_run',
           'operation_url':None,'group_restored':False,'cleanup':'not_executed'}
    from .execution_contracts import validation, expected
    value['validation'] = validation(checked)
    save(path/'execution_validation.json', value['validation'])
    save(path/'execution_expected.json', expected(value))
    save(path/'execution_preflight.json',checked)
    save(path/'execution_request.json',{'schema_version':VERSION,'scenario_job_id':identifier,'plan_sha256':checked['plan_sha256'],
        'target':checked['target'],'scope':checked['scope'],'idempotency_key':execution_id,'created_at':value['created_at']})
    write(value)
    if start_on_click and checked['ready']:
        return confirm(execution_id, {
            'confirmed': True, 'target_ip': value['target']['ip'],
            'plan_sha256': value['plan_sha256'],
        }, config)
    return value


def confirm(identifier,data,config):
    with LOCK:
        value=read(identifier)
        if value['state']!='ready':return value  # same ID is a retry, never a new operation
        if data.get('confirmed') is not True or data.get('target_ip')!=value['target']['ip'] or data.get('plan_sha256')!=value['plan_sha256']:
            raise ValueError('Xác nhận phải trùng IP và hash của preview; không nhận target/quyền thực thi từ client.')
        if age(value['created_at'])>value['preflight']['policy']['preview_ttl_seconds']:raise ValueError('Preview hết hạn; kiểm tra lại.')
        if pending(value['target']['ip'],identifier):raise ValueError('Endpoint đang bận/cần phục hồi.')
        value.update(state='confirmed',confirmed_at=now(),confirmation={'plan_sha256':value['plan_sha256'],'target':value['target'],'scope':value['preflight']['scope']})
        write(value)
        worker=threading.Thread(target=run,args=(identifier,config),daemon=True)
        THREADS[identifier]=worker;worker.start()
        return value


def stop(identifier,config=None):
    with LOCK:
        value=read(identifier)
        if value['state'] not in RECOVERY:raise ValueError('Execution không đang chạy/cần phục hồi.')
        value.update(state='stop_requested',stop_requested_at=now())
        write(value)
        # A restarted controller can process an explicit stop, never resume.
        worker=THREADS.get(identifier)
        if config is not None and (worker is None or not worker.is_alive()):return reconcile(identifier,config)
        return value


def _stop_operation(api,value):
    oid=value['operation_id']
    if not oid:return []
    op=get_execution_operation(api,value)
    if op['state'] not in ('finished','out_of_time'):api.call('operations/'+oid,'PATCH',{'state':'paused'})
    links=api.call('operations/'+oid+'/links')
    validate_links(value,links)
    for link in links:
        if not link.get('collect') and not link.get('finish') and link['status'] not in (-2,-5):
            api.call('operations/'+oid+'/links/'+link['id'],'PATCH',{'status':-2})
    return links


def validate_links(value,links):
    allowed={x['execution_ability_id'] for x in value['mapping']}
    for link in links:
        if link['paw']!=value['target']['paw'] or link['ability']['ability_id'] not in allowed:raise ValueError('Link ngoài paw/ability đã duyệt.')
        if link.get('cleanup'):raise ValueError('Cleanup link ngoài kế hoạch adapter hỗ trợ.')
        match=next(x for x in value['mapping'] if x['execution_ability_id']==link['ability']['ability_id'])
        raw=link.get('command','')
        expected=match['command_sha256']
        # API displays base64-encoded command. Validate the actual command before dispatch.
        try:plain=base64.b64decode(raw,validate=True).decode('utf-8')
        except (ValueError,UnicodeDecodeError):plain=raw
        if hashlib.sha256(plain.encode()).hexdigest()!=expected:raise ValueError('Lệnh link khác artifact đã duyệt.')
    ids=[l['ability']['ability_id'] for l in links]
    if len(ids)!=len(set(ids)):raise ValueError('Link trùng cho cùng bước; cần phục hồi.')


def restore_group(api,value):
    if not value.get('group_change_intent'):return
    a=api.call('agents/'+value['target']['paw'])
    if a['group']==value['temporary_group']:
        api.call('agents/'+a['paw'],'PATCH',{'group':value['original_group']})
        value['group_restored']=api.call('agents/'+a['paw'])['group']==value['original_group']
    elif a['group']==value['original_group']:value['group_restored']=True
    else:raise ValueError('Group đã bị bên khác đổi; không ghi đè.')


def locate_operation(api,value):
    matches=[o for o in operations(api) if o['name']==value['operation_name'] and o['group']==value['temporary_group']]
    if len(matches)!=1:raise ValueError('Không xác định duy nhất operation sau POST; không POST lại.')
    value['operation_id']=matches[0]['id'];write(value)
    return matches[0]


def reconcile(identifier,config):
    with LOCK:
        if identifier in THREADS and THREADS[identifier].is_alive():return read(identifier)
        value=read(identifier)
        if value['state'] not in RECOVERY:return value
        api=api_for(config)
        try:
            if not value.get('operation_id'):
                if not value.get('operation_post_intent'):
                    restore_group(api,value);value.update(state='failed',error='Chưa POST operation; không tự tiếp tục.')
                    write(value);return value
                locate_operation(api,value)
            op=get_execution_operation(api,value)
            ensure_members(value,op)
            if value.get('stop_requested_at'):
                links=_stop_operation(api,value)
                if any(l.get('collect') and not l.get('finish') for l in links):
                    value.update(state='recovery_required',error='Lệnh đã dispatch còn chạy; pause không hủy lệnh đó.')
                else:
                    if op['state'] not in ('finished','out_of_time'):api.call('operations/'+op['id'],'PATCH',{'state':'finished'})
                    restore_group(api,value);value.update(state='stopped',command_status='stopped')
            elif op['state'] in ('finished','out_of_time'):
                links=api.call('operations/'+op['id']+'/links');validate_links(value,links)
                # Recovered output is not treated as verified success without collection.
                restore_group(api,value);value.update(state='failed',error='Operation đã kết thúc khi gián đoạn; kết quả cần đối chiếu thủ công.',command_status='unknown')
            else:value.update(state='recovery_required',error='Operation còn mở; không tự resume/dispatch. Có thể yêu cầu dừng rồi đối soát.')
        except Exception as error:value.update(state='recovery_required',error=redact(str(error)))
        write(value);return value


def ensure_members(value,op):
    if {a['paw'] for a in op.get('host_group',[])}!={value['target']['paw']} or op.get('group')!=value['temporary_group']:
        raise ValueError('Membership operation không đúng duy nhất paw đã duyệt.')


def assert_artifacts_unchanged(value):
    source=bridge.directory(value['scenario_job_id'])
    job=bridge.read(source/'job.json',{})
    if job.get('deleted_at') or job.get('status')!='completed':raise ValueError('Scenario bị xóa hoặc không còn completed.')
    for item in value['preflight']['artifacts']:
        path=bridge.checked_download(source,item['file'])
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
            raise ValueError('Artifact/hash thay đổi trước dispatch: '+item['file'])


def collect_results(api,value,links,config):
    validate_links(value,links)
    for row,match in zip(value['steps'],value['mapping']):
        matches=[l for l in links if l['ability']['ability_id']==match['execution_ability_id']]
        if not matches:continue
        link=matches[0]
        if row.get('state')=='completed' and row.get('finished_at')==link.get('finish'):continue
        row.update(process_id=link.get('pid'),link_id=link['id'],state='dispatched' if link.get('collect') else 'pending',collected_at=link.get('collect'),finished_at=link.get('finish'))
        if not link.get('finish'):continue
        result=api.call('operations/'+value['operation_id']+'/links/'+link['id']+'/result')
        raw=result.get('result') or ''
        if len(raw)>policy(config)['max_output_bytes']*2:raise ValueError('Output quá lớn; không lưu raw response.')
        try:output=json.loads(base64.b64decode(raw,validate=True).decode('utf-8-sig'))
        except (ValueError,UnicodeDecodeError):raise ValueError('Kết quả executor thiếu/không hợp lệ.') from None
        row.update(state='completed' if link['status']==0 and str(output.get('exit_code'))=='0' else 'error',exit_code=output.get('exit_code'),
                   stdout=safe_text(output.get('stdout',''),limit=policy(config)['max_output_bytes']),stderr=safe_text(output.get('stderr',''),limit=policy(config)['max_output_bytes']))
        if row['state']=='error':raise ValueError('Bước '+str(row['index'])+' trả lỗi; không gửi bước sau.')
    for n,row in enumerate(value['steps']):
        if row['state']=='pending':
            if not all(x['state']=='completed' for x in value['steps'][:n]):
                if any(l.get('collect') for l in links if l['id']==row['link_id']):raise ValueError('Bước chạy sai thứ tự.')
                continue
            with LOCK:
                if read(value['id']).get('stop_requested_at'):return
                assert_artifacts_unchanged(value)
                a=api.call('agents/'+value['target']['paw'])
                if a.get('group')!=value['temporary_group'] or not a.get('trusted') or value['target']['ip'] not in a.get('host_ip_addrs',[]) or a.get('host','').lower()!=value['target']['host'].lower() or not -60<=age(a['last_seen'])<=policy(config)['agent_max_age_seconds']:
                    raise ValueError('Agent/group/heartbeat thay đổi trước dispatch.')
                requirement=value['preflight']['steps'][n]
                if requirement['executor']['platform']!=a.get('platform') or requirement['executor']['name'] not in a.get('executors',[]):raise ValueError('Executor thay đổi trước dispatch.')
                if str(requirement.get('required_privilege') or '').lower() in ('elevated','admin','administrator','root','system') and str(a.get('privilege','')).lower() not in ('elevated','root','system'):raise ValueError('Privilege thay đổi trước dispatch.')
                api.call('operations/'+value['operation_id']+'/links/'+row['link_id'],'PATCH',{'status':-3})
                row['state']='sent'
            break


def run(identifier,config):
    value=read(identifier);api=api_for(config);held=False;operation_may_exist=False
    try:
        with InstanceLock(endpoint_activity_path(value['target']['ip'])), InstanceLock(endpoint_runner_path(value['target']['ip'])):
            held=True
            if read(identifier).get('stop_requested_at'):value.update(state='stopped');write(value);return
            ctx=context_for(value['scenario_job_id'],config)
            fresh=preflight(value['scenario_job_id'],config,api,ctx,exclude=identifier)
            api.deadline=None
            if not fresh['ready'] or fresh['binding_sha256']!=value['preflight']['binding_sha256'] or age(value['created_at'])>fresh['policy']['preview_ttl_seconds']:
                value.update(state='blocked',error='Preflight/hash/target đã đổi hoặc preview hết hạn; xem kiểm tra mới.',preflight=fresh);write(value);return
            from .execution_contracts import verify_expected, expected
            contract_path=folder(identifier)/'execution_expected.json'
            if contract_path.exists():
                contract=bridge.read(contract_path)
                verify_expected(contract,value)
                if contract!=expected(value):raise ValueError('Expected contract differs from validated source')
            agent=api.call('agents/'+value['target']['paw'])
            value.update(state='registering',original_group=agent['group'],temporary_group='scenario-'+identifier,
                         operation_name='Scenario execution '+identifier,mapping=[])
            write(value)
            api.deadline=time.monotonic()+90
            # Always new per-step IDs: no overwrite of shared abilities; repeated
            # source IDs remain separate steps under atomic planner semantics.
            private=[]
            for item in ctx['steps']:
                source=item['record']['ability'];ex=item['executor'];exec_id=str(uuid.uuid4())
                command=execution_command(ex)
                private.append({'ability_id':exec_id,'name':'Scenario '+identifier+' step '+str(item['step']['step_index']),
                    'description':'Verified source '+item['record']['canonical_id'],'tactic':source.get('tactic') or 'execution',
                    'technique_id':source.get('technique_id') or 'T1059','technique_name':source.get('technique_name') or 'Command execution',
                    'privilege':source.get('privilege'),'repeatable':False,'requirements':[],'delete_payload':False,
                    'executors':[{'name':ex['name'],'platform':ex['platform'],'command':command,'timeout':min(120,int(ex.get('timeout') or 60)),
                                  'parsers':[],'payloads':[],'uploads':[],'cleanup':[]}]})
                value['mapping'].append({'index':item['step']['step_index'],'source_ability_id':item['record']['canonical_id'],
                    'source':item['record']['provenance'],'execution_ability_id':exec_id,'command_sha256':hashlib.sha256(command.encode()).hexdigest()})
            adv_id=str(uuid.uuid4());source_id=str(uuid.uuid4())
            manifest={'schema_version':VERSION,'execution_id':identifier,'plan_sha256':value['plan_sha256'],'survey':fresh['survey'],
                'artifacts':fresh['artifacts'],'mapping':value['mapping'],'adversary_id':adv_id,'source_id':source_id,'target':value['target'],
                'planner':fresh['planner'],'cleanup':'none_supported','transport':'psh_utf16le_encodedcommand_other_single_line_literal'}
            save(folder(identifier)/'execution_manifest.json',clean(manifest));write(value)
            for ability in private:
                api.call('abilities','POST',ability)
                actual=api.call('abilities/'+ability['ability_id'])
                if actual['executors'][0]['command']!=ability['executors'][0]['command']:raise ValueError('Registration command mismatch.')
            adv={'adversary_id':adv_id,'name':value['operation_name'],'description':'Explicit confirmed scenario '+identifier,
                 'atomic_ordering':[a['ability_id'] for a in private]}
            api.call('adversaries','POST',adv)
            api.call('sources','POST',{'id':source_id,'name':value['operation_name'],'facts':[],'rules':[],'relationships':[]})
            if read(identifier).get('stop_requested_at'):value.update(state='stopped');write(value);return
            # Journal before any group mutation, including uncertain PATCH responses.
            value['group_change_intent']=True;write(value)
            api.call('agents/'+value['target']['paw'],'PATCH',{'group':value['temporary_group']})
            members=api.call('agents?include=paw&include=group')
            if {a['paw'] for a in members if a.get('group')==value['temporary_group']}!={value['target']['paw']}:raise ValueError('Private group membership mismatch.')
            request={'name':value['operation_name'],'group':value['temporary_group'],'adversary':{'adversary_id':adv_id},
                'planner':{'id':fresh['planner']['id']},'source':{'id':source_id},'state':'paused','autonomous':0,'auto_close':True,
                'obfuscator':'plain-text','jitter':'2/4','use_learning_parsers':False}
            value.update(state='creating_operation',operation_post_intent=now());write(value)
            operation_may_exist=True
            try:
                op=api.call('operations','POST',request)
                value['operation_id']=op['id'];write(value)
            except Exception:
                locate_operation(api,value)
                # A lost response never grants permission to dispatch automatically.
                raise ValueError('Đã reconcile operation sau POST không chắc chắn; cần người dùng đối soát, không tự dispatch.')
            op=get_execution_operation(api,value);ensure_members(value,op)
            if op.get('adversary',{}).get('atomic_ordering')!=adv['atomic_ordering']:raise ValueError('Operation ordering mismatch.')
            api.deadline=None
            if read(identifier).get('stop_requested_at'):value['stop_requested_at']=read(identifier)['stop_requested_at']
            else:api.call('operations/'+value['operation_id'],'PATCH',{'state':'running'})
            value.update(state='running',operation_url=config['caldera_url'].rstrip('/')+'/#operations')
            write(value)
            deadline=time.monotonic()+policy(config)['timeout_seconds'];backoff=1
            while time.monotonic()<deadline:
                persisted=read(identifier)
                if persisted.get('stop_requested_at'):value['stop_requested_at']=persisted['stop_requested_at']
                op=get_execution_operation(api,value);ensure_members(value,op)
                links=api.call('operations/'+value['operation_id']+'/links')
                if value.get('stop_requested_at'):
                    links=_stop_operation(api,value)
                    if not any(l.get('collect') and not l.get('finish') for l in links):
                        if op['state'] not in ('finished','out_of_time'):api.call('operations/'+op['id'],'PATCH',{'state':'finished'})
                        value.update(state='stopped',command_status='stopped');break
                    value['state']='stop_requested'
                else:
                    collect_results(api,value,links,config)
                    if op['state'] in ('finished','out_of_time'):
                        if all(s['state']=='completed' for s in value['steps']):value.update(state='completed',command_status='success')
                        else:
                            for s in value['steps']:
                                if s['state'] not in ('completed','error'):s['state']='skipped'
                            value.update(state='failed',command_status='incomplete',error='Operation kết thúc nhưng thiếu bước thành công.')
                        break
                save(folder(identifier)/'operation-summary.json',{'schema_version':VERSION,'id':op['id'],'state':op['state'],
                    'paw':value['target']['paw'],'steps':clean(value['steps']),'checked_at':now()})
                write(value);time.sleep(backoff);backoff=min(5,backoff+1)
            else:raise TimeoutError('Hết thời gian theo dõi; cần dừng/đối soát lệnh đã dispatch.')
            restore_group(api,value)
            save(folder(identifier)/'operation-summary.json',{'schema_version':VERSION,'id':op['id'],'operation_state':op['state'],'execution_state':value['state'],'command_status':value['command_status'],'steps':clean(value['steps']),'checked_at':now()})
            write(value)
    except Exception as error:
        api.deadline=None
        value.update(state='recovery_required' if operation_may_exist or value.get('operation_id') else 'failed',error=redact(str(error)))
        if value.get('operation_id'):
            try:_stop_operation(api,value)
            except Exception:pass
        if not operation_may_exist and held:
            try:restore_group(api,value)
            except Exception as e:value.update(state='recovery_required',error=redact(str(e)))
        write(value)
    finally:
        with LOCK:THREADS.pop(identifier,None)
