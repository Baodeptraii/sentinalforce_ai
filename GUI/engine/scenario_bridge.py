"""Planning-only bridge. Survey evidence is immutable; scope is a separate policy."""
import copy
import hashlib
import ipaddress
import importlib.util
import json
import os
import re
import signal
import shutil
import time
import subprocess
import threading
import uuid
from pathlib import Path

from .runner import save
from .survey import ROOT, now
from .contracts import TargetProfile
from .llm import redact

OUTPUTS = ROOT / 'scenario_outputs'
LOCK = threading.RLock()
ACTIVE = None
RESUMABLE = {'waiting_budget','budget_exceeded','needs_information', 'waiting_service', 'waiting_quota', 'error', 'invalid_plan', 'insufficient_coverage'}
DOWNLOADS = {'token_metrics.json','grounding_diagnostics.json', 'behavior_analysis.json', 'behavior_coverage.json', 'input/input_manifest.json', 'input/input_envelope.json', 'input/survey/scenario_handoff.json',
             'input/survey/survey_context.json', 'input/survey/target_profile_v2.json', 'context_selection.json',
             'evidence_registry.json', 'compatibility_report.json', 'validation_report.json', 'step_evidence.json', 'scenario_plan.yml', 'request.json', 'policy.json', 'target_profile.json', 'planning_target.json', 'provenance.json', 'result.json'}


def input_module(root):
    spec = importlib.util.spec_from_file_location('_scenario_survey_input', root/'scenario_agent/survey_input.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def survey_snapshot(identifier, loader):
    if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{32}', identifier):
        raise ValueError('Invalid Survey run ID')
    run = ROOT/'outputs'/identifier
    if not run.is_dir() or run.is_symlink(): raise ValueError('Survey run unavailable')
    primary = run/'survey_v2'
    if primary.exists():
        bundle = loader.load_bundle(primary)
        if bundle['survey_context']['survey_run_id'] != identifier: raise ValueError('Survey snapshot/run identity mismatch')
        return bundle
    # Historical offline conversions live under the fixed project review directory.
    for path in sorted((ROOT/'review').glob('*/scenario_handoff.json')):
        manifest = read(path, {})
        if manifest.get('survey_run_id') == identifier: return loader.load_bundle(path.parent)
    raise ValueError('Survey v2 snapshot missing; convert the historical run offline or explicitly upload a legacy profile')


def checked_download(folder, name):
    if read(folder/'job.json', {}).get('deleted_at'): raise ValueError('Scenario deleted.')
    if name in DOWNLOADS:
        path = folder/name
    elif name.startswith('input/survey/'):
        relative = name[len('input/survey/'):]
        manifest = read(folder/'input/survey/scenario_handoff.json', {})
        allowed = {entry['file'] for entry in manifest.get('artifacts', [])}
        if relative not in allowed: raise ValueError('File unavailable')
        path = folder/name
    else: raise ValueError('File unavailable')
    if path.is_symlink() or folder.resolve() not in path.resolve().parents or any(p.is_symlink() for p in path.parents):
        raise ValueError('Invalid download path')
    return path


def directory(identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{32}', identifier):
        raise ValueError('Invalid scenario job ID')
    folder = OUTPUTS / identifier
    if any(p.is_symlink() for p in (folder, *folder.parents)):
        raise ValueError('Invalid scenario storage path')
    return folder


def read(path, fallback=None):
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else fallback


def public(identifier):
    folder = directory(identifier)
    job = read(folder / 'job.json')
    if not job or job.get('deleted_at'):
        raise ValueError('Không tìm thấy lượt lập kế hoạch.')
    progress = read(folder / 'progress.json', {})
    if job['status'] in ('running', 'cancelling'):
        job['phase'] = progress.get('phase', 'starting')
        job['events'] = progress.get('events', [])
        job['token_metrics']=progress.get('token_metrics')
        for state_path in (folder/'runs').glob('*/state.json'):
            if state_path.is_symlink() or any(p.is_symlink() for p in state_path.parents):continue
            if read(state_path,{}).get('run_id')==progress.get('run_id'):
                job['token_metrics']=read(state_path.parent/'token_metrics.json',job['token_metrics'])
                break
    job['result'] = {} if job['status'] in ('running', 'cancelling') else read(folder / 'result.json', {})
    # Expose the effective request for historical jobs without changing saved files.
    result = job['result']
    if result.get('run_id') and 'analyzed_behaviors' not in result:
        for state_path in (folder/'runs').glob('*/state.json'):
            if state_path.is_symlink() or any(p.is_symlink() for p in state_path.parents): continue
            if folder.resolve() not in state_path.resolve().parents: continue
            state = read(state_path, {})
            if state.get('run_id') == result['run_id']:
                result['effective_request_text'] = state.get('text', '')
                result['analyzed_behaviors'] = state.get('behavior_analysis', {}).get('behaviors', [])
                break
    job['saved_to_library'] = (ROOT/'scenario_library'/(identifier+'.json')).is_file()
    job['execution_supported'] = True
    from . import scenario_execution
    latest = scenario_execution.history(identifier)
    job['execution_id'] = latest[0]['id'] if latest else None
    job['files'] = sorted(name for name in DOWNLOADS if (folder / name).is_file())
    manifest = read(folder/'input/survey/scenario_handoff.json', {})
    job['files'] += ['input/survey/'+row['file'] for row in manifest.get('artifacts', []) if row['file'] not in ('ai_trace.json',)]
    provenance = read(folder/'provenance.json', {})
    job['input_source'] = provenance.get('source', 'legacy_profile')
    job['survey'] = {k: provenance.get(k) for k in ('survey_run_id', 'survey_finished_at', 'evidence_quality')}
    if job['status'] == 'completed' and (folder / 'scenario_plan.yml').is_file():
        job['yaml'] = (folder / 'scenario_plan.yml').read_text(encoding='utf-8')
    return job


def history():
    rows = [read(p) for p in OUTPUTS.glob('*/job.json') if not p.is_symlink() and not p.parent.is_symlink()]
    rows = [row for row in rows if row and not row.get('deleted_at')]
    return sorted(rows, key=lambda j: j['created_at'], reverse=True)[:100]


def initialize():
    OUTPUTS.mkdir(exist_ok=True)
    for path in OUTPUTS.glob('*/job.json'):
        job = read(path)
        if job['status'] in ('running', 'cancelling'):
            job.update(status='interrupted', error='Backend restarted; start a new plan from the saved request.')
            save(path, job)


def adapt(data, config):
    profile = data.get('profile')
    TargetProfile.model_validate(profile)
    address = ipaddress.ip_address(profile['address'])
    if not any(address in ipaddress.ip_network(n) for n in config['allowed_networks']):
        raise ValueError('Target nằm ngoài phạm vi cấu hình.')
    text = data.get('text')
    if not isinstance(text, str) or not 1 <= len(text.strip()) <= 4000:
        raise ValueError('Yêu cầu phải có từ 1 đến 4000 ký tự.')
    scope = data.get('scope')
    if not isinstance(scope, list) or not scope or any(x not in ('endpoint', 'web') for x in scope):
        raise ValueError('Chọn phạm vi lập kế hoạch.')
    count = data.get('max_steps')
    if type(count) is not int or not 1 <= count <= 20:
        raise ValueError('Số bước phải từ 1 đến 20.')
    policy = {'version': 'survey_scenario_adapter_v1', 'mode': 'plan_only',
              'target_id': profile['id'], 'target_ip': profile['address'],
              'planning_scope': sorted(set(scope)), 'max_steps': count,
              'execution_authorized': False, 'cleanup_required': True, 'rollback_required': True}
    adapted = copy.deepcopy(profile)
    # Legacy Scenario validator reads this field even in plan_only. This bridge
    # supplies selected planning surfaces, never runtime permission or dummy paths.
    adapted['capabilities']['execution_scope'] = {
        'allowed_surfaces': policy['planning_scope'], 'allowed_targets': [profile['address']],
        'mode': 'plan_only', 'execution_authorized': False,
        'basis': 'GUI planning selection; execution requires separate authorization and preflight.'}
    return copy.deepcopy(profile), adapted, policy


def evidence_for(profile):
    for path in (ROOT / 'outputs').glob('*/target_profile.json'):
        if read(path) != profile:
            continue
        handoff = read(path.parent / 'handoff.json')
        if not handoff:
            continue
        if handoff.get('target_ip') != profile['address']:
            raise ValueError('Handoff target mismatch')
        for row in handoff.get('evidence', []):
            file = (path.parent / row['file']).resolve()
            if path.parent.resolve() not in file.parents or file.is_symlink() or not file.is_file():
                raise ValueError('Invalid evidence reference')
            if hashlib.sha256(file.read_bytes()).hexdigest() != row['sha256']:
                raise ValueError('Survey evidence hash mismatch: ' + row['file'])
        return {'source': 'survey_run', 'survey_run_id': path.parent.name,
                'handoff_sha256': hashlib.sha256((path.parent / 'handoff.json').read_bytes()).hexdigest(),
                'profile_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'evidence_hashes_checked': len(handoff['evidence']),
                'handoff': handoff, 'evidence_root': str(path.parent)}
    return {'source': 'uploaded_profile', 'evidence_verified': False,
            'limitation': 'Uploaded profile has no matching local survey handoff.'}


def start(data, config, resume_id=None):
    global ACTIVE
    root = Path(config.get('scenario_root', '/home/soc/build_scenario_agent')).resolve()
    python = root / '.venv/bin/python'
    if not python.is_file() or not (root / 'data/catalog.sqlite').is_file():
        raise ValueError('Scenario runtime/catalog unavailable.')
    with LOCK:
        if ACTIVE:
            raise ValueError('Một lượt lập kế hoạch đang chạy; đợi kết thúc.')
        if resume_id:
            folder = directory(resume_id)
            job = read(folder / 'job.json')
            result = read(folder / 'result.json', {})
            if not job or job.get('deleted_at') or job['status'] not in RESUMABLE or not result.get('run_id'):
                raise ValueError('Lượt này không thể tiếp tục.')
            clarification = data.get('clarification', '')
            if not isinstance(clarification, str) or len(clarification) > 4000:
                raise ValueError('Bổ sung quá dài.')
            if (folder/'input/input_manifest.json').is_file():
                loader = input_module(root)
                loader.verify_snapshot(folder/'input', job.get('input_manifest_sha256'))
                if job.get('adapter_version') != loader.ADAPTER: raise ValueError('Adapter changed; create a new job from saved request')
            elif job.get('adapter_version'):
                raise ValueError('Input snapshot missing; create a new job from saved request')
            save(folder / 'resume.json', {'run_id': result['run_id'], 'clarification': clarification})
            job.update(status='running', error=None)
        else:
            loader = input_module(root)
            if data.get('input_kind') == 'survey_v2' and not data.get('survey_run_id'): raise ValueError('Survey v2 cần survey_run_id; không hạ xuống profile_only.')
            source = survey_snapshot(data['survey_run_id'], loader) if data.get('survey_run_id') else None
            from . import fixed_case_registry
            from .runtime_fixed_cases import CASE_SCOPE, CASE_CHAINS, CASE_TITLES, CASE_REQUEST_TEXT
            if data.get('case_id'):
                fixed = fixed_case_registry.resolve_case(data['case_id'])
            else:
                fixed = fixed_case_registry.classify_case(data.get('text') or '')
            user_text = data.get('text')
            if fixed:
                case_id = fixed['case_id']
                data = dict(data, text=CASE_REQUEST_TEXT[case_id], scope=list(CASE_SCOPE[case_id]),
                            max_steps=len(CASE_CHAINS[case_id]))
            incoming = dict(data)
            if source: incoming['profile'] = loader.planning_target(source)
            profile, adapted, policy = adapt(incoming, config)
            if source:
                policy = loader.policy_for(profile, policy['planning_scope'], policy['max_steps'])
                if not set(policy['planning_scope']).issubset(source['survey_context']['scope']):
                    raise ValueError('Planning scope exceeds Survey scope')
                provenance = {'source': 'survey_v2', 'survey_run_id': source['survey_context']['survey_run_id'],
                              'evidence_quality': source['evidence_quality'], 'survey_finished_at': source['survey_context']['finished_at'],
                              'manifest_file': 'input/survey/scenario_handoff.json', 'hashes_describe': 'sanitized_snapshot_bytes'}
            else:
                provenance = {'source': 'profile_only', 'evidence_verified': False,
                              'limitation': 'Legacy profile only; no evidence registry or verified bindings.'}
            identifier = uuid.uuid4().hex
            folder = directory(identifier)
            folder.mkdir(parents=True)
            if fixed:
                save(folder / 'fixed_case.json', {'case_id': fixed['case_id'], 'spec_version': fixed['spec_version'],
                     'matched_by': fixed['matched_by'], 'user_text': user_text,
                     'title': CASE_TITLES[fixed['case_id']]})
            for name, value in [('target_profile.json', profile), ('planning_target.json', adapted),
                                ('policy.json', policy), ('provenance.json', provenance),
                                ('request.json', {'text': data['text'], 'scope': policy['planning_scope'], 'max_steps': policy['max_steps'], 'survey_run_id':data.get('survey_run_id'), 'input_kind':'survey_v2' if source else 'profile_only'})]:
                save(folder / name, value)
            input_manifest = loader.snapshot(source, folder/'input', {'text': data['text']}, policy) if source else None
            job = {'id': identifier, 'status': 'running', 'created_at': now(),
                   'target_id': profile['id'], 'target_ip': profile['address'], 'text': data['text'],
                   'mode': 'plan_only', 'execution_authorized': False,
                   'fixed_case': {'case_id': fixed['case_id'], 'title': CASE_TITLES[fixed['case_id']],
                                  'matched_by': fixed['matched_by']} if fixed else None}
            if input_manifest:
                job.update(adapter_version=loader.ADAPTER, input_manifest_sha256=hashlib.sha256((folder/'input/input_manifest.json').read_bytes()).hexdigest())
        save(folder / 'job.json', job)
        ACTIVE = job['id']
        threading.Thread(target=run_worker, args=(folder, root, python, bool(resume_id)), daemon=True).start()
        return {'id': job['id']}


def cancel(identifier):
    with LOCK:
        folder = directory(identifier)
        job = read(folder/'job.json')
        if not job or job.get('deleted_at') or job['status'] not in ('running', 'cancelling'):
            raise ValueError('Lượt này không còn đang sinh kịch bản.')
        (folder/'cancel.requested').touch()
        job.update(status='cancelling')
        save(folder/'job.json', job)
        return {'id':identifier, 'status':'cancelling'}


def delete(identifier):
    # Soft deletion keeps evidence recoverable; saved library entries are independent.
    with LOCK:
        folder = directory(identifier)
        job = read(folder/'job.json')
        if not job: raise ValueError('Không tìm thấy lượt lập kế hoạch.')
        from . import scenario_execution
        if any(e['scenario_job_id']==identifier for e in scenario_execution.pending()):raise ValueError('Kịch bản có execution đang chạy/cần phục hồi; dừng và đối soát trước khi xóa.')
        if job['status'] in ('running', 'cancelling') or ACTIVE == identifier:
            raise ValueError('Hủy lượt đang sinh và chờ dừng trước khi xóa.')
        if not job.get('deleted_at'):
            job['deleted_at'] = now()
            save(folder/'job.json', job)
        return {'id':identifier, 'status':'deleted'}


def regenerate(identifier, config):
    """New job, same frozen Survey/profile and effective clarified request."""
    global ACTIVE
    root = Path(config.get('scenario_root', '/home/soc/build_scenario_agent')).resolve()
    python = root/'.venv/bin/python'
    if not python.is_file() or not (root/'data/catalog.sqlite').is_file():
        raise ValueError('Scenario runtime/catalog unavailable.')
    with LOCK:
        if ACTIVE: raise ValueError('Một lượt lập kế hoạch đang chạy; đợi kết thúc.')
        original = public(identifier)
        if original['status'] in ('running', 'cancelling'): raise ValueError('Chờ hoặc hủy lượt đang sinh trước khi tạo lại.')
        source = directory(identifier)
        request = read(source/'request.json')
        profile = read(source/'target_profile.json')
        adapt(dict(request, profile=profile), config)  # Enforce current target allowlist.
        names = ['target_profile.json', 'planning_target.json', 'policy.json', 'provenance.json', 'request.json']
        for name in names: checked_download(source, name)
        marker = source / 'fixed_case.json'
        if marker.is_file():
            if marker.is_symlink() or source.resolve() not in marker.resolve().parents:
                raise ValueError('Invalid marker path')
            names.append('fixed_case.json')
        frozen = source/'input'
        if original.get('adapter_version') and not frozen.is_dir(): raise ValueError('Input snapshot missing.')
        if frozen.exists():
            if any(p.is_symlink() for p in [frozen, *frozen.rglob('*')]): raise ValueError('Snapshot symlink refused.')
            input_module(root).verify_snapshot(frozen, original.get('input_manifest_sha256'))
        new_id = uuid.uuid4().hex
        folder = directory(new_id); folder.mkdir(parents=True)
        try:
            for name in names: shutil.copyfile(source/name, folder/name)
            if frozen.exists(): shutil.copytree(frozen, folder/'input')
            effective = original.get('result', {}).get('effective_request_text')
            previous_context = read(source/'regeneration_context.json', {})
            effective = effective or previous_context.get('effective_request_text')
            if effective:
                if not isinstance(effective, str) or len(effective)>32000: raise ValueError('Invalid effective request.')
                save(folder/'regeneration_context.json', {'effective_request_text':effective, 'parent_job_id':identifier})
            job = {k: original[k] for k in ('target_id', 'target_ip', 'text', 'adapter_version', 'input_manifest_sha256') if k in original}
            job.update(id=new_id, parent_job_id=identifier, status='running', created_at=now(), mode='plan_only', execution_authorized=False)
            save(folder/'job.json', job)
        except Exception:
            shutil.rmtree(folder)
            raise
        ACTIVE = new_id
        threading.Thread(target=run_worker, args=(folder, root, python, False), daemon=True).start()
        return {'id':new_id, 'parent_job_id':identifier}


def stop_worker(process):
    if process.poll() is None:
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()


def run_worker(folder, root, python, resume):
    global ACTIVE
    job = read(folder / 'job.json')
    process = None
    try:
        command = [str(python), '-B', str(ROOT / 'engine/scenario_worker.py'), str(root), str(folder)]
        if resume:
            command.append('--resume')
        with (folder / 'worker.log').open('a', encoding='utf-8') as log:
            env = dict(os.environ, GEMINI_PROGRESS='1', PYTHONUNBUFFERED='1', HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1')
            if not (folder/'cancel.requested').exists():
                process = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=log, start_new_session=True)
                deadline = time.monotonic()+900
                while process.poll() is None:
                    if (folder/'cancel.requested').exists():
                        stop_worker(process)
                        break
                    if time.monotonic() >= deadline:
                        stop_worker(process)
                        raise ValueError('Scenario exceeded 15-minute limit; evidence retained.')
                    try: process.wait(timeout=.25)
                    except subprocess.TimeoutExpired: pass
        if (folder/'cancel.requested').exists():
            job['status'] = 'cancelled'
            return
        result = read(folder / 'result.json', {})
        if process.returncode or not result.get('status'):
            raise ValueError('Scenario worker failed; inspect server-side worker.log.')
        job['status'] = result['status']
    except Exception as exc:
        job.update(status='error', error=redact(str(exc)))
    finally:
        with LOCK:
            if (folder/'cancel.requested').exists(): job.update(status='cancelled', error=None)
            job['finished_at'] = now()
            save(folder/'job.json', job)
            if ACTIVE == job['id']: ACTIVE = None
