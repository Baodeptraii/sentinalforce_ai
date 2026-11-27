"""Persist generated plans in the GUI library; execution delegates to an explicit-confirmation controller."""
import hashlib
import json
import subprocess
from pathlib import Path
from . import scenario_bridge as bridge
from .runner import save
from .survey import now


def library_folder():
    folder=bridge.ROOT/'scenario_library'
    if any(p.is_symlink() for p in (folder, *folder.parents)): raise ValueError('Invalid library path.')
    return folder


def library():
    entries=[]
    with bridge.LOCK:
        for path in sorted(library_folder().glob('*.json')):
            if path.is_symlink(): continue
            entry=bridge.read(path)
            if entry: entries.append(entry)
    return {'items':entries, 'total':len(entries)}


def inspect_plan(path, config):
    root=Path(config.get('scenario_root','/home/soc/build_scenario_agent')).resolve()
    try:
        result=subprocess.run([str(root/'.venv/bin/python'), '-B', str(Path(__file__).with_name('scenario_worker.py')),
             '--inspect-plan',str(root),str(path)],capture_output=True,text=True,timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Không kiểm tra được schema kế hoạch; kiểm tra Scenario runtime.') from None
    if result.returncode: raise ValueError('Kế hoạch chưa đạt schema ScenarioPlan; chưa thể thêm vào kho.')
    return json.loads(result.stdout)


def add_to_library(identifier, config):
    with bridge.LOCK:
        job=bridge.public(identifier)
        if job['status']!='completed': raise ValueError('Chỉ thêm được kịch bản đã sinh hoàn tất.')
        source=bridge.directory(identifier)
        path=bridge.checked_download(source,'scenario_plan.yml')
        if not path.is_file() or path.stat().st_size>2_000_000: raise ValueError('File kế hoạch không hợp lệ.')
        raw=path.read_bytes();digest=hashlib.sha256(raw).hexdigest()
        folder=library_folder();destination=folder/(identifier+'.json')
        if destination.is_symlink(): raise ValueError('Invalid library entry.')
        existing=bridge.read(destination)
        if existing:
            if existing['sha256']!=digest: raise ValueError('Bản đã lưu khác nội dung hiện tại; tạo lượt mới để lưu phiên bản khác.')
            return {'status':'already_saved','item':existing}
        info=inspect_plan(path,config)
        existing_ids = {x['id'] for x in bridge.read(bridge.ROOT/'static/scenario-data.json', {}).get('items', [])}
        existing_ids.update(x['id'] for x in library()['items'])
        if info['id'] in existing_ids: raise ValueError('ID kịch bản đã có trong kho; tạo lượt mới để lưu bản riêng.')
        request=bridge.read(source/'request.json')
        effective=job.get('result',{}).get('effective_request_text') or request['text']
        entry={'id':info['id'],'name':info['name'],'description':info['description'],'family':'generated',
            'scope':request['scope'],'abilities':info['atomic_ordering'],'yaml':raw.decode('utf-8'),
            'file':'scenario_library/'+destination.name,'job_id':identifier,'saved_at':now(),'sha256':digest,
            'request':request,'effective_request_text':effective,
            'profile':bridge.read(source/'target_profile.json'),
            'survey_run_id':job.get('survey',{}).get('survey_run_id') if job.get('input_source')=='survey_v2' else None,
            'execution_authorized':False}
        folder.mkdir(exist_ok=True)
        save(destination,entry)
        return {'status':'saved','item':entry}


def execute(identifier, config, *, start_on_click=False):
    from .scenario_execution import preview
    if start_on_click:
        return preview(identifier, config, start_on_click=True)
    return preview(identifier, config)
