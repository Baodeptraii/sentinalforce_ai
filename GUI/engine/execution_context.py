"""Read-only runtime helper. Run with Scenario Python; never calls an LLM or CALDERA."""
import hashlib
import copy
import json
import sys
from pathlib import Path
import re

REVIEWED_INVENTORY = {
    'f8de05d1741dcc468f772ab0ff4dac72': (
        'b1e6e8fbdfccdac5272e8448ce3a5c068fe7dcbe012dd01027371941b238bf4f', 'tasklist'),
    'a6bff7612c9f5dec9c44574181feac26': (
        'a663dffdf90c8d17b588ef389a01a24144b45191ff22eb78dc641f5e67c96139', 'powershell.exe Get-Service'),
    'dca8b042fcdffcc1f5cddcff4122c434': (
        '43dd478d4df62b1b346111f786dfdc6350031f30954541422bd860943d83e627',
        r'systeminfo && reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum'),
}


def is_reviewed_inventory(record, executor):
    if not record or not executor:
        return False
    expected = REVIEWED_INVENTORY.get(record['canonical_id'])
    return (
        expected is not None
        and (executor['platform'], executor['name']) == ('windows', 'cmd')
        and expected == (record['provenance']['revision'], executor.get('command'))
    )


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect(root, folder):
    import yaml
    sys.path.insert(0,str(root))
    from scenario_agent.models import validate_contract
    from scenario_agent.catalog import ability, connect
    from scenario_agent.config import Config
    from scenario_agent.survey_input import verify_snapshot
    from scenario_agent.target_evidence import catalog_handles
    plan=yaml.safe_load((folder/'scenario_plan.yml').read_text())
    validate_contract(root,'plan',plan)
    profile=json.loads((folder/'planning_target.json').read_text())
    policy=json.loads((folder/'policy.json').read_text())
    job=json.loads((folder/'job.json').read_text())
    problems=[];evidence={'verified':False,'detection':'unknown'}
    if plan['metadata']['target_id']!=profile['id'] or policy['target_id']!=profile['id'] or policy['target_ip']!=profile['address']:
        problems.append('Target của plan/profile/policy không trùng khớp.')
    if len(plan['atomic_ordering'])!=len(plan['metadata']['steps']) or plan['atomic_ordering']!=[s['ability_id'] for s in plan['metadata']['steps']]:
        problems.append('Thứ tự/ID bước không khớp atomic_ordering.')
    artifacts=[]
    for name in ('scenario_plan.yml','planning_target.json','policy.json','provenance.json','context_selection.json','compatibility_report.json','step_evidence.json','validation_report.json'):
        p=folder/name
        if p.is_file():
            if p.is_symlink(): raise ValueError('Artifact symlink refused')
            artifacts.append({'file':name,'sha256':digest(p)})
    if (folder/'input/input_manifest.json').exists():
        envelope,target=verify_snapshot(folder/'input',job.get('input_manifest_sha256'))
        if target['id']!=profile['id'] or target['address']!=profile['address'] or envelope['policy']!=policy:
            problems.append('Input snapshot khác target/policy.')
        top=copy.deepcopy(profile);pinned=copy.deepcopy(target)
        top.get('capabilities',{}).pop('execution_scope',None);pinned.get('capabilities',{}).pop('execution_scope',None)
        if top!=pinned:problems.append('Planning profile khác snapshot đã ghim.')
        profile=target
        evidence={'verified':True,'survey_run_id':envelope['survey']['survey_run_id'] if 'survey' in envelope and 'survey_run_id' in envelope['survey'] else None,
                  'detection':'unknown'}
        context=json.loads((folder/'input/survey/survey_context.json').read_text())
        evidence.update(survey_run_id=context['survey_run_id'],finished_at=context['finished_at'],scope=context['scope'])
        artifacts.append({'file':'input/input_manifest.json','sha256':digest(folder/'input/input_manifest.json')})
        for name in ('context_selection.json','compatibility_report.json','step_evidence.json'):
            if not (folder/name).is_file():problems.append('Thiếu artifact context: '+name)
    else: problems.append('Plan profile_only: thiếu snapshot Survey v2 đã ghim; tạo phiên bản mới từ Survey.')
    config=Config(root)
    result=json.loads((folder/'result.json').read_text())
    states=[p for p in (folder/'runs').glob('*/state.json') if not p.is_symlink()]
    state=next((json.loads(p.read_text()) for p in states if json.loads(p.read_text()).get('run_id')==result.get('run_id')),None)
    if not state:problems.append('Thiếu checkpoint nguồn của plan.')
    else:
        from scenario_agent.workflow import Workflow
        config.runs=folder/'runs'
        try: Workflow(config).check_fingerprints(state)
        except (ValueError,OSError,KeyError): problems.append('Checkpoint/input/code fingerprint đã đổi; cần phiên bản mới hoặc revalidation.')
        for name,key in [('context_selection.json','context_selection'),('compatibility_report.json','compatibility_report'),('step_evidence.json','validation_report'),('validation_report.json','validation_report')]:
            if evidence['verified'] and (not (folder/name).is_file() or json.loads((folder/name).read_text())!=state.get(key)):
                problems.append('Artifact khác checkpoint: '+name)
        if state.get('plan')!=plan:problems.append('Plan khác checkpoint đã kiểm tra; cần revalidation.')
        if state.get('catalog_sha256')!=digest(config.catalog):problems.append('Catalog đã thay đổi từ khi sinh plan.')
    rows=[]
    with connect(config.catalog) as db:
        for step in plan['metadata']['steps']:
            issues=[];record=None;executor=None
            try:
                record=ability(db,step['ability_id'])
                provenance=record['provenance']
                source_path=root/record['source']['original_path']
                path=source_path.resolve()
                if root.resolve() not in path.parents or any(p.is_symlink() for p in (source_path,*source_path.parents)) or not path.is_file() or digest(path)!=provenance['revision']:
                    issues.append('File nguồn ability thiếu hoặc hash sai.')
                if step['executor'].get('privilege')!=record['ability'].get('privilege'):issues.append('Privilege khai báo khác nguồn catalog.')
                matches=[ex for ex in record['ability']['executors'] if ex['name']==step['executor']['name'] and ex['platform']==step['executor']['platform']]
                if len(matches)!=1:issues.append('Executor nguồn thiếu/không duy nhất.')
                else:executor=matches[0]
                accepted = [provenance]
                if executor and (is_inventory_command(executor.get('command')) or is_reviewed_inventory(record, executor)):
                    published = catalog_handles({'abilities':[{'record':record}]})
                    accepted.append(published['abilities'][0]['record']['provenance'])
                if not all(any(source in refs for source in accepted)
                           for refs in (step['sources'], plan['metadata']['selection']['sources'])):
                    issues.append('Revision/provenance không trùng catalog.')
            except (LookupError,ValueError,OSError,KeyError) as error:
                issues.append('Không resolve được ability nguồn: '+type(error).__name__)
            rows.append({'step':step,'record':record,'executor':executor,'blockers':issues})
    return {'plan':plan,'profile':profile,'policy':policy,'evidence':evidence,'artifacts':artifacts,'steps':rows,'blockers':problems}


def is_inventory_command(command):
    """Recognize standalone local inventory commands without arguments."""
    return isinstance(command, str) and re.fullmatch(
        r'(?:tasklist(?:\.exe)?|Get-Process|Get-Service|hostname|systeminfo|ipconfig)',
        command.strip(), re.IGNORECASE,
    ) is not None


if __name__=='__main__':
    try:
        result=inspect(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
        print(json.dumps(result,ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'context_error':type(error).__name__},ensure_ascii=False))
        sys.exit(1)
