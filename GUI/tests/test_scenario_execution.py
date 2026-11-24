"""Execution integration uses a schema-shaped fake API only; no live endpoint calls."""
import base64
import copy
import json
import tempfile
import unittest
import sys
from datetime import datetime,timezone,timedelta
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import Mock,patch
from engine import scenario_execution as execution, scenario_bridge as bridge


def runtime_python():
    runtime=Path('scenario_agent')
    candidate=runtime/'.venv'/'Scripts/python.exe' if sys.platform == 'win32' else runtime/'.venv/bin/python'
    return str(candidate if candidate.is_file() else Path(sys.executable))
from engine.runner import save


def fixture_context(kind='process'):
    command={'process':'Get-Process','network':'Get-NetTCPConnection','web':'curl.exe http://192.0.2.10/health'}[kind]
    source={'kind':'caldera_ability','id':'source-1','location':'fixtures/source.yml','revision':'verified-revision'}
    ex={'name':'psh','platform':'windows','command':command,'timeout':30,'cleanup':[],'parsers':[],'payloads':[]}
    step={'step_index':1,'ability_id':'source-1','name':kind,'executor':{'name':'psh','platform':'windows','privilege':None},
          'readiness':'ready','reason':'Offline fixture','parameters':{},'prerequisites':[],'sources':[source]}
    record={'canonical_id':'source-1','provenance':source,'ability':{'name':kind,'privilege':None,'requirements':[],
        'executors':[ex],'tactic':'discovery','technique_id':'T1057','technique_name':'Process Discovery'}}
    return {'plan':{'id':'plan','metadata':{'readiness':'ready','blockers':[]}},
        'profile':{'id':'target','address':'192.0.2.10','os':{'hostname':'example-host'},'services':[{'url':'http://192.0.2.10/'}]},
        'policy':{'planning_scope':['web'] if kind=='web' else ['endpoint']},
        'evidence':{'verified':True,'survey_run_id':'survey','finished_at':execution.now(),'scope':['endpoint','web']},
        'artifacts':[{'file':'scenario_plan.yml','sha256':execution.hashlib.sha256(b'mock-plan').hexdigest()}],
        'steps':[{'step':step,'record':record,'executor':ex,'blockers':[]}],'blockers':[]}


class FakeAPI:
    def __init__(self,ctx):
        self.agent={'paw':'paw','host':'example-host','host_ip_addrs':['192.0.2.10'],'group':'original','platform':'windows',
            'trusted':True,'last_seen':execution.now(),'executors':['psh'],'privilege':'Elevated'}
        self.abilities={'source-1':copy.deepcopy(ctx['steps'][0]['record']['ability'])}
        self.adv={};self.op=None;self.links=[];self.calls=[];self.busy=[]
        self.lose_post=False;self.membership_wrong=False;self.exit_code='0';self.stdout='fixture completed';self.advance=True
    def call(self,path,method='GET',body=None):
        self.calls.append((path,method,copy.deepcopy(body)))
        p=path.split('?')[0]
        if p=='agents':return [copy.deepcopy(self.agent)]
        if p=='agents/paw':
            if method=='PATCH':self.agent.update(body)
            return copy.deepcopy(self.agent)
        if p=='planners':return [{'id':'planner','name':'atomic'}]
        if p=='sources':return [] if method=='GET' else body
        if p.startswith('abilities/'):
            key=p.split('/')[1]
            if key not in self.abilities:raise HTTPError('fixture',404,'Not found',{},None)
            return copy.deepcopy(self.abilities[key])
        if p=='abilities':self.abilities[body['ability_id']]=copy.deepcopy(body);return body
        if p=='adversaries':self.adv[body['adversary_id']]=copy.deepcopy(body);return body
        if p=='operations':
            if method=='GET':return self.busy+([copy.deepcopy(self.op)] if self.op else [])
            adv=self.adv[body['adversary']['adversary_id']]
            self.op={'id':'op','name':body['name'],'group':body['group'],'state':body['state'],
                     'adversary':adv,'host_group':[{'paw':'other' if self.membership_wrong else 'paw'}]}
            if self.lose_post:raise TimeoutError('POST response lost')
            return copy.deepcopy(self.op)
        if p=='operations/op':
            if method=='PATCH':self.op.update(body)
            if self.op['state']=='running' and self.links and all(l.get('finish') for l in self.links) and len(self.links)==len(self.op['adversary']['atomic_ordering']):
                self.op['state']='finished'
            return copy.deepcopy(self.op)
        if p=='operations/op/links':
            if self.op['state']=='running' and self.advance and (not self.links or self.links[-1].get('finish')) and len(self.links)<len(self.op['adversary']['atomic_ordering']):
                identifier=self.op['adversary']['atomic_ordering'][len(self.links)]
                command=self.abilities[identifier]['executors'][0]['command']
                self.links.append({'id':'link-'+str(len(self.links)+1),'paw':'paw','ability':{'ability_id':identifier},
                    'command':base64.b64encode(command.encode()).decode(),'status':-1,'collect':None,'finish':None,'cleanup':0})
            return copy.deepcopy(self.links)
        if '/links/' in p and p.endswith('/result'):
            return {'result':base64.b64encode(json.dumps({'exit_code':self.exit_code,'stdout':self.stdout,'stderr':''}).encode()).decode()}
        if '/links/' in p:
            link=next(l for l in self.links if l['id']==p.split('/')[-1])
            link.update(body)
            if body.get('status')==-3:
                link.update(collect='now',finish='done',status=0 if self.exit_code=='0' else 1)
            return copy.deepcopy(link)
        raise AssertionError((path,method))


class ExecutionTests(unittest.TestCase):
    def test_catalog_handle_compatibility_is_limited_to_local_inventory(self):
        from engine.execution_context import is_inventory_command

        for command in ('tasklist', 'Get-Process', 'Get-Service', 'hostname'):
            with self.subTest(command=command):
                self.assertTrue(is_inventory_command(command))
        for command in ('tasklist /s remote', 'Get-Process; hostname', 'hostname\nwhoami',
                        'curl http://example.test', 'Get-Process > output.txt', None):
            with self.subTest(command=command):
                self.assertFalse(is_inventory_command(command))

    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        for name,value in [('ROOT',self.root),('OUTPUTS',self.root/'scenario_outputs')]:
            p=patch.object(bridge,name,value);p.start();self.addCleanup(p.stop)
        source=bridge.OUTPUTS/('a'*32);source.mkdir(parents=True)
        (source/'scenario_plan.yml').write_bytes(b'mock-plan');save(source/'job.json',{'id':'a'*32,'status':'completed'})
        self.ctx=fixture_context();self.api=FakeAPI(self.ctx)
        self.config={'allowed_networks':['192.0.2.0/24'],'caldera_url':'http://fixture'}
        for name,value in [('context_for',lambda *a,**kw:copy.deepcopy(self.ctx)),('api_for',lambda *a:self.api),
                           ('endpoint_runner_path',lambda ip:self.root/'runner.lock'),('endpoint_activity_path',lambda ip:self.root/'activity.lock')]:
            p=patch.object(execution,name,value);p.start();self.addCleanup(p.stop)
        execution.THREADS.clear()
    def preview(self):return execution.preview('a'*32,self.config)
    def confirm_sync(self,value):
        with patch.object(execution.threading,'Thread'):
            result=execution.confirm(value['id'],{'confirmed':True,'target_ip':value['target']['ip'],'plan_sha256':value['plan_sha256']},self.config)
        with patch.object(execution.time,'sleep'):
            execution.run(value['id'],self.config)
        return execution.read(value['id'])
    def test_preview_is_read_only_for_multiple_behavior_families(self):
        for kind in ('process','network','web'):
            with self.subTest(kind=kind):
                self.ctx=fixture_context(kind);self.api=FakeAPI(self.ctx)
                value=self.preview();self.assertEqual(value['state'],'ready')
                self.assertTrue(all(method=='GET' for _,method,_ in self.api.calls))
                self.assertIsNone(value['operation_id'])
                self.assertEqual(value['detection'],'unknown')
    def test_live_runner_verifies_only_matching_unknown_executor(self):
        step = self.ctx['steps'][0]['step']
        step['prerequisites'] = [
            {'condition': 'survey.executors:paw', 'status': 'unknown'},
            {'condition': 'survey.executors:other', 'status': 'unknown'},
        ]
        for trusted, expected in ((True, 'verified'), (False, 'unknown')):
            with self.subTest(trusted=trusted):
                self.api.agent['trusted'] = trusted
                value = self.preview()
                row = value['preflight']['steps'][0]
                self.assertEqual(row['prerequisites'][0]['status'], expected)
                self.assertEqual(row['prerequisites'][1]['status'], 'unknown')
                self.assertEqual(step['prerequisites'][0]['status'], 'unknown')
                self.assertIsNone(row['required_privilege'])
                self.assertEqual(value['state'], 'blocked')
                self.assertTrue(all(method == 'GET' for _, method, _ in self.api.calls))
    def test_single_click_requires_every_step_to_be_verified_local_inventory(self):
        second = copy.deepcopy(self.ctx['steps'][0])
        second['step']['step_index'] = 2
        self.ctx['steps'].append(second)
        second['executor']['command'] = 'Get-NetTCPConnection'
        # Both commands can pass the normal preflight, but the second is outside
        # the restricted one-click policy.
        self.assertEqual(self.preview()['state'], 'ready')
        with patch.object(execution.threading, 'Thread') as worker:
            blocked = execution.preview('a'*32, self.config, start_on_click=True)
            self.assertEqual(blocked['state'], 'blocked')
            worker.assert_not_called()
            second['executor']['command'] = 'Get-Service'
            accepted = execution.preview('a'*32, self.config, start_on_click=True)
            self.assertEqual(accepted['state'], 'confirmed')
            worker.assert_called_once()
        self.assertTrue(all(method == 'GET' for _, method, _ in self.api.calls))

    def test_static_inventory_revalidation_is_independent_of_llm_readiness(self):
        self.ctx['plan']['metadata'].update(readiness='needs_information', blockers=sorted(execution.REVIEWED_INVENTORY_BLOCKERS))
        self.ctx['steps'][0]['step']['readiness']='needs_information'
        before=copy.deepcopy(self.ctx)
        checked=execution.preflight('a'*32,self.config,self.api,self.ctx)
        self.assertTrue(checked['ready'],checked['blockers'])
        self.assertEqual(before,self.ctx)
        from engine.execution_contracts import validation
        self.assertTrue(validation(checked)['ready'])
        self.ctx['steps'][0]['step']['parameters']={'path':'example'}
        blocked=execution.preflight('a'*32,self.config,self.api,self.ctx)
        self.assertFalse(blocked['ready'])

    def test_reviewed_inventory_plan_can_revalidate_three_steps(self):
        from engine.execution_context import REVIEWED_INVENTORY

        items = []
        for index, (identifier, (revision, command)) in enumerate(REVIEWED_INVENTORY.items(), 1):
            item = fixture_context()['steps'][0]
            item['record']['canonical_id'] = identifier
            item['record']['provenance']['revision'] = revision
            item['executor'].update(name='cmd', command=command)
            item['step'].update(step_index=index, ability_id=identifier, readiness='needs_information',
                                prerequisites=[{'condition':'survey.executors:paw','status':'unknown'}])
            item['step']['executor']['name'] = 'cmd'
            items.append(item)
        self.ctx['steps'] = items
        self.ctx['plan']['metadata'].update(readiness='needs_information', blockers=sorted(execution.REVIEWED_INVENTORY_BLOCKERS))
        self.api.agent['executors'] = ['cmd']

        command = items[-1]['executor']['command']
        items[-1]['executor']['command'] += ' && hostname'
        with patch.object(execution.threading, 'Thread') as worker:
            self.assertEqual(execution.preview('a'*32, self.config, start_on_click=True)['state'], 'blocked')
            worker.assert_not_called()
            items[-1]['executor']['command'] = command
            result = execution.preview('a'*32, self.config, start_on_click=True)
            self.assertEqual(result['state'], 'confirmed', result['preflight']['blockers'])
            self.assertTrue(all(row['required_privilege'] == 'Elevated' for row in result['preflight']['steps']))
            worker.assert_called_once()
    def test_success_registers_private_artifacts_dispatches_and_restores_group(self):
        value=self.preview();result=self.confirm_sync(value)
        self.assertEqual(result['state'],'completed',result.get('error'))
        self.assertEqual(result['steps'][0]['exit_code'],'0')
        self.assertTrue(result['group_restored']);self.assertEqual(self.api.agent['group'],'original')
        self.assertNotEqual(result['mapping'][0]['execution_ability_id'],'source-1')
        posts=[b for p,m,b in self.api.calls if p=='operations' and m=='POST']
        self.assertEqual(len(posts),1);self.assertEqual(posts[0]['state'],'paused');self.assertEqual(posts[0]['autonomous'],0)
        self.assertEqual(result['behavior_evidence'],'not_evaluated');self.assertEqual(result['detection'],'unknown')

    def test_reviewed_tasklist_plan_runs_after_confirmation_only(self):
        from engine.execution_context import REVIEWED_INVENTORY
        item = self.ctx['steps'][0]
        item['record']['canonical_id'] = 'f8de05d1741dcc468f772ab0ff4dac72'
        item['record']['provenance']['revision'] = REVIEWED_INVENTORY[item['record']['canonical_id']][0]
        item['executor'].update(name='cmd', command='tasklist')
        item['step'].update(ability_id=item['record']['canonical_id'], readiness='needs_information',
                            prerequisites=[{'condition':'survey.executors:paw','status':'unknown'}])
        item['step']['executor']['name'] = 'cmd'
        meta = self.ctx['plan']['metadata']
        meta.update(readiness='needs_information', blockers=sorted(execution.REVIEWED_INVENTORY_BLOCKERS))
        self.api.agent['executors'] = ['cmd']

        meta['blockers'].append('Unresolved condition')
        self.assertEqual(self.preview()['state'], 'blocked')
        meta['blockers'].pop()
        self.api.agent['privilege'] = 'User'
        self.assertEqual(self.preview()['state'], 'blocked')
        self.api.agent['privilege'] = 'Elevated'
        original_revision = item['record']['provenance']['revision']
        item['record']['provenance']['revision'] = 'different'
        self.assertEqual(self.preview()['state'], 'blocked')
        item['record']['provenance']['revision'] = original_revision

        value = self.preview()
        self.assertEqual(value['state'], 'ready', value['preflight']['blockers'])
        self.assertEqual(value['preflight']['steps'][0]['required_privilege'], 'Elevated')
        self.assertTrue(all(method == 'GET' for _, method, _ in self.api.calls))
        self.assertEqual(self.confirm_sync(value)['state'], 'completed')
    def test_duplicate_confirmation_and_concurrent_preview_do_not_create_duplicate_operation(self):
        value=self.preview()
        with patch.object(execution.threading,'Thread') as thread:
            body={'confirmed':True,'target_ip':'192.0.2.10','plan_sha256':value['plan_sha256']}
            execution.confirm(value['id'],body,self.config);execution.confirm(value['id'],body,self.config)
            self.assertEqual(thread.call_count,1)
        other=self.preview();self.assertEqual(other['state'],'blocked')
        self.assertFalse(any(m=='POST' for _,m,_ in self.api.calls))
    def test_wrong_target_hash_or_expired_confirmation_is_rejected(self):
        value=self.preview()
        for body in ({'confirmed':True,'target_ip':'other','plan_sha256':value['plan_sha256']}, {'confirmed':True,'target_ip':'192.0.2.10','plan_sha256':'wrong'}):
            with self.assertRaises(ValueError):execution.confirm(value['id'],body,self.config)
        value['created_at']=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat();execution.write(value)
        with self.assertRaisesRegex(ValueError,'hết hạn'):execution.confirm(value['id'],{'confirmed':True,'target_ip':'192.0.2.10','plan_sha256':value['plan_sha256']},self.config)
    def test_mutated_plan_or_revision_is_blocked_before_registration(self):
        value=self.preview();self.ctx['artifacts'][0]['sha256']='changed'
        result=self.confirm_sync(value)
        self.assertEqual(result['state'],'blocked');self.assertFalse(any(m=='POST' for _,m,_ in self.api.calls))
    def test_completed_generation_does_not_override_readiness_or_prerequisites(self):
        self.ctx['plan']['metadata']['readiness']='needs_information';self.ctx['plan']['metadata']['blockers']=['Unverified execution condition']
        self.ctx['steps'][0]['step']['prerequisites']=[{'condition':'Unknown dependency','status':'assumed'}]
        value=self.preview();self.assertEqual(value['state'],'blocked')
        self.assertTrue(any('Unknown dependency' in s for s in value['preflight']['blockers']))
    def test_stale_untrusted_busy_missing_executor_and_privilege(self):
        cases=[('stale',lambda:setattr(self.api,'agent',dict(self.api.agent,last_seen='2020-01-01T00:00:00Z'))),
               ('untrusted',lambda:self.api.agent.update(trusted=False)),
               ('executor',lambda:self.api.agent.update(executors=['cmd'])),
               ('busy',lambda:self.api.busy.append({'id':'other','state':'running','host_group':[{'paw':'paw'}]}))]
        for name,change in cases:
            with self.subTest(name=name):
                self.api=FakeAPI(self.ctx);change();self.assertEqual(self.preview()['state'],'blocked')
        self.api=FakeAPI(self.ctx);self.api.agent['privilege']='User';self.ctx['steps'][0]['record']['ability']['privilege']='Elevated'
        self.assertEqual(self.preview()['state'],'blocked')
    def test_missing_or_different_live_ability_is_previewed_and_never_overwritten(self):
        for registration in ('missing','different'):
            self.api=FakeAPI(self.ctx)
            if registration=='missing':self.api.abilities.pop('source-1')
            else:self.api.abilities['source-1']['executors'][0]['command']='Other'
            value=self.preview();self.assertEqual(value['preflight']['steps'][0]['registration'],registration)
            result=self.confirm_sync(value);self.assertEqual(result['state'],'completed',result.get('error'))
            self.assertFalse(any(p=='abilities/source-1' and m!='GET' for p,m,_ in self.api.calls))
    def test_missing_dependency_parameter_secret_placeholder_or_scope_blocks(self):
        baseline=fixture_context()
        cases=[lambda c:c['steps'][0]['executor'].update(payloads=['missing.bin']),
               lambda c:c['steps'][0]['step'].update(parameters={'path':'C:\\; evil'}),
               lambda c:c['steps'][0]['executor'].update(command='curl http://192.0.2.10/ -H "Cookie: SESSION=SECRET"'),
               lambda c:c['steps'][0]['executor'].update(command='Get-Content #{missing}'),
               lambda c:c['steps'][0]['executor'].update(command='curl http://192.0.2.22/'),
               lambda c:c['steps'][0]['executor'].update(cleanup=['Remove-Item C:\\unknown'])]
        for change in cases:
            self.ctx=copy.deepcopy(baseline);change(self.ctx);self.api=FakeAPI(self.ctx)
            value=self.preview();self.assertEqual(value['state'],'blocked')
            self.assertNotIn('SESSION=SECRET',json.dumps(value))
    def test_post_timeout_reconciles_without_resending_or_dispatching(self):
        self.api.lose_post=True;result=self.confirm_sync(self.preview())
        self.assertEqual(result['state'],'recovery_required');self.assertEqual(result['operation_id'],'op')
        self.assertEqual(sum(p=='operations' and m=='POST' for p,m,_ in self.api.calls),1)
        self.assertFalse(any(m=='PATCH' and b=={'status':-3} for _,m,b in self.api.calls))
    def test_restart_only_marks_recovery_and_never_contacts_api(self):
        value=self.preview();value['state']='creating_operation';execution.write(value)
        self.api.calls.clear();execution.initialize()
        self.assertEqual(execution.read(value['id'])['state'],'recovery_required');self.assertEqual(self.api.calls,[])
    def test_membership_mismatch_cannot_dispatch(self):
        self.api.membership_wrong=True;result=self.confirm_sync(self.preview())
        self.assertEqual(result['state'],'recovery_required')
        self.assertFalse(any(b=={'status':-3} for _,_,b in self.api.calls))
    def test_error_exit_does_not_dispatch_later_steps(self):
        second=copy.deepcopy(self.ctx['steps'][0]);second['step']['step_index']=2
        self.ctx['steps'].append(second);self.api.exit_code='1'
        result=self.confirm_sync(self.preview());self.assertEqual(result['state'],'recovery_required')
        self.assertEqual(sum(b=={'status':-3} for _,_,b in self.api.calls),1)
    def test_oversized_output_not_persisted_and_secrets_redacted(self):
        self.api.stdout='X'*100000;result=self.confirm_sync(self.preview())
        self.assertEqual(result['state'],'recovery_required')
        self.assertNotIn('X'*1000,json.dumps(result))
        self.assertNotIn('abcd',execution.safe_text('Cookie=abcd; password=abcd; secret=abcd'))
    def test_stop_and_reconcile_do_not_claim_to_interrupt_dispatched_command(self):
        result=self.confirm_sync(self.preview())
        result.update(state='running');execution.write(result)
        self.api.op['state']='running';self.api.links[0].update(collect='now',finish=None,status=-3)
        execution.stop(result['id']);value=execution.reconcile(result['id'],self.config)
        self.assertEqual(value['state'],'recovery_required');self.assertIn('dispatch',value['error'])
        self.assertFalse(any(p=='agents/paw' and m=='PATCH' and b.get('group')=='original' for p,m,b in self.api.calls[-4:]))
        self.api.links[0]['finish']='done';value=execution.reconcile(result['id'],self.config)
        self.assertEqual(value['state'],'stopped')
    def test_conditional_group_restore_never_overwrites_external_change(self):
        value=self.preview();value.update(group_change_intent=True,temporary_group='private',original_group='original')
        self.api.agent['group']='external'
        with self.assertRaises(ValueError):execution.restore_group(self.api,value)
        self.assertEqual(self.api.agent['group'],'external')
    def test_stop_request_is_not_lost_by_stale_worker_save(self):
        value=self.preview();value['state']='running';execution.write(value)
        stale=copy.deepcopy(value);execution.stop(value['id']);execution.write(stale)
        self.assertTrue(execution.read(value['id']).get('stop_requested_at'))

    def test_runtime_export_rejects_changed_revision_and_target(self):
        import shutil
        import yaml
        from engine.scenario_actions import inspect_plan
        runtime=Path('scenario_agent')
        original=Path(__file__).resolve().parents[1]/'scenario_outputs/f987d00f4905481ea3ab7a1f794f7382'
        target=bridge.OUTPUTS/('b'*32)
        shutil.copytree(original,target)
        # Use the real helper, bypassing the synthetic context provider of other tests.
        path=target/'scenario_plan.yml'
        value=yaml.safe_load(path.read_text())
        value['metadata']['steps'][0]['sources'][0]['revision']='bad-revision'
        path.write_text(yaml.safe_dump(value,allow_unicode=True))
        import subprocess
        response=subprocess.run([runtime_python(),'-B',str(Path(execution.__file__).with_name('execution_context.py')),str(runtime),str(target)],capture_output=True,text=True,timeout=25)
        self.assertEqual(response.returncode,0,response.stdout+response.stderr)
        exported=json.loads(response.stdout)
        self.assertTrue(any('Revision' in b for b in exported['steps'][0]['blockers']))
        profile=json.loads((target/'planning_target.json').read_text());profile['address']='192.0.2.22'
        save(target/'planning_target.json',profile)
        response=subprocess.run([runtime_python(),'-B',str(Path(execution.__file__).with_name('execution_context.py')),str(runtime),str(target)],capture_output=True,text=True,timeout=25)
        self.assertTrue(any('Target' in b for b in json.loads(response.stdout)['blockers']))

    def test_endpoint_lock_is_shared_and_blocks_before_registration(self):
        from engine.lifecycle import InstanceLock
        with InstanceLock(self.root/'activity.lock'):
            result=self.confirm_sync(self.preview())
        self.assertEqual(result['state'],'failed')
        self.assertFalse(any(m=='POST' for _,m,_ in self.api.calls))

    def test_missing_telemetry_does_not_block_verified_standalone_command(self):
        self.ctx['evidence']['detection']='unknown'
        value=self.preview();self.assertEqual(value['state'],'ready')
        self.assertEqual(value['detection'],'unknown')

    def test_semicolon_injection_and_dynamic_shell_are_not_supported(self):
        for command in ('Get-Process; whoami','Get-Process | Invoke-Expression','curl.exe http://192.0.2.10/; evil','Invoke-WebRequest $remote'):
            self.assertTrue(execution.command_blockers(command,'192.0.2.10'))

    def test_http_confirmation_and_stop_keep_csrf_and_origin_controls(self):
        import app,io
        for action in ('confirm','stop','reconcile'):
            h=app.Handler.__new__(app.Handler);h.path='/api/executions/'+('e'*32)+'/'+action
            h.headers={'X-Survey-Token':app.TOKEN,'Content-Length':'2','Origin':'http://evil.invalid','Host':'localhost'}
            h.rfile=io.BytesIO(b'{}');h.send=Mock()
            with patch.object(execution,'confirm') as confirm,patch.object(execution,'stop') as stop,patch.object(execution,'reconcile') as reconcile:
                h.do_POST()
            self.assertEqual(h.send.call_args.args[1],403)
            confirm.assert_not_called();stop.assert_not_called();reconcile.assert_not_called()

    def test_repeated_source_abilities_are_distinct_steps_and_schema_valid(self):
        second=copy.deepcopy(self.ctx['steps'][0]);second['step']['step_index']=2
        self.ctx['steps'].append(second)
        result=self.confirm_sync(self.preview())
        self.assertEqual(result['state'],'completed',result.get('error'))
        self.assertEqual(len({m['execution_ability_id'] for m in result['mapping']}),2)
        sent=[b for p,m,b in self.api.calls if '/links/' in p and m=='PATCH' and b=={'status':-3}]
        self.assertEqual(len(sent),2)
        import subprocess
        runtime=Path('scenario_agent/.venv/bin/python')
        schema_root=Path(__file__).resolve().parents[1]/'schemas/execution_v1'
        script="import json,sys; from jsonschema import Draft202012Validator; from pathlib import Path; root=Path(sys.argv[1]); folder=Path(sys.argv[2]); [Draft202012Validator(json.loads((root/(kind+'.schema.json')).read_text())).validate(json.loads((folder/name).read_text())) for kind,name in [('execution_record','execution_result.json'),('execution_manifest','execution_manifest.json')]]"
        check=subprocess.run([str(runtime),'-c',script,str(schema_root),str(execution.folder(result['id']))],capture_output=True,text=True,timeout=20)
        self.assertEqual(check.returncode,0,check.stderr)

    def test_preview_history_limit_cannot_hide_old_recovery_lock(self):
        value=self.preview();value.update(state='recovery_required',created_at='2000-01-01T00:00:00Z');execution.write(value)
        for i in range(101):
            row=copy.deepcopy(value);row.update(id=format(i+1000,'032x'),state='blocked',created_at=execution.now());execution.write(row)
        self.assertEqual(len(execution.history()),100)
        self.assertEqual(execution.pending('192.0.2.10')[0]['id'],value['id'])

    def test_artifact_tamper_between_preview_and_dispatch_is_rejected(self):
        value=self.preview()
        # Same context provider/hash fixture simulates a stale inspected source;
        # the final disk check must still stop dispatch.
        (bridge.OUTPUTS/('a'*32)/'scenario_plan.yml').write_text('changed')
        result=self.confirm_sync(value)
        self.assertEqual(result['state'],'recovery_required')
        self.assertFalse(any(b=={'status':-3} for _,_,b in self.api.calls))

    def test_unobserved_web_port_is_a_specific_blocker(self):
        self.ctx=fixture_context('web');self.ctx['profile']['services']=[{'url':'http://192.0.2.10:8080/'}];self.api=FakeAPI(self.ctx)
        value=self.preview();self.assertEqual(value['state'],'blocked')
        self.assertTrue(any('origin/port' in x for x in value['preflight']['blockers']))

if __name__=='__main__':unittest.main()
