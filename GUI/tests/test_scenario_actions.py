"""Offline action lifecycle: immutable inputs, local persistence, cancellation, no CALDERA."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from engine import scenario_bridge as bridge, scenario_actions as actions
from engine.runner import save

GUI=Path(__file__).resolve().parents[1]
RUNTIME=GUI.parent/'scenario_agent'
PLAN=GUI/'tests/fixtures/scenario_plan.yml'


def runtime_python():
    candidate=RUNTIME/'.venv'/'Scripts/python.exe' if sys.platform == 'win32' else RUNTIME/'.venv/bin/python'
    return Path(candidate) if candidate.is_file() else Path(sys.executable)


class ScenarioActionsTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        for name in ('ROOT','OUTPUTS','ACTIVE'):
            value={'ROOT':self.root,'OUTPUTS':self.root/'scenario_outputs','ACTIVE':None}[name]
            p=patch.object(bridge,name,value);p.start();self.addCleanup(p.stop)
        self.identifier='a'*32;self.folder=bridge.directory(self.identifier);self.folder.mkdir(parents=True)
        profile=json.loads((GUI/'static/scenario-data.json').read_text())['profiles'][0]['profile']
        self.config={'scenario_root':str(RUNTIME),'allowed_networks':['192.0.2.0/24']}
        request={'text':'PowerShell sinh cmd','scope':['endpoint'],'max_steps':4}
        profile,adapted,policy=bridge.adapt(dict(request,profile=profile),self.config)
        for name,value in [('job.json',{'id':self.identifier,'status':'completed','created_at':'2026-01-01','target_id':profile['id'],'target_ip':profile['address'],'text':request['text']}),
                           ('request.json',request),('policy.json',policy),('target_profile.json',profile),('planning_target.json',adapted),
                           ('provenance.json',{'source':'profile_only'}),('result.json',{'status':'completed','effective_request_text':'PowerShell sinh cmd\nBổ sung của người dùng: tạo file'})]:save(self.folder/name,value)
        shutil.copyfile(PLAN,self.folder/'scenario_plan.yml')

    def files(self,folder=None):
        return {str(p.relative_to(folder or self.folder)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (folder or self.folder).rglob('*') if p.is_file()}

    def test_save_validates_schema_persists_exact_yaml_and_is_idempotent(self):
        before=self.files()
        result=actions.add_to_library(self.identifier,self.config)
        self.assertEqual(result['status'],'saved')
        self.assertEqual(result['item']['yaml'],(self.folder/'scenario_plan.yml').read_text())
        self.assertFalse(result['item']['execution_authorized'])
        self.assertEqual(actions.add_to_library(self.identifier,self.config)['status'],'already_saved')
        self.assertEqual(actions.library()['total'],1)
        self.assertTrue(bridge.public(self.identifier)['saved_to_library'])
        self.assertEqual(self.files(),before)

    def test_invalid_plan_or_unfinished_job_cannot_enter_library(self):
        (self.folder/'scenario_plan.yml').write_text('id: invalid\n')
        with self.assertRaisesRegex(ValueError,'schema'):actions.add_to_library(self.identifier,self.config)
        self.assertEqual(actions.library()['items'],[])
        job=bridge.read(self.folder/'job.json');job['status']='running';save(self.folder/'job.json',job)
        with patch.object(actions,'inspect_plan') as inspect,self.assertRaises(ValueError):actions.add_to_library(self.identifier,self.config)
        inspect.assert_not_called()

    def test_changed_plan_does_not_overwrite_saved_version(self):
        actions.add_to_library(self.identifier,self.config)
        with (self.folder/'scenario_plan.yml').open('a') as f:f.write('\n# changed\n')
        with self.assertRaisesRegex(ValueError,'khác nội dung'):actions.add_to_library(self.identifier,self.config)
        self.assertNotIn('# changed',actions.library()['items'][0]['yaml'])

    def test_library_is_independent_of_soft_deleted_history(self):
        actions.add_to_library(self.identifier,self.config)
        original=(self.folder/'scenario_plan.yml').read_bytes()
        bridge.delete(self.identifier)
        self.assertEqual(bridge.history(),[])
        with self.assertRaises(ValueError):bridge.public(self.identifier)
        with self.assertRaises(ValueError):bridge.checked_download(self.folder,'scenario_plan.yml')
        self.assertEqual(actions.library()['total'],1)
        self.assertEqual((self.folder/'scenario_plan.yml').read_bytes(),original)

    def test_execution_entry_opens_preview_without_launching_a_worker(self):
        from engine import scenario_execution as execution
        with patch.object(execution,'preview',return_value={'state':'blocked'}) as preview,patch.object(bridge.subprocess,'Popen') as process:
            result=actions.execute(self.identifier,self.config)
        preview.assert_called_once_with(self.identifier,self.config)
        process.assert_not_called();self.assertEqual(result['state'],'blocked')

    def test_regenerate_keeps_original_and_clarifications_and_starts_new_job(self):
        before=self.files()
        with patch.object(bridge.threading,'Thread') as thread:
            result=bridge.regenerate(self.identifier,self.config)
        new=bridge.directory(result['id'])
        self.assertNotEqual(result['id'],self.identifier)
        for name in ('request.json','policy.json','target_profile.json','planning_target.json','provenance.json'):
            self.assertEqual((new/name).read_bytes(),(self.folder/name).read_bytes())
        self.assertEqual(bridge.read(new/'regeneration_context.json')['effective_request_text'],bridge.read(self.folder/'result.json')['effective_request_text'])
        self.assertEqual(bridge.read(new/'job.json')['parent_job_id'],self.identifier)
        self.assertFalse(bridge.read(new/'job.json')['execution_authorized'])
        self.assertEqual(self.files(),before);thread.return_value.start.assert_called_once()
        with self.assertRaises(ValueError):bridge.regenerate(self.identifier,self.config)

    def test_regenerate_clones_verified_snapshot(self):
        loader=bridge.input_module(RUNTIME)
        bundle=loader.load_bundle(GUI/'review/survey-v2-8722')
        profile=loader.planning_target(bundle);policy=loader.policy_for(profile,['endpoint'],4)
        request=bridge.read(self.folder/'request.json')
        loader.snapshot(bundle,self.folder/'input',{'text':request['text']},policy)
        save(self.folder/'target_profile.json',profile);save(self.folder/'policy.json',policy)
        job=bridge.read(self.folder/'job.json')
        job.update(adapter_version=loader.ADAPTER,input_manifest_sha256=hashlib.sha256((self.folder/'input/input_manifest.json').read_bytes()).hexdigest())
        save(self.folder/'job.json',job)
        before=self.files(self.folder/'input')
        with patch.object(bridge.threading,'Thread'):result=bridge.regenerate(self.identifier,self.config)
        new=bridge.directory(result['id'])
        self.assertEqual(self.files(new/'input'),before)
        loader.verify_snapshot(new/'input',job['input_manifest_sha256'])

    def test_regenerate_refuses_snapshot_symlink(self):
        (self.folder/'input').mkdir();(self.folder/'input/evil').symlink_to(self.folder/'request.json')
        with patch.object(bridge.threading,'Thread') as thread,self.assertRaisesRegex(ValueError,'symlink'):bridge.regenerate(self.identifier,self.config)
        thread.assert_not_called()

    def test_cancel_before_worker_spawn_never_launches_model(self):
        job=bridge.read(self.folder/'job.json');job['status']='running';save(self.folder/'job.json',job)
        bridge.ACTIVE=self.identifier
        self.assertEqual(bridge.cancel(self.identifier)['status'],'cancelling')
        with self.assertRaises(ValueError):bridge.delete(self.identifier)
        with patch.object(bridge.subprocess,'Popen') as process:
            bridge.run_worker(self.folder,RUNTIME,runtime_python(),False)
        process.assert_not_called()
        self.assertEqual(bridge.public(self.identifier)['status'],'cancelled')
        self.assertIsNone(bridge.ACTIVE)
        bridge.delete(self.identifier)

    def test_cancel_running_process_stops_only_its_process_group(self):
        job=bridge.read(self.folder/'job.json');job['status']='running';save(self.folder/'job.json',job)
        process=Mock(pid=987654,returncode=-15)
        process.poll.side_effect=[None,None]
        def start(*args,**kwargs):
            bridge.cancel(self.identifier)
            return process
        with patch.object(bridge.subprocess,'Popen',side_effect=start),patch.object(bridge.os,'killpg') as kill:
            bridge.run_worker(self.folder,RUNTIME,runtime_python(),False)
        kill.assert_called_once_with(process.pid,bridge.signal.SIGTERM)
        self.assertEqual(bridge.public(self.identifier)['status'],'cancelled')

    def test_storage_traversal_and_symlinks_refused(self):
        for value in ('../bad','/etc',None,'g'*32):
            with self.assertRaises(ValueError):bridge.directory(value)
        self.root.joinpath('scenario_library').symlink_to(self.folder,target_is_directory=True)
        with self.assertRaises(ValueError):actions.library()

    def test_http_actions_require_token_and_execute_returns_preflight(self):
        import io
        import app
        def handler(path,token):
            h=app.Handler.__new__(app.Handler);h.path=path
            h.headers={'X-Survey-Token':token,'Content-Length':'2'}
            h.rfile=io.BytesIO(b'{}');h.send=Mock()
            return h
        path='/api/scenarios/'+self.identifier+'/execute'
        h=handler(path,'wrong')
        with patch.object(actions,'execute') as execute:h.do_POST()
        self.assertEqual(h.send.call_args.args[1],403);execute.assert_not_called()
        h=handler(path,app.TOKEN)
        with patch.object(app,'load_config',return_value=self.config),patch('engine.scenario_execution.preview',return_value={'state':'blocked'}) as preview,patch.object(bridge.subprocess,'Popen') as process:
            h.do_POST()
        self.assertEqual(h.send.call_args.args[0]['state'],'blocked')
        preview.assert_called_once_with(self.identifier,self.config);process.assert_not_called()

    def test_http_action_routes_dispatch_to_expected_lifecycle(self):
        import io
        import app
        routes=[('library',actions,'add_to_library',{'status':'saved'}),
                ('regenerate',bridge,'regenerate',{'id':'b'*32}),
                ('cancel',bridge,'cancel',{'status':'cancelling'}),
                ('delete',bridge,'delete',{'status':'deleted'})]
        for name,module,method,result in routes:
            with self.subTest(action=name):
                h=app.Handler.__new__(app.Handler)
                h.path='/api/scenarios/'+self.identifier+'/'+name
                h.headers={'X-Survey-Token':app.TOKEN,'Content-Length':'2'}
                h.rfile=io.BytesIO(b'{}');h.send=Mock()
                with patch.object(app,'load_config',return_value=self.config),patch.object(module,method,return_value=result) as action:
                    h.do_POST()
                self.assertEqual(h.send.call_args.args[0],result)
                expected=(self.identifier,self.config) if name in ('library','regenerate') else (self.identifier,)
                action.assert_called_once_with(*expected)

    def test_regeneration_worker_uses_saved_effective_text_without_llm(self):
        with patch.object(bridge.threading,'Thread'):result=bridge.regenerate(self.identifier,self.config)
        folder=bridge.directory(result['id'])
        script="""
import sys,json
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,sys.argv[2])
from engine.scenario_worker import run_planning
from scenario_agent.workflow import Workflow
folder=Path(sys.argv[3])
def fake_run(flow,state):
    state['status']='needs_information'
    state['next']='END'
    return state
llm=Mock()
with patch.object(Workflow,'run',fake_run):
    state=run_planning(sys.argv[2],folder,llm=llm,mode='keyword')
llm.generate.assert_not_called()
print(json.dumps({'text':state['text'],'request_id':state['request_id']}))
"""
        response=subprocess.run([str(runtime_python()),'-c',script,str(GUI),str(RUNTIME),str(folder)],capture_output=True,text=True,timeout=20)
        self.assertEqual(response.returncode,0,response.stderr)
        state=json.loads(response.stdout)
        self.assertEqual(state['text'],bridge.read(self.folder/'result.json')['effective_request_text'])
        self.assertTrue(state['request_id'].startswith('REQ-'))

if __name__=='__main__':unittest.main()
