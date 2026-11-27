"""Offline regression cases: scope, evidence, cancellation and cleanup."""
import copy
import io
import json
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import survey
from engine.agent import SurveyTools
from engine.runner import API, run, definitions, ABILITY_ID, ADVERSARY_ID, save
from engine.lifecycle import Cancelled, InstanceLock, pending_recovery
from engine.handoff import build_handoff, bundle
from engine.dvwa_session import verify_session, LoginPage
from engine.contracts import TargetProfile
from final_template.contracts import validate_document
from test_agent import endpoint, call
from test_dvwa_session import Response, BASE


class TestUpgrade(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.config = survey.load_config()
        self.config.update(web_scope=[{'scheme': 'http', 'port': 80}, {'scheme': 'https', 'port': 80}], web_ports=[80], web_scope_by_target={})
        self.request = {'target_ip': '192.168.73.199', 'survey_scope': ['endpoint', 'web'], 'web_checks': ['dvwa']}
        self.agent = {'paw': 'fixture', 'host': 'FIXTURE', 'platform': 'windows', 'privilege': 'User'}

    def test_no_request_is_not_checked_and_both_protocols_are_attempted(self):
        with patch.object(survey, 'build_opener') as build:
            raw = survey.probe_web(self.request['target_ip'], {}, self.config, lambda *x: None, deadline=time.monotonic()-1)
            self.assertEqual(raw['ports_checked'], [])
            self.assertEqual(raw['ports_planned'], [80])
            build.assert_not_called()
        response = MagicMock(); response.__enter__.return_value = response
        response.read.return_value = b'<title>Fixture</title>'; response.code = 200
        with patch.object(survey, 'build_opener') as build:
            def open_request(req, **kwargs):
                response.geturl.return_value = req.full_url
                response.headers = {}
                return response
            build.return_value.open.side_effect = open_request
            raw = survey.probe_web(self.request['target_ip'], {}, dict(self.config, web_paths=['/'], max_web_pages=1), lambda *x: None)
            self.assertEqual([r['requested_url'].split(':')[0] for r in raw['requests']], ['http','https'])
            self.assertEqual(raw['request_count'], 2)

    def test_body_limit_is_evidence(self):
        response = MagicMock(); response.__enter__.return_value=response; response.code=200
        response.read.return_value=b'x'*262145; response.geturl.return_value='http://192.168.73.199/'; response.headers={}
        config=dict(self.config, web_scope=[{'scheme':'http','port':80}], web_paths=['/'])
        with patch.object(survey, 'build_opener') as build:
            build.return_value.open.return_value=response
            raw=survey.probe_web('192.168.73.199',{},config,lambda *x:None)
        self.assertTrue(raw['requests'][0]['body_truncated'])

    def test_dynamic_candidates_do_not_expand_scope_or_repeat_ports(self):
        runtime=SurveyTools(self.request,self.agent,self.config,self.directory,lambda *x:None,lambda *x:None)
        self.config['web_scope'].append({'scheme':'http','port':8088})
        self.assertEqual(runtime.candidates('configured','probe_web'),[80])
        runtime.endpoint=endpoint()
        runtime.endpoint['data']['listeners'].append({'LocalAddress':'0.0.0.0','LocalPort':9999,'OwningProcess':1})
        self.assertEqual(runtime.candidates('discovered','probe_web'),[8088])
        runtime.web_results=[('probe_web','e.json',{'ports_checked':[8088]})]
        self.assertEqual(runtime.candidates('discovered','probe_web'),[])
        self.assertNotIn('inspect_dvwa_modules',[d['function']['name'] for d in runtime.available_definitions()])
        self.assertEqual(runtime.invoke(call('inspect_dvwa_modules'),30)['status'],'rejected')

    def test_cancelled_tool_never_runs_and_api_deadline_prevents_request(self):
        (self.directory/'cancel.requested').touch()
        runtime=SurveyTools(self.request,self.agent,self.config,self.directory,lambda *x:None,lambda *x:None)
        with patch.object(survey,'collect_endpoint') as collect, self.assertRaises(Cancelled): runtime.invoke(call('collect_endpoint'),30)
        collect.assert_not_called()
        api=API('http://127.0.0.1:1','fixture'); api.deadline=time.monotonic()-1
        with patch.object(api.opener,'open') as opener,self.assertRaises(TimeoutError): api.call('agents')
        opener.assert_not_called()

    def test_process_lock_releases_and_rejects_second_instance(self):
        path=self.directory/'lock'
        with InstanceLock(path):
            with self.assertRaises(RuntimeError):
                with InstanceLock(path): pass
        with InstanceLock(path): pass

    def test_lost_patch_response_still_restores_group(self):
        agent=dict(self.agent, group='red', trusted=True, host_ip_addrs=[self.request['target_ip']], executors=['psh'], last_seen=survey.now())
        class Fake:
            failed=False
            def call(inner,path,method='GET',body=None):
                ability, adversary=definitions()
                if path=='abilities/'+ABILITY_ID:return ability
                if path=='adversaries/'+ADVERSARY_ID:return adversary
                if path=='agents/fixture':
                    if body:
                        agent.update(body)
                        if not inner.failed: inner.failed=True; raise TimeoutError('response lost')
                    return copy.deepcopy(agent)
                if path=='operations':return []
                if path=='planners':return [{'name':'atomic','id':'p'}]
                if path=='sources':return [{'name':'basic','id':'s'}]
                raise AssertionError(path)
        args=SimpleNamespace(paw='fixture',expected_host='FIXTURE',expected_ip=self.request['target_ip'],max_age=180,timeout=2,output_dir=self.directory)
        with self.assertRaises(TimeoutError):run(Fake(),args)
        result=json.loads((self.directory/'summary.json').read_text())
        self.assertEqual(agent['group'],'red');self.assertTrue(result['group_restored']);self.assertFalse(result['cleanup_required'])

    def test_handoff_preserves_hashes_partial_and_detects_changes(self):
        profile=survey.build_profile(self.request,self.agent,dict(endpoint(),data=dict(endpoint()['data'],listeners=[])),None)
        save(self.directory/'target_profile.json',profile)
        save(self.directory/'report.json',{'status':'partial','missing_information':[{'field':'web'}]})
        metadata=build_handoff(self.directory,{'id':'fixture','request':self.request,'created_at':survey.now()})
        self.assertEqual(metadata['readiness']['planning'],'partial_evidence')
        self.assertEqual(len(profile),6)
        with zipfile.ZipFile(io.BytesIO(bundle(self.directory))) as archive:
            self.assertIn('report.json',archive.namelist());self.assertIn('handoff.json',archive.namelist())
        save(self.directory/'report.json',{'status':'completed'})
        with self.assertRaises(ValueError):bundle(self.directory)

    def test_dvwa_modules_read_only_and_no_values_are_exported(self):
        file=self.directory/'credential.json';file.write_text(json.dumps({'username':'fixture','password':'private-password'}))
        config={'dvwa_auth_by_target':{'192.168.73.130':{'enabled':True,'base_url':BASE,'credentials_file':str(file)}}}
        replies=[Response('login.php',"<input name='user_token' value='private-token'>"),Response('index.php',''),
            Response('index.php',"<a href='logout.php'>Logout</a><a href='vulnerabilities/sqli/'>SQLi</a><a href='setup.php'>setup</a><a href='vulnerabilities/sqli/?id=1'>payload</a><a href='http://outside/vulnerabilities/x/'>outside</a>"),
            Response('security.php',"<a href='logout.php'>Logout</a><select name='security'><option value='low' selected>low</option></select>"),
            Response('vulnerabilities/sqli/',"<a href='../../logout.php'>Logout</a><form method='POST'><input name='id' value='private-value'><input name='user_token' value='private-token'></form>")]
        with patch('engine.dvwa_session.build_opener') as build:
            build.return_value.open.side_effect=replies
            result=verify_session('192.168.73.130',config,survey_modules=True)
            requests=[c.args[0] for c in build.return_value.open.call_args_list]
        self.assertEqual([r.get_method() for r in requests],['GET','POST','GET','GET','GET'])
        self.assertEqual(result['modules_planned'],['vulnerabilities/sqli/'])
        self.assertTrue(result['modules'][0]['authenticated'])
        self.assertTrue(result['modules'][0]['forms'][0]['csrf_present'])
        self.assertNotIn('private-',json.dumps(result))
        self.assertEqual(verify_session('192.168.73.199',config)['status'],'not_configured')

    def test_contracts_both_reject_unverified_telemetry(self):
        profile=survey.build_profile(self.request,self.agent,endpoint(),None)
        profile['telemetry']['wazuh_ingestion']=True
        # Schema checks type; evidence validator rejects unsupported factual claims.
        TargetProfile.model_validate(profile)
        validate_document(profile, 'target_profile')
        from engine.evidence_refs import validate_profile_refs
        with self.assertRaises((ValueError, OSError)): validate_profile_refs(self.directory, profile)

    def test_recovery_is_target_bound_and_resolved_marker_is_retained(self):
        journal=self.directory/'a'/ 'caldera/summary.json'
        save(journal,{'cleanup_required':True,'expected_ip':'192.168.73.199','paw':'p','operation_id':'o'})
        self.assertEqual(pending_recovery(self.directory)[0]['target_ip'],'192.168.73.199')
        save(journal,{'cleanup_required':False,'group_restored':True})
        save(journal.parent.parent/'recovery_required.json',{'reason':'watchdog','resolved_at':survey.now()})
        self.assertEqual(pending_recovery(self.directory),[])

    def test_cancel_api_sets_local_marker_without_lab_calls(self):
        import app
        identifier='a'*32;directory=self.directory/identifier;directory.mkdir()
        job={'id':identifier,'status':'running'}
        handler=app.Handler.__new__(app.Handler)
        handler.path='/api/jobs/'+identifier+'/cancel'
        handler.headers={'X-Survey-Token':app.TOKEN,'Content-Length':'2'};handler.rfile=io.BytesIO(b'{}')
        with patch.object(app,'OUTPUTS',self.directory),patch.object(app,'JOBS',{identifier:job}),patch.object(app,'load_config',return_value={}),patch.object(app,'execute') as execute,patch.object(handler,'send') as send:
            handler.do_POST()
            self.assertEqual(send.call_args.args[1],202)
            self.assertTrue((directory/'cancel.requested').exists());execute.assert_not_called()

    def test_budget_exhaustion_survives_normalization(self):
        from final_template.web_profile import aggregate_web
        from engine.readiness import assess
        evidence=aggregate_web([('web.json',{'requests':[],'budget_exhausted':True,'ports_planned':[80],'ports_checked':[]})])
        profile=survey.build_profile(self.request,self.agent,endpoint(),evidence)
        result=assess(self.request,profile,evidence,{'probe_web','probe_dvwa'},config=self.config)
        self.assertTrue(result['required_missing'])


if __name__ == '__main__':unittest.main()
