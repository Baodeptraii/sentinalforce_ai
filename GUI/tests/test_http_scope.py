"""No sockets: enforce scope before requests, verify references and reporting."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import Request
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from engine import survey
from engine.web_scope import allowed_pairs
from engine.web_limitations import limitations
from engine.dvwa_session import verify_session
from engine.evidence_refs import resolve, validate_profile_refs
from engine.readiness import assess
from final_template.web_profile import aggregate_web

IP='192.0.2.10'
CONFIG={'web_ports':[80,443,8080,8000,8443], 'max_web_ports':12,'max_web_pages':4,
        'web_scope_by_target':{IP:[{'scheme':'http','port':80}]},'web_paths':['/']}
class Response:
    code=200; headers={}
    def __init__(self,url):self.url=url
    def geturl(self):return self.url
    def read(self,_):return b'<title>DVWA</title><a href="https://192.0.2.10/">TLS</a><a href="http://192.0.2.10:8080/">other</a>'
    def __enter__(self):return self
    def __exit__(self,*a):pass

class TestScope(unittest.TestCase):
    def test_http80_blocks_discovery_links_and_fallback(self):
        for failure in (False,True):
            with self.subTest(failure=failure),patch.object(survey,'build_opener') as build:
                build.return_value.open.side_effect=URLError('fixture error') if failure else lambda req,**kw:Response(req.full_url)
                raw=survey.probe_web(IP,{'data':{'listeners':[{'LocalPort':p} for p in (443,8080,8000,8443,9999)]}},CONFIG,lambda _:None)
                urls=[c.args[0].full_url for c in build.return_value.open.call_args_list]
                self.assertEqual(urls,['http://192.0.2.10/'])
                self.assertEqual(raw['scope'],[{'scheme':'http','port':80}])
                redirect=build.call_args.args[1]
                for url in ['https://192.0.2.10/','https://192.0.2.10:80/','http://192.0.2.10:443/','http://192.0.2.10:8080/','http://192.0.2.12/']:
                    with self.assertRaises(survey.RedirectScopeError):redirect.redirect_request(Request(urls[0]),None,302,'',{},url)
    def test_both_agent_tools_and_sources_obey_http_scope(self):
        from engine.agent import SurveyTools
        from engine.survey import load_config
        config=load_config();config.update(CONFIG);config['dvwa_auth']={'enabled':False}
        request={'target_ip':IP,'survey_scope':['web'],'web_checks':['dvwa']}
        with tempfile.TemporaryDirectory() as tmp,patch.object(survey,'build_opener') as build:
            build.return_value.open.side_effect=lambda req,**kw:Response(req.full_url)
            runtime=SurveyTools(request,{},config,Path(tmp),lambda *a:None,lambda *a:None)
            runtime.endpoint={'data':{'listeners':[{'LocalPort':80},{'LocalPort':443},{'LocalPort':9999}]}}
            for tool in ('probe_web','probe_dvwa'):
                for source in ('configured','discovered'):
                    call={'function':{'name':tool,'arguments':json.dumps({'source':source})}}
                    self.assertEqual(runtime.invoke(call,30)['status'],'ok' if source == 'configured' else 'rejected')
            urls=[call.args[0].full_url for call in build.return_value.open.call_args_list]
            self.assertTrue(urls)
            self.assertTrue(all(url.startswith('http://192.0.2.10/') for url in urls))

    def test_other_target_can_use_https(self):
        config=dict(CONFIG,web_scope=[{'scheme':'https','port':8443}])
        with patch.object(survey,'build_opener') as build:
            build.return_value.open.side_effect=lambda req,**kw:Response(req.full_url)
            raw=survey.probe_web('192.0.2.12',{},config,lambda _:None)
            self.assertEqual([c.args[0].full_url for c in build.return_value.open.call_args_list],['https://192.0.2.12:8443/'])
            self.assertTrue(raw['requests'][0]['tls_verified'])
    def test_auth_scope_blocks_before_credentials_or_network(self):
        for base in ['https://192.0.2.10/dvwa/','http://192.0.2.10:8080/dvwa/']:
            config=dict(CONFIG,dvwa_auth={'enabled':True,'base_url':base,'credentials_file':'/nonexistent'})
            with patch('engine.dvwa_session.build_opener') as build:
                result=verify_session(IP,config)
                self.assertEqual(result['status'],'out_of_scope');build.assert_not_called()
    def test_authentication_reference_and_all_profile_pointers(self):
        auth={'base_url':'http://192.0.2.10/dvwa/','session_ready':True,'current_security_level':'low','status':'verified'}
        data={'authentication':auth,'requests':[{'url':auth['base_url']+'login.php','http_status':200,'title':'DVWA'}]}
        evidence=aggregate_web([('tool_03_probe_dvwa.json#/data',data)])
        app=evidence['services'][0]['applications'][0]
        self.assertEqual(app['authentication_ref'],'tool_03_probe_dvwa.json#/data/authentication')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'tool_03_probe_dvwa.json').write_text(json.dumps({'data':data}))
            (root/'web_evidence.json').write_text(json.dumps(evidence))
            validate_profile_refs(root,{'services':evidence['services']})
            self.assertEqual(resolve(root,app['authentication_ref']),auth)
            self.assertEqual(resolve(root,'tool_03_probe_dvwa.json#/data/requests/0')['http_status'],200)
            for ref in ['../outside.json#/secret','/tmp/outside.json#/secret']:
                with self.assertRaises(ValueError):resolve(root,ref)
            (root/'escape.json').symlink_to(root.parent/'outside.json')
            with self.assertRaises(ValueError):resolve(root,'escape.json#/secret')
    def test_limitations_success_failure_not_configured_and_unknown_level(self):
        auth={'status':'verified','session_ready':True,'current_security_level':'low','checked_at':'fixture-time'}
        success=' '.join(limitations(auth))
        self.assertIn('Đã đọc security level',success);self.assertNotIn('không đăng nhập',success)
        self.assertIn('không bảo đảm phiên thực thi sau',success)
        for status in ('not_configured','credential_unavailable','authentication_unverified','check_failed','out_of_scope'):
            result={'status':status,'session_ready':None,'current_security_level':None}
            self.assertIn(status,' '.join(limitations(result)));self.assertNotIn('Đã đọc security level',' '.join(limitations(result)))
            self.assertIsNone(result['current_security_level'])
        auth['current_security_level']=None
        self.assertIn('Chưa xác minh security level',' '.join(limitations(auth)))
        self.assertIn('Không thực hiện bước xác thực',' '.join(limitations()))
    def test_scope_and_dedup_preserve_all_telemetry_details(self):
        evidence=aggregate_web([])
        profile={'services':[],'capabilities':{'web_reachable':None},'telemetry':dict.fromkeys(['process_events','network_events','web_access_logs','wazuh_ingestion'])}
        request={'target_ip':IP,'survey_scope':['web'],'web_checks':[]}
        result=assess(request,profile,evidence,{'probe_web'},config=CONFIG)
        gaps=[g for g in result['missing_information'] if g['field'].startswith('telemetry.')]
        self.assertEqual(len(gaps),4)
        self.assertEqual(result['warnings'].count(gaps[0]['reason']),1)
        self.assertEqual(result['warnings'],list(dict.fromkeys(result['warnings'])))
        self.assertTrue(all(set(g)=={'field','status','reason','required'} for g in gaps))
        self.assertEqual(result['web_readiness']['https']['status'],'out_of_scope')
        self.assertIsNone(result['web_readiness']['https']['verified'])
        self.assertFalse(any('HTTPS' in w for w in result['warnings']))
        self.assertTrue(all(v is None for v in profile['telemetry'].values()))

    def test_auth_outside_policy_is_not_a_failed_prerequisite(self):
        evidence=aggregate_web([]);evidence['authentication']=[{'status':'out_of_scope'}]
        profile={'services':[],'capabilities':{},'telemetry':{}}
        result=assess({'target_ip':IP,'survey_scope':['web'],'web_checks':['dvwa']},profile,evidence,{'probe_web','probe_dvwa'},config=CONFIG)
        for field in ('dvwa_session_ready','dvwa_security_level','https'):
            self.assertEqual(next(m for m in result['missing_information'] if m['field']==field)['status'],'out_of_scope')
