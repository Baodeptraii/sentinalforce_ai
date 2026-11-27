"""DVWA auth fixtures; no target requests or credentials in output."""
import json
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.request import Request
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine.dvwa_session import verify_session, AuthRedirect
from engine.survey import RedirectScopeError
from final_template.web_profile import aggregate_web, llm_web_summary
from engine.contracts import WebApplication

BASE = 'http://192.168.73.130/dvwa/'
class Response:
    code = 200
    def __init__(self, path, body): self.path, self.body = path, body
    def geturl(self): return BASE+self.path
    def read(self, _): return self.body.encode()
    def __enter__(self): return self
    def __exit__(self, *args): pass

class TestDVWASession(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        file = Path(self.temp.name)/'credential.json'; file.write_text(json.dumps({'username':'fixture-user','password':'fixture-password'}))
        self.config = {'dvwa_auth':{'enabled':True,'base_url':BASE,'credentials_file':str(file)}}
    def responses(self):
        return [Response('login.php',"<input name='user_token' value='fixture-csrf'>"), Response('index.php',''),
                Response('index.php',"<a href='logout.php'>Logout</a>"),
                Response('security.php',"<a href='logout.php'>Logout</a><select name='security'><option value='high'>high</option><option value='impossible' selected>impossible</option></select>")]
    def test_login_csrf_cookie_jar_verification_and_level(self):
        with patch('engine.dvwa_session.build_opener') as build:
            build.return_value.open.side_effect=self.responses()
            result=verify_session('192.168.73.130',self.config)
            requests=[c.args[0] for c in build.return_value.open.call_args_list]
            self.assertEqual([r.get_method() for r in requests],['GET','POST','GET','GET'])
            form=parse_qs(requests[1].data.decode()); self.assertEqual(form['user_token'],['fixture-csrf'])
            self.assertEqual(form['password'],['fixture-password'])
            self.assertTrue(result['session_ready']); self.assertEqual(result['current_security_level'],'impossible')
            serialized=json.dumps(result)
            for secret in ['fixture-password','fixture-user','fixture-csrf','PHPSESSID']: self.assertNotIn(secret,serialized)
            self.assertTrue(any(type(handler).__name__=='HTTPCookieProcessor' for handler in build.call_args.args))
    def test_login_200_alone_never_proves_session(self):
        replies=self.responses(); replies[2]=Response('login.php',"<input name='user_token' value='again'>")
        with patch('engine.dvwa_session.build_opener') as build:
            build.return_value.open.side_effect=replies
            result=verify_session('192.168.73.130',self.config)
            self.assertIsNone(result['session_ready']); self.assertEqual(result['status'],'authentication_unverified')
            self.assertEqual(build.return_value.open.call_count,3)
    def test_security_error_preserves_verified_login(self):
        replies=self.responses(); replies[-1]=TimeoutError('timeout')
        with patch('engine.dvwa_session.build_opener') as build:
            build.return_value.open.side_effect=replies
            result=verify_session('192.168.73.130',self.config)
            self.assertTrue(result['session_ready']); self.assertIsNone(result['current_security_level'])
            self.assertEqual(result['status'],'security_check_failed')
    def test_missing_token_does_not_send_credentials(self):
        with patch('engine.dvwa_session.build_opener') as build:
            build.return_value.open.return_value=Response('login.php','unrelated page')
            result=verify_session('192.168.73.130',self.config)
            self.assertEqual(build.return_value.open.call_count,1); self.assertIsNone(result['session_ready'])
    def test_target_binding_and_redirect_guard(self):
        with patch('engine.dvwa_session.build_opener') as build:
            self.assertEqual(verify_session('192.168.73.199',self.config)['status'],'out_of_scope'); build.assert_not_called()
        handler=AuthRedirect(BASE)
        for dest in ['http://outside.test/','http://192.168.73.130/setup.php',BASE+'../evil',BASE+'%2e%2e/evil','https://192.168.73.130/dvwa/index.php']:
            with self.subTest(dest=dest), self.assertRaises(RedirectScopeError): handler.redirect_request(Request(BASE+'login.php'),None,302,'',{},dest)
    def test_auth_evidence_applies_only_to_identified_matching_app(self):
        auth={'base_url':BASE,'session_ready':True,'current_security_level':'impossible','status':'verified'}
        raw={'requests':[{'url':BASE+'login.php','http_status':200,'title':'DVWA Login'}],'authentication':auth}
        evidence=aggregate_web([('tool.json',raw)])
        app=evidence['services'][0]['applications'][0]; WebApplication.model_validate(app)
        self.assertTrue(app['session_ready']); self.assertEqual(app['authentication_ref'],'tool.json#/authentication')
        self.assertEqual(llm_web_summary(raw)['authentication']['current_security_level'],'impossible')
        raw['authentication']['base_url']='http://192.168.73.199/dvwa/'
        self.assertIsNone(aggregate_web([('tool.json',raw)])['services'][0]['applications'][0]['session_ready'])
