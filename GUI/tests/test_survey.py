"""Offline tests: fake CALDERA API; no requests to lab endpoints."""
import base64
import copy
import json
import os
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import Request
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import survey
from engine.runner import ABILITY_ID, ADVERSARY_ID, definitions, run
from final_template.contracts import normalize_profile, validate_document


def agent():
    return {'paw': 'fixture', 'host': 'LAB-FIXTURE', 'host_ip_addrs': ['10.10.10.10', '192.168.73.199'],
            'platform': 'windows', 'trusted': True, 'executors': ['psh'], 'last_seen': survey.now(), 'privilege': 'User', 'group': 'red'}


def endpoint():
    return {'tool': 'get_endpoint_info', 'target': 'LAB-FIXTURE', 'status': 'ok', 'data': {
        'os_name': 'Windows fixture', 'os_version': 'test', 'architecture': '64-bit', 'hostname': 'LAB-FIXTURE',
        'username': 'fixture', 'is_elevated': False, 'powershell_version': '5.1', 'collected_at': survey.now(),
        'listeners': [], 'services': [], 'limitations': []}}


class FakeAPI:
    def __init__(self, agents=None): self.agents = [agent()] if agents is None else agents
    def call(self, path):
        return {'agents': self.agents, 'planners': [{'name': 'atomic', 'id': 'p'}], 'sources': [{'name': 'basic', 'id': 's'}], 'operations': []}[path]


class TestSurvey(unittest.TestCase):
    def local_server(self, handler):
        try:
            return ThreadingHTTPServer(('127.0.0.1', 0), handler)
        except PermissionError:
            self.skipTest('Sandbox prohibits sockets; HTTP integration requires a normal local shell.')

    def setUp(self):
        self.config = survey.load_config()
        self.config['orchestration_mode'] = 'scripts'
        self.config['allowed_networks'] = ['192.168.73.0/24']
        self.request = {'target_ip': '192.168.73.199', 'survey_scope': ['endpoint']}

    def test_scope_validation(self):
        for ip in ['127.0.0.1', '8.8.8.8', '::1', '192.168.73.199;whoami', 'not-an-ip']:
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                survey.normalize_request(dict(self.request, target_ip=ip), self.config)
        for scope in [[], 'endpoint', ['unknown']]:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                survey.normalize_request(dict(self.request, survey_scope=scope), self.config)

    def test_dynamic_ip_and_privilege_warning(self):
        with patch.object(survey, 'api_for', return_value=FakeAPI()):
            result = survey.preflight(self.request, self.config)
        self.assertTrue(result['ready'])
        self.assertEqual(result['agent']['paw'], 'fixture')
        self.assertTrue(any(c['state'] == 'warn' for c in result['checks']))

    def test_stale_duplicate_and_malformed_agent_blocked(self):
        stale = agent(); stale['last_seen'] = '2000-01-01T00:00:00Z'
        for agents in [[stale], [agent(), agent()], {'error': 'bad format'}]:
            with self.subTest(agents=agents), patch.object(survey, 'api_for', return_value=FakeAPI(agents)):
                self.assertFalse(survey.preflight(self.request, self.config)['ready'])

    def test_missing_key_is_actionable(self):
        with patch.object(survey, 'api_for', side_effect=ValueError('Missing key')):
            result = survey.preflight(self.request, self.config)
        self.assertFalse(result['ready'])
        self.assertEqual(result['checks'][-1]['detail'], 'Missing key')

    def test_profile_uses_selected_ip_and_preserves_unknowns(self):
        result = survey.build_profile(self.request, agent(), endpoint(), None)
        self.assertEqual(result['address'], '192.168.73.199')
        self.assertEqual(len(result), 6)
        self.assertNotIn('art_ready', result['capabilities'])
        self.assertTrue(all(v is None for v in result['telemetry'].values()))

    def test_survey_definitions_do_not_require_art_or_overwrite_v1(self):
        ability, adversary = definitions()
        command = ability['executors'][0]['command']
        self.assertNotIn('Invoke-AtomicRedTeam', command)
        self.assertNotIn('Get-Module', command)
        self.assertNotEqual(ABILITY_ID, '9e1297bd-47cd-455e-a258-bdf570ea0001')
        self.assertNotEqual(ADVERSARY_ID, '9e1297bd-47cd-455e-a258-bdf570ea0002')
        self.assertEqual(adversary['atomic_ordering'], [ABILITY_ID])

    def test_contract_rejects_legacy_extra_root_and_invalid_boolean(self):
        profile = survey.build_profile(self.request, agent(), endpoint(), None)
        invalid = copy.deepcopy(profile); invalid['capabilities']['art_ready'] = None
        with self.assertRaises(ValueError): validate_document(invalid, 'target_profile')
        invalid = copy.deepcopy(profile); invalid['metadata'] = {}
        with self.assertRaises(ValueError): validate_document(invalid, 'target_profile')
        invalid = copy.deepcopy(profile); invalid['capabilities']['admin_ready'] = 'yes'
        with self.assertRaises(ValueError): validate_document(invalid, 'target_profile')

    def test_legacy_profile_adapter_preserves_unknowns_and_source(self):
        original = survey.build_profile(self.request, agent(), endpoint(), None)
        original['capabilities']['art_ready'] = None
        original['services'].append({'name': 'Atomic Red Team', 'installed': True})
        migrated = normalize_profile(original)
        self.assertIn('art_ready', original['capabilities'])
        self.assertNotIn('art_ready', migrated['capabilities'])
        self.assertFalse(any(s['name'] == 'Atomic Red Team' for s in migrated['services']))
        self.assertEqual(migrated['id'], original['id'])
        self.assertEqual(migrated['telemetry'], original['telemetry'])

    def test_request_and_adversary_contracts(self):
        # ID linking and UUID spelling are deferred; steps must still be unique.
        request = {'id': 'r', 'text': 'test', 'target_id': 'different-target',
                   'scope': ['endpoint'], 'max_steps': 2, 'mode': 'plan_only'}
        validate_document(request, 'user_request')
        with self.assertRaises(ValueError):
            validate_document(dict(request, max_steps=True), 'user_request')
        adversary = {'id': 'source-id', 'name': 'Example', 'description': 'Test',
                     'atomic_ordering': ['source-ability']}
        validate_document(adversary, 'scenario_adversary')
        with self.assertRaises(ValueError):
            validate_document(dict(adversary, atomic_ordering=['a', 'a']), 'scenario_adversary')

    def test_runner_result_and_group_restore_without_sockets(self):
        class MemoryAPI:
            def __init__(self, status):
                self.agent = agent(); self.status = status; self.calls = []
            def call(self, path, method='GET', body=None):
                self.calls.append((path, method, body))
                ability, adversary = definitions()
                operation = {'id': 'test-op', 'state': 'finished', 'host_group': [copy.deepcopy(self.agent)]}
                if path == 'abilities/' + ABILITY_ID: return ability
                if path == 'adversaries/' + ADVERSARY_ID: return adversary
                if path == 'agents/fixture':
                    if body: self.agent.update(body)
                    return copy.deepcopy(self.agent)
                if path == 'agents': return [copy.deepcopy(self.agent)]
                if path == 'planners': return [{'name': 'atomic', 'id': 'p'}]
                if path == 'sources': return [{'name': 'basic', 'id': 's'}]
                if path == 'operations': return operation if body else []
                if path == 'operations/test-op': return operation
                if path == 'operations/test-op/links':
                    return [{'id': 'link', 'paw': 'fixture', 'ability': {'ability_id': ABILITY_ID}, 'finish': 'done', 'status': self.status}]
                if path.endswith('/result'):
                    value = {'stdout': json.dumps(endpoint()), 'stderr': '', 'exit_code': 0}
                    return {'result': base64.b64encode(json.dumps(value).encode()).decode()}
                raise AssertionError('Unexpected API call: ' + path)
        for status in [0, 1]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temp:
                api = MemoryAPI(status)
                args = SimpleNamespace(paw='fixture', expected_host='LAB-FIXTURE',
                                       expected_ip='192.168.73.199', max_age=180,
                                       timeout=1, output_dir=Path(temp))
                if status:
                    with self.assertRaises(RuntimeError): run(api, args)
                else:
                    run(api, args)
                    saved = json.loads((Path(temp) / 'endpoint-info.json').read_text())
                    executor = json.loads((Path(temp) / 'executor-result.json').read_text())
                    self.assertEqual(saved, json.loads(executor['stdout']))
                summary = json.loads((Path(temp) / 'summary.json').read_text())
                self.assertEqual(summary['status'], 'passed' if status == 0 else 'failed')
                self.assertEqual(api.agent['group'], 'red')
                self.assertTrue(summary['group_restored'])

    def test_legacy_history_and_download_adapt_without_rewriting(self):
        import app
        with tempfile.TemporaryDirectory() as temp:
            identifier = 'a' * 32
            directory = Path(temp) / identifier; directory.mkdir()
            profile = survey.build_profile(self.request, agent(), endpoint(), None)
            profile['capabilities']['art_ready'] = None
            original = json.dumps(profile)
            (directory / 'target_profile.json').write_text(original)
            (directory / 'state.json').write_text(json.dumps({'id': identifier,
                'profile': profile, 'status': 'completed', 'warnings': []}))
            with patch.object(app, 'OUTPUTS', Path(temp)), patch.object(app, 'JOBS', {}):
                app.load_jobs()
                self.assertNotIn('art_ready', app.JOBS[identifier]['profile']['capabilities'])
                handler = app.Handler.__new__(app.Handler)
                handler.path = '/api/jobs/' + identifier + '/files/target_profile.json'
                with patch.object(handler, 'send') as send:
                    handler.do_GET()
                    downloaded = json.loads(send.call_args[0][0])
                    self.assertEqual(downloaded, profile)
                self.assertEqual((directory / 'target_profile.json').read_text(), original)

    def test_redirect_cannot_leave_target(self):
        redirect = survey.SameHostRedirect('192.168.73.199', 80)
        with self.assertRaises(URLError):
            redirect.redirect_request(Request('http://192.168.73.199/'), None, 302, '', {}, 'http://example.com/')

    def test_real_runner_pipeline_against_fake_caldera(self):
        state = {'agent': agent(), 'definitions': {}, 'operation': None}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def handle_api(self):
                path = urlsplit(self.path).path[len('/api/v2/'):] # Real API permits repeated include query parameters.
                size = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(size)) if size else None
                code, result = 200, None
                if self.headers.get('KEY') != 'fixture-key': code = 403
                elif path == 'agents': result = [state['agent']]
                elif path == 'agents/fixture':
                    if body: state['agent'].update(body)
                    result = state['agent']
                elif path == 'planners': result = [{'name': 'atomic', 'id': 'p'}]
                elif path == 'sources': result = [{'name': 'basic', 'id': 's'}]
                elif path == 'operations':
                    if body:
                        state['operation'] = {'id': 'test-op', 'state': 'finished', 'host_group': [copy.deepcopy(state['agent'])]}
                        result = state['operation']
                    else: result = []
                elif path == 'operations/test-op': result = state['operation']
                elif path == 'operations/test-op/links': result = [{'id': 'link', 'paw': 'fixture', 'ability': {'ability_id': ABILITY_ID}, 'finish': 'done', 'status': 0}]
                elif path.endswith('/result'):
                    value = {'stdout': json.dumps(endpoint()), 'stderr': '', 'exit_code': 0}
                    result = {'result': base64.b64encode(json.dumps(value).encode()).decode()}
                elif body and path in ('abilities', 'adversaries'):
                    key = 'ability_id' if path == 'abilities' else 'adversary_id'
                    state['definitions'][path + '/' + body[key]] = body; result = body
                elif path in state['definitions']: result = state['definitions'][path]
                else: code = 404; result = {'error': 'not found'}
                payload = json.dumps(result).encode()
                self.send_response(code); self.send_header('Content-Length', str(len(payload))); self.end_headers(); self.wfile.write(payload)
            do_GET = do_POST = do_PATCH = handle_api
        server = self.local_server(Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            self.config['caldera_url'] = 'http://127.0.0.1:%d' % server.server_port
            with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {'CALDERA_KEY': 'fixture-key'}):
                output = Path(temp)
                result, warnings = survey.execute(self.request, self.config, output, lambda *x: None, lambda *x: None)
                self.assertEqual(result['address'], self.request['target_ip'])
                self.assertEqual(state['agent']['group'], 'red')
                self.assertTrue((output / 'target_profile.json').is_file())
                self.assertFalse((output / '03_web.json').exists())
                self.assertTrue(json.loads((output / 'caldera/summary.json').read_text())['group_restored'])
                self.assertIsNone(result['telemetry']['wazuh_ingestion'])
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_web_probe_collects_evidence_from_local_fixture(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                body = b'<title>DVWA fixture</title>' if self.path == '/dvwa/' else b'<title>Fixture root</title>'
                self.send_response(200); self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
        server = self.local_server(Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            self.config.update(web_ports=[server.server_port], web_paths=['/', '/dvwa/'], web_scope=[{'scheme': 'http', 'port': server.server_port}])
            evidence = survey.probe_web('127.0.0.1', endpoint(), self.config, lambda text: None)
            self.assertEqual(evidence['status'], 'observed')
            self.assertEqual(len(evidence['requests']), 2)
            self.assertEqual(evidence['requests'][1]['application_hint'], 'DVWA')
            profile = survey.build_profile(dict(self.request, survey_scope=['web']), agent(), endpoint(), evidence)
            self.assertTrue(profile['capabilities']['web_reachable'])
            self.assertFalse(any(s['name'] == 'Sandcat' for s in profile['services']))
            self.assertIsNone(profile['services'][0]['applications'][0]['current_security_level'])
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__': unittest.main()
