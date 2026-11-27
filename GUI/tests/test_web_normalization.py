"""Offline web normalization, transport diagnostics and history replay; no lab traffic."""
import copy
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import Request

PROJECT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(PROJECT), str(PROJECT / 'GUI')]
from final_template.web_profile import aggregate_web, canonical_url, llm_web_summary
from final_template.contracts import normalize_profile, validate_document
from engine import survey
from engine.contracts import TargetProfile
from engine.readiness import assess
from engine.presentation import hydrate
from engine.web_history import load_evidence


def row(url, code=200, **extra):
    return dict(url=url, requested_url=url, http_status=code, redirect_chain=[], **extra)


def request(web=True):
    return {'target_ip': '192.168.73.130', 'survey_scope': ['endpoint', 'web'] if web else ['endpoint'], 'web_checks': ['dvwa'] if web else []}


def profile(evidence):
    return {'id': 'test', 'os': {'name': 'fixture', 'hostname': 'fixture', 'version': None, 'architecture': None, 'status': 'observed'},
            'address': '192.168.73.130', 'services': evidence['services'],
            'capabilities': {'sandcat_online': True, 'powershell_ready': True, 'admin_ready': False, 'web_runner_ready': True, 'web_reachable': True if evidence['services'] else None, 'dvwa_session_ready': None},
            'telemetry': dict.fromkeys(['process_events', 'network_events', 'web_access_logs', 'wazuh_ingestion'])}


class TestWebNormalization(unittest.TestCase):
    def test_redirect_duplicates_preserve_sources_chains_and_paths(self):
        first = row('http://EXAMPLE.test:80/dvwa/login.php#form', title='Login :: DVWA')
        first.update(requested_url='http://EXAMPLE.test:80/dvwa/', redirect_chain=[{'from': 'http://example.test/dvwa/', 'to': 'http://example.test/dvwa/login.php', 'http_status': 302}])
        evidence = aggregate_web([('a.json', {'requests': [first, row('http://example.test/dvwa/login.php', title='Login :: DVWA'), row('http://example.test/other/'), row('https://example.test:443/dvwa/login.php', title='Login :: DVWA', tls_verified=True)]}),
                                  ('b.json', {'requests': [copy.deepcopy(first)]})])
        self.assertEqual(len(evidence['requests']), 5)
        self.assertEqual(len(evidence['observations']), 3)
        self.assertEqual(len(evidence['services']), 2)
        self.assertEqual(len(evidence['observations'][0]['sources']), 3)
        self.assertEqual(len(evidence['observations'][0]['redirect_chains']), 2)
        self.assertIn('http://example.test/dvwa/', evidence['observations'][0]['requested_urls'])
        self.assertEqual(evidence['services'][0]['applications'][0]['base_url'], 'http://example.test/dvwa/')
        self.assertEqual(canonical_url('HTTP://EXAMPLE.test:80/Case/'), 'http://example.test/Case/')
        self.assertNotEqual(canonical_url('http://example.test/A/'), canonical_url('http://example.test/a/'))

    def test_login_and_403_and_400_do_not_invent_readiness_or_apps(self):
        evidence = aggregate_web([('fixture', {'requests': [row('http://192.168.73.130/dvwa/login.php', title='Login :: DVWA', server_banner='Apache/fixture'),
            row('http://192.168.73.130/phpmyadmin/', 403, title='Forbidden', application_hint='phpMyAdmin'),
            row('http://192.168.73.130:443/', 400), row('http://192.168.73.130:443/dvwa/', 400)]})])
        self.assertEqual(len(evidence['services']), 1)
        app = evidence['services'][0]['applications'][0]
        self.assertEqual(app['name'], 'DVWA')
        for key in ['session_ready', 'current_security_level', 'version']: self.assertIsNone(app[key])
        self.assertEqual(len(evidence['observations']), 4)
        self.assertNotIn('server_banner', evidence['services'][0])
        checked = profile(evidence)
        validate_document(checked, 'target_profile'); TargetProfile.model_validate(checked)
        checked['services'][0]['applications'][0]['session_ready'] = 'unverified'
        with self.assertRaises(ValueError): validate_document(checked, 'target_profile')

    def test_error_classification_redacts_details(self):
        examples = [(ssl.SSLCertVerificationError(1, 'certificate verify failed'), 'tls_certificate'),
                    (ssl.SSLCertVerificationError(1, 'IP address mismatch'), 'hostname_mismatch'),
                    (socket.timeout('timed out'), 'timeout'), (ConnectionRefusedError(111, 'refused'), 'refused'),
                    (socket.gaierror(-2, 'Name or service not known'), 'dns'), (ssl.SSLError('TLS alert'), 'tls_error')]
        for error, kind in examples:
            with self.subTest(kind=kind): self.assertEqual(survey.classify_url_error(URLError(error))['kind'], kind)
        error = survey.classify_url_error(URLError('password=fixture-secret token=fixture-token'))
        self.assertNotIn('fixture-secret', error['message']); self.assertNotIn('fixture-token', error['message'])

    def test_redirects_check_every_hop_and_block_before_request(self):
        handler = survey.SameHostRedirect('192.168.73.130', 80, [80, 443])
        req = Request('http://192.168.73.130/')
        redirected = handler.redirect_request(req, None, 302, '', {}, 'https://192.168.73.130/dvwa/')
        self.assertEqual(redirected.full_url, 'https://192.168.73.130/dvwa/')
        for url in ['http://outside.test/', 'http://192.168.73.130:9999/', 'http://user:secret@192.168.73.130/', 'ftp://192.168.73.130/', 'http://192.168.73.130:invalid/']:
            with self.subTest(url=url), self.assertRaises(survey.RedirectScopeError):
                handler.redirect_request(redirected, None, 302, '', {}, url)
            self.assertTrue(handler.chain[-1]['blocked'])
        self.assertNotIn('user:secret', json.dumps(handler.chain))

    def test_probe_retains_https_error_http400_diagnostics_and_tls_verification(self):
        class Response:
            code = 400; headers = {}
            def geturl(self): return 'http://192.168.73.130:443/'
            def read(self, _): return b'<title>400 Bad Request</title>'
            def __enter__(self): return self
            def __exit__(self, *args): pass
        for error in [ssl.SSLCertVerificationError(1, 'certificate verify failed'), socket.timeout('timed out'), ConnectionRefusedError(111, 'refused')]:
            with self.subTest(error=error), patch.object(survey, 'build_opener') as opener, patch.object(survey.socket, 'create_connection') as tcp:
                opener.return_value.open.side_effect = [URLError(error), Response()]
                data = survey.probe_web('192.168.73.130', {}, {'web_ports': [443], 'max_web_ports': 1, 'max_web_pages': 2, 'web_paths': ['/']}, lambda _: None)
                tcp.assert_not_called()
                self.assertEqual(len(data['requests']), 2)
                self.assertIsNotNone(data['requests'][0]['error'])
                self.assertEqual(data['requests'][1]['http_status'], 400)
                self.assertEqual(aggregate_web([('fixture', data)])['services'], [])
                https_handler = opener.call_args_list[0].args[-1]
                self.assertEqual(https_handler._context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(https_handler._context.check_hostname)
        with patch.object(survey.ssl, 'create_default_context') as context, patch.object(survey, 'build_opener') as opener:
            opener.return_value.open.side_effect = URLError(socket.timeout('timed out'))
            survey.probe_web('192.168.73.130', {}, {'web_ports': [443], 'max_web_ports': 1, 'max_web_pages': 1, 'web_paths': ['/'], 'web_ca_file': '/tmp/fixture-ca.pem'}, lambda _: None)
            context.assert_called_once_with(cafile='/tmp/fixture-ca.pem')

    def test_llm_summary_contains_decision_fields_without_html_cookie_or_credentials(self):
        data = {'status': 'observed', 'requests': [row('http://192.168.73.130/dvwa/?password=fixture-secret', title='DVWA', application_hint='DVWA', html='<html>private</html>', cookie='fixture-cookie')] * 2}
        result = llm_web_summary(data)
        serialized = json.dumps(result)
        for secret in ['fixture-secret', 'fixture-cookie', '<html>', 'title']: self.assertNotIn(secret, serialized)
        self.assertEqual(result['request_count'], 2); self.assertEqual(result['unique_observation_count'], 1)
        self.assertEqual(result['observations'][0]['port'], 80)
        self.assertEqual(result['observations'][0]['application_hint'], 'DVWA')

    def test_readiness_optional_unknowns_and_scope_are_not_partial(self):
        evidence = aggregate_web([])
        checked = assess(request(False), profile(evidence), evidence, set())
        self.assertFalse(checked['required_missing'])
        self.assertEqual(next(x for x in checked['missing_information'] if x['field'] == 'web')['status'], 'out_of_scope')
        self.assertFalse(any(x['field'] == 'https' for x in checked['missing_information']))
        self.assertFalse(any('Không chọn' in x for x in checked['warnings']))
        evidence = aggregate_web([('fixture', {'requests': [row('https://192.168.73.130/', None, error={'kind': 'timeout', 'message': 'timed out'})]})])
        checked = assess(request(), profile(evidence), evidence, {'probe_web', 'probe_dvwa'})
        self.assertFalse(checked['required_missing'])
        self.assertEqual(checked['web_readiness']['https']['error_kinds'], ['timeout'])
        failed = assess(request(), profile(evidence), evidence, set(), failed_tools={'probe_web'})
        self.assertTrue(failed['required_missing'])
        self.assertEqual(next(x for x in failed['missing_information'] if x['field'] == 'probe_web_not_completed')['status'], 'check_failed')
        self.assertEqual(next(x for x in failed['missing_information'] if x['field'] == 'probe_dvwa_not_completed')['status'], 'not_checked')

    def test_scripts_orchestration_exports_grouped_profile_and_endpoint_scope_offline(self):
        endpoint = {'data': {'os_name': 'fixture Windows', 'os_version': 'test', 'architecture': '64-bit', 'hostname': 'fixture', 'is_elevated': False, 'services': [], 'limitations': []}}
        agent = {'paw': 'fixture', 'platform': 'windows', 'host': 'fixture', 'privilege': 'User'}
        # Offline fixture policy is independent of config.json and host environment overrides.
        config = {'orchestration_mode': 'scripts', 'allowed_networks': ['192.168.73.0/24'],
                  'web_scope': [{'scheme': 'http', 'port': 80}, {'scheme': 'https', 'port': 443}],
                  'dvwa_auth': {'enabled': False}, 'telemetry': {'enabled': False}}
        raw = {'status': 'observed', 'requests': [row('http://192.168.73.130/dvwa/login.php', title='Login :: DVWA')]}
        for web in (True, False):
            with self.subTest(web=web), tempfile.TemporaryDirectory() as tmp, patch.object(survey, 'load_config', side_effect=AssertionError('Offline test must not read host config')), patch.object(survey, 'preflight', return_value={'ready': True, 'agent': agent}), patch.object(survey, 'collect_endpoint', return_value=endpoint), patch.object(survey, 'probe_web', return_value=copy.deepcopy(raw)) as probe, patch('engine.telemetry.manager_query') as manager, patch('engine.dvwa_session.build_opener') as auth_network:
                directory = Path(tmp)
                result, warnings = survey.execute(request(web), config, directory, lambda *args: None, lambda *args: None)
                TargetProfile.model_validate(result)
                report = json.loads((directory / 'report.json').read_text())
                self.assertEqual(report['status'], 'completed_with_unknowns')
                self.assertEqual(probe.call_count, 2 if web else 0)
                self.assertTrue((directory / 'target_profile.json').exists())
                if web:
                    self.assertEqual(result['services'][-1]['applications'][0]['name'], 'DVWA')
                    self.assertIsNone(result['services'][-1]['applications'][0]['session_ready'])
                else:
                    self.assertFalse(any(x['field'] == 'https' for x in report['missing_information']))
                manager.assert_not_called()
                auth_network.assert_not_called()

    def test_replay_original_run_and_history_are_readable_without_mutation(self):
        source = Path(__file__).parent / 'fixtures/legacy_run'
        spec = importlib.util.spec_from_file_location('replay_web', PROJECT / 'GUI/tools/replay_web.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        before = {p: p.read_bytes() for p in source.rglob('*') if p.is_file()}
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'review'; result = module.replay(source, dest)
            self.assertEqual((result['before_service_count'], result['after_service_count']), (9, 5))
            self.assertEqual((result['request_count'], result['unique_observation_count']), (11, 9))
            self.assertEqual((dest / 'execution.log').read_bytes(), (source / 'execution.log').read_bytes())
            evidence = json.loads((dest / 'web_evidence.json').read_text())
            expected_errors = [r for r in json.loads((source.parent / 'web_web_evidence.json').read_text())['requests'] if r.get('error')]
            actual_errors = [r for r in evidence['requests'] if r.get('error')]
            self.assertEqual([(r['url'], r['error']['kind'], r['log_line']) for r in actual_errors],
                             [(r['url'], r['error']['kind'], r['log_line']) for r in expected_errors])
            normalized = json.loads((dest / 'target_profile.json').read_text())
            self.assertEqual(sum(s['name'] == 'TCP listeners' for s in normalized['services']), 1)
            self.assertEqual([a['name'] for a in normalized['services'][-1]['applications']], ['XAMPP', 'DVWA'])
            TargetProfile.model_validate(normalized); validate_document(normalized, 'target_profile')
            report = json.loads((dest / 'report.json').read_text())
            self.assertEqual(report['status'], 'completed_with_unknowns')
            self.assertEqual(report['web_readiness']['https']['error_kinds'], ['legacy_unknown'])
        raw = json.loads((source / 'target_profile.json').read_text())
        normalized = normalize_profile(raw)
        self.assertEqual(len(normalized['services']), 4)
        hydrated = hydrate({'id': source.name, 'status': 'completed', 'request': request(), 'profile': normalized}, source)
        self.assertEqual(hydrated['status'], 'completed_with_unknowns')
        self.assertEqual(hydrated['web_inspection']['request_count'], 11)
        for path, content in before.items(): self.assertEqual(path.read_bytes(), content)


if __name__ == '__main__': unittest.main()
