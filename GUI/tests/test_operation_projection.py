"""Regression: large history must not prevent survey readiness checks."""
import io
import json
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from engine.runner import API
from engine import survey
from tests.test_survey import FakeAPI, agent


class OperationProjectionTests(unittest.TestCase):
    def test_history_projection_preserves_busy_membership(self):
        api = API('http://localhost:8888', 'test-only')
        operation = {'id': 'busy', 'name': 'test', 'group': 'lab',
                     'state': 'running', 'host_group': [{'paw': 'fixture'}],
                     'chain': ['x' * 8_000_001]}

        def respond(request, **kwargs):
            query = parse_qs(urlsplit(request.full_url).query)
            row = {k: v for k, v in operation.items() if k in query.get('include', operation)}
            return io.BytesIO(json.dumps([row]).encode())

        with patch.object(api.opener, 'open', side_effect=respond):
            rows = api.call('operations')
        self.assertNotIn('chain', rows[0])
        self.assertEqual(rows[0]['host_group'], [{'paw': 'fixture'}])
        self.assertEqual(rows[0]['state'], 'running')

    def test_projection_does_not_change_mutations_or_detail(self):
        api = API('http://localhost:8888', 'test-only')
        for path, method, body in [('operations', 'POST', {'name': 'test'}),
                                    ('operations/test', 'GET', None),
                                    ('operations/test', 'PATCH', {'state': 'paused'})]:
            with self.subTest(method=method), patch.object(api.opener, 'open', return_value=io.BytesIO(b'{}')) as opened:
                api.call(path, method, body)
                request = opened.call_args.args[0]
                self.assertEqual(request.full_url, api.url + '/api/v2/' + path)
                self.assertEqual(request.method, method)

    def test_preflight_busy_and_finished_history(self):
        config = survey.load_config()
        config.update(orchestration_mode='scripts', allowed_networks=['192.0.2.0/24'])
        request = {'target_ip': '192.0.2.11', 'survey_scope': ['endpoint']}
        for state, ready in [('running', False), ('paused', False), ('finished', True), ('out_of_time', True)]:
            fake = FakeAPI()
            original = fake.call
            fake.call = lambda path: [{'state': state, 'host_group': [agent()]}] if path == 'operations' else original(path)
            with self.subTest(state=state), patch.object(survey, 'api_for', return_value=fake):
                self.assertEqual(survey.preflight(request, config)['ready'], ready)


if __name__ == '__main__':
    unittest.main()
