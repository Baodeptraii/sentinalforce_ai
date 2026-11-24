"""Wire-level multi-turn regression, no network sockets or victim operations."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import survey
from engine.agent import run_agent
from engine.check_llm import check
from engine.llm import ChatClient, LLMError, assistant_message
from test_agent import endpoint


def tool(name='collect_endpoint', identity='call-one', signature='OPAQUE-SIGNATURE'):
    return {'id': identity, 'type': 'function', 'function': {'name': name, 'arguments': ' { } '},
            'extra_content': {'google': {'thought_signature': signature}, 'provider_version': 7}}


class Opener:
    def __init__(self, outcomes): self.outcomes = iter(outcomes); self.requests = []
    def open(self, request, timeout=None):
        self.requests.append(json.loads(request.data))
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception): raise outcome
        message = {'role': 'assistant', 'content': 'Invented model prose is not evidence',
                   'reasoning_content': 'PRIVATE-REASONING', 'extra_content': {'opaque': 'wire-only'}, 'tool_calls': [outcome]}
        return io.BytesIO(json.dumps({'choices': [{'message': message, 'finish_reason': 'tool_calls'}]}).encode())


class TestLLMProtocol(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        env=patch.dict('os.environ',{'SOC_LLM_BUDGET_DB':str(Path(tmp.name)/'budget.sqlite')})
        env.start();self.addCleanup(env.stop)

    def client(self, outcomes):
        with patch.dict('os.environ', {'SURVEY_LLM_API_KEY': 'key-fixture-secret'}):
            client = ChatClient({'llm': {'base_url': 'http://127.0.0.1/v1', 'model': 'fixture'}})
        client.opener = Opener(outcomes)
        return client

    def test_replay_keeps_call_id_arguments_and_provider_metadata(self):
        first, second = tool(), tool('finish_survey', 'call-two', 'OPAQUE-TWO')
        client = self.client([first, second])
        messages = [{'role': 'user', 'content': 'survey'}]
        call = client.choose(messages, [])
        messages += [assistant_message(call, client), {'role': 'tool', 'tool_call_id': call['id'], 'name': 'collect_endpoint', 'content': '{"status":"ok"}'}]
        client.choose(messages, [])
        wire = client.opener.requests[1]['messages']
        self.assertEqual(wire[-2]['tool_calls'][0], first)
        self.assertEqual(wire[-1]['tool_call_id'], first['id'])
        self.assertEqual(wire[-2]['extra_content'], {'opaque': 'wire-only'})
        self.assertNotIn('reasoning_content', wire[-2])
        self.assertEqual(wire[-2]['role'], 'assistant')
        self.assertEqual(wire[-1]['role'], 'tool')

    def test_agent_roundtrip_metadata_is_memory_only_and_profile_is_evidence(self):
        client = self.client([tool(), tool('finish_survey', 'two')])
        request = {'target_ip': '192.0.2.11', 'survey_scope': ['endpoint'], 'web_checks': []}
        agent = {'host': 'FIXTURE', 'platform': 'windows', 'paw': 'fixture', 'privilege': 'User'}
        with tempfile.TemporaryDirectory() as temp, patch.object(survey, 'collect_endpoint', return_value=endpoint()):
            directory = Path(temp)
            profile, _ = run_agent(request, agent, survey.load_config(), directory, lambda *a: None, lambda *a: None, client)
            self.assertEqual(profile['os']['name'], 'Windows fixture')
            trace = (directory / 'ai_trace.json').read_text()
            for private in ['OPAQUE-SIGNATURE', 'PRIVATE-REASONING', 'Invented model prose']:
                self.assertNotIn(private, trace)
                self.assertNotIn(private, json.dumps(profile))
            self.assertTrue(client.opener.requests[1]['messages'][-2]['tool_calls'][0]['extra_content'])

    def test_http400_after_tool_keeps_partial_evidence_and_diagnostic_without_retry(self):
        body = {'error': {'status': 'INVALID_ARGUMENT', 'message': 'Missing thought_signature. key-fixture-secret OPAQUE-SIGNATURE ' + 'x' * 4000}}
        error = HTTPError('http://fixture', 400, '', {}, io.BytesIO(json.dumps(body).encode()))
        client = self.client([tool(), error])
        request = {'target_ip': '192.0.2.11', 'survey_scope': ['endpoint'], 'web_checks': []}
        agent = {'host': 'FIXTURE', 'platform': 'windows', 'paw': 'fixture', 'privilege': 'User'}
        with tempfile.TemporaryDirectory() as temp, patch.object(survey, 'collect_endpoint', return_value=endpoint()) as collect:
            directory = Path(temp)
            profile, _ = run_agent(request, agent, survey.load_config(), directory, lambda *a: None, lambda *a: None, client)
            report = json.loads((directory / 'report.json').read_text())
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(report['failure']['turn'], 2)
            self.assertEqual(report['failure']['http_status'], 400)
            self.assertIn('INVALID_ARGUMENT', report['failure']['message'])
            self.assertIn('thought_signature', report['failure']['message'])
            self.assertLess(len(report['failure']['message']), 1700)
            self.assertEqual(len(client.opener.requests), 2)
            collect.assert_called_once()
            self.assertEqual(profile['os']['name'], 'Windows fixture')
            self.assertEqual(json.loads((directory / 'evidence_index.json').read_text())['records'][0]['status'], 'ok')
            for name in ['report.json', 'ai_trace.json', 'target_profile.json']:
                text = (directory / name).read_text()
                self.assertNotIn('key-fixture-secret', text); self.assertNotIn('OPAQUE-SIGNATURE', text)

    def test_checker_requires_roundtrip_nonce_not_just_one_tool_call(self):
        client = self.client([])
        class Echo:
            requests = []
            def open(self, request, timeout=None):
                body = json.loads(request.data); self.requests.append(body)
                if len(self.requests) == 1: call = tool('confirm_connection')
                else:
                    wire = body['messages']
                    if 'extra_content' not in wire[-2]['tool_calls'][0]:
                        raise HTTPError('http://fixture', 400, '', {}, io.BytesIO(b'{"error":{"message":"Missing thought_signature"}}'))
                    nonce = json.loads(wire[-1]['content'])['nonce']
                    call = tool('confirm_receipt', 'second'); call['function']['arguments'] = json.dumps({'nonce': nonce})
                return io.BytesIO(json.dumps({'choices': [{'message': {'role': 'assistant', 'tool_calls': [call]}}]}).encode())
        client.opener = Echo()
        result = check(client)
        self.assertEqual(result['status'], 'multi_turn_verified')
        self.assertEqual(result['api_requests'], 2); self.assertEqual(result['lab_actions'], 0)
        self.assertEqual(len(client.opener.requests), 2)

    def test_mock_rejects_the_old_stripped_wire_shape(self):
        first = tool()
        stripped = {k: copy.deepcopy(first[k]) for k in ('id', 'type', 'function')}
        client = self.client([])
        class SignatureGate:
            attempts = 0
            def open(self, request, timeout=None):
                self.attempts += 1
                messages = json.loads(request.data)['messages']
                if 'extra_content' not in messages[-2]['tool_calls'][0]:
                    raise HTTPError('http://fixture', 400, '', {}, io.BytesIO(b'{"error":{"message":"Missing thought_signature"}}'))
                return io.BytesIO(b'{"choices":[{"message":{"role":"assistant","content":"done"}}]}')
        client.opener = SignatureGate()
        history = [{'role': 'assistant', 'tool_calls': [stripped]}, {'role': 'tool', 'tool_call_id': first['id'], 'content': '{}'}]
        with self.assertRaises(LLMError) as caught: client.choose(history, [])
        self.assertEqual(caught.exception.http_status, 400)
        history[0]['tool_calls'] = [first]
        self.assertIsNone(client.choose(history, []))
        self.assertEqual(client.opener.attempts, 2)

    def test_malformed_error_body_is_bounded_and_not_echoed(self):
        error = HTTPError('http://fixture', 400, '', {}, io.BytesIO(b'<html>key-fixture-secret PRIVATE</html>'))
        client = self.client([error])
        with self.assertRaises(LLMError) as caught: client.choose([], [])
        self.assertNotIn('PRIVATE', str(caught.exception))
        self.assertEqual(caught.exception.http_status, 400)


if __name__ == '__main__': unittest.main()
