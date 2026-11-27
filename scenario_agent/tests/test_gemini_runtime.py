"""Runtime timeout/thinking/progress checks. No network or API calls."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scenario_agent.config import Config, ROOT
from scenario_agent.llm import Gemini
from scenario_agent.errors import GeminiAPIError


class GeminiRuntimeTests(unittest.TestCase):
    def test_configurable_timeout_and_invalid_bounds(self):
        with patch.dict(os.environ, {'GEMINI_TIMEOUT_SECONDS': '300', 'GEMINI_PARSE_THINKING_LEVEL': 'low'}):
            config = Config()
            self.assertEqual(config.gemini_timeout_ms, 300000)
            self.assertEqual(config.gemini_parse_thinking_level, 'low')
        for value in ('0', '601', 'nan', 'inf', 'bad'):
            with self.subTest(value=value), patch.dict(os.environ, {'GEMINI_TIMEOUT_SECONDS': value}):
                with self.assertRaises(ValueError):
                    Config()

    def test_sdk_receives_millisecond_timeout_and_one_attempt(self):
        config = SimpleNamespace(free_confirmed=True, gemini_timeout_ms=300000,
                                 gemini_parse_thinking_level='low', gemini_progress=False,
                                 model='gemini-3.8-flash')
        with patch.dict(os.environ, {'GEMINI_API_KEY': 'fake-local-test-key'}), patch('google.genai.Client') as client:
            Gemini(config)
        options = client.call_args.kwargs['http_options']
        self.assertEqual(options.timeout, 300000)
        self.assertEqual(options.retry_options.attempts, 1)

    def fake_llm(self, model='gemini-3.8-flash'):
        llm = Gemini.__new__(Gemini)
        llm.model = model
        llm.parse_thinking_level = 'low'
        llm.progress = False
        llm.timeout_ms = 300000
        llm.client = SimpleNamespace(models=SimpleNamespace(generate_content=Mock(return_value=SimpleNamespace(text='{"ok": true}'))))
        return llm

    def test_low_thinking_only_for_parse_and_supported_model(self):
        from google.genai import types
        llm = self.fake_llm()
        parse_data = {'app_context': {}, 'text': 'Discovery'}
        llm.generate('instruction', parse_data, {'type': 'object'})
        config = llm.client.models.generate_content.call_args.kwargs['config']
        self.assertEqual(config['thinking_config'], {'thinking_level': 'low'})
        types.GenerateContentConfig.model_validate(config)
        llm.generate('instruction', {'request': {}}, {'type': 'object'})
        self.assertNotIn('thinking_config', llm.client.models.generate_content.call_args.kwargs['config'])
        other = self.fake_llm('another-model')
        other.generate('instruction', parse_data, {'type': 'object'})
        self.assertNotIn('thinking_config', other.client.models.generate_content.call_args.kwargs['config'])

    def test_progress_never_prints_key_or_request_body(self):
        llm = self.fake_llm()
        llm.progress = True
        stream = io.StringIO()
        secret = 'fake-secret-must-not-appear'
        with patch.dict(os.environ, {'GEMINI_API_KEY': secret}), contextlib.redirect_stderr(stream):
            llm.generate('do-not-print-instruction', {'text': secret, 'app_context': {}}, {'type': 'object'})
        log = stream.getvalue()
        self.assertIn('timeout=300s', log)
        self.assertIn('response received', log)
        self.assertNotIn(secret, log)
        self.assertNotIn('do-not-print-instruction', log)

    def test_504_is_preserved_and_not_retried_indefinitely(self):
        from google.genai import errors
        llm = self.fake_llm()
        llm.client.models.generate_content.side_effect = errors.ServerError(504, {'error': {
            'code': 504, 'status': 'DEADLINE_EXCEEDED', 'message': 'Deadline expired'}})
        with self.assertRaises(GeminiAPIError) as caught:
            llm.generate('test', {}, {'type': 'object'})
        self.assertEqual(caught.exception.code, 504)
        self.assertEqual(llm.client.models.generate_content.call_count, 1)


class EvaluationContinuationTests(unittest.TestCase):
    def evaluator(self, rows):
        path = ROOT / 'evaluation/run_verification.py'
        spec = importlib.util.spec_from_file_location('runtime_eval_under_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        evaluation = module.Evaluation.__new__(module.Evaluation)
        evaluation.results = rows
        evaluation.config = SimpleNamespace()
        evaluation.live_cases = lambda: [{'id': 'CASE', 'text': 'test', 'strategy': 'compose_abilities'}]
        evaluation.state = Mock(side_effect=AssertionError('Do not create a new run while resuming'))
        evaluation.save = Mock()
        return evaluation

    def test_blocked_live_case_resumes_existing_checkpoint(self):
        evaluation = self.evaluator([{'id': 'CASE', 'status': 'BLOCKED', 'run_id': 'existing-uuid'}])
        result = {'run_id': 'existing-uuid', 'status': 'completed', 'plan': {
            'metadata': {'selection': {'strategy': 'compose_abilities'}}}}
        with patch('socket.getaddrinfo', return_value=[]), patch('scenario_agent.workflow.Workflow') as workflow, contextlib.redirect_stdout(io.StringIO()):
            workflow.return_value.resume.return_value = result
            evaluation.run_live(1, resume_live=True)
        workflow.return_value.resume.assert_called_once_with('existing-uuid')
        workflow.return_value.run.assert_not_called()
        evaluation.state.assert_not_called()
        self.assertEqual(evaluation.results[-1]['status'], 'PASS')

    def test_passing_live_case_is_not_called_again(self):
        evaluation = self.evaluator([{'id': 'CASE', 'status': 'PASS', 'run_id': 'existing-uuid'}])
        with patch('socket.getaddrinfo', return_value=[]), patch('scenario_agent.workflow.Workflow') as workflow, contextlib.redirect_stdout(io.StringIO()):
            evaluation.run_live(1, resume_live=True)
        workflow.assert_not_called()


if __name__ == '__main__':
    unittest.main()
