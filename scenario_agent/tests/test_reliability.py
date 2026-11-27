"""Regression checks for provider outages and source/target constraints; no network."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scenario_agent.catalog import ability, adversary, compatible_executors, connect
from scenario_agent.config import Config, ROOT
from scenario_agent.errors import GeminiAPIError, ServiceUnavailable
from scenario_agent.llm import Gemini, QuotaExceeded
from scenario_agent.rag import eligible
from scenario_agent.selection import check_adaptation
from scenario_agent.validation import validate_plan
from scenario_agent.workflow import Workflow, new_state
from test_scenario_agent import fixture_request, fixture_plan, ABILITY


class ReliabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.target = json.loads((ROOT / 'input/target_profile.json').read_text())
        with connect(cls.config.catalog) as db:
            cls.record = ability(db, ABILITY)
            cls.chain = adversary(db, 'd6ea4c1e-7959-4eb1-a292-b6fd2b06c73e')

    def fake_llm(self, error, attempts=2):
        llm = Gemini.__new__(Gemini)
        llm.model = 'gemini-3.8-flash'
        llm.progress = False
        llm.max_attempts = attempts
        llm.retry_delay = 5
        llm.client = SimpleNamespace(models=SimpleNamespace(generate_content=Mock(side_effect=error)))
        return llm

    @staticmethod
    def api_error(code):
        from google.genai import errors
        error_type = errors.ServerError if code >= 500 else errors.ClientError
        return error_type(code, {'error': {'code': code, 'status': 'TEST', 'message': 'controlled error'}})

    def test_transient_failure_does_not_automatically_retry_or_change_model(self):
        llm=self.fake_llm([self.api_error(503),SimpleNamespace(text='{"ok":true}')])
        with patch('scenario_agent.llm.time.sleep') as sleep,self.assertRaises(ServiceUnavailable):
            llm.generate('test',{}, {'type':'object'})
        sleep.assert_not_called()
        self.assertEqual(llm.client.models.generate_content.call_count,1)
        self.assertEqual(llm.client.models.generate_content.call_args.kwargs['model'],'gemini-3.8-flash')

    def test_old_retry_setting_cannot_reenable_a_hidden_retry_loop(self):
        llm=self.fake_llm(self.api_error(503),attempts=3)
        with patch('scenario_agent.llm.time.sleep') as sleep,self.assertRaises(ServiceUnavailable):
            llm.generate('test',{}, {'type':'object'})
        self.assertEqual(llm.client.models.generate_content.call_count,1);sleep.assert_not_called()

    def test_quota_and_invalid_request_are_not_retried(self):
        for code, expected in ((429, QuotaExceeded), (400, GeminiAPIError)):
            llm = self.fake_llm(self.api_error(code))
            with self.subTest(code=code), patch('scenario_agent.llm.time.sleep') as sleep, self.assertRaises(expected):
                llm.generate('test', {}, {'type': 'object'})
            self.assertEqual(llm.client.models.generate_content.call_count, 1)
            sleep.assert_not_called()

    def test_transport_failure_waits_without_exposing_request(self):
        import httpx
        llm = self.fake_llm(httpx.ReadTimeout('secret request detail'))
        with self.assertRaises(ServiceUnavailable) as caught:
            llm.generate('test', {}, {'type': 'object'})
        self.assertEqual(caught.exception.status, 'TRANSPORT_ERROR')
        self.assertNotIn('secret request detail', str(caught.exception))
        self.assertEqual(llm.client.models.generate_content.call_count, 1)

    def test_retry_configuration_rejects_unbounded_values(self):
        for key, value in (('GEMINI_MAX_ATTEMPTS', '0'), ('GEMINI_MAX_ATTEMPTS', '4'),
                           ('GEMINI_RETRY_DELAY_SECONDS', '-1'), ('GEMINI_RETRY_DELAY_SECONDS', 'nan')):
            with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError):
                    Config()

    def test_service_outage_saves_checkpoint_and_resume_cooldown(self):
        class Outage:
            def generate(self, *args):
                raise ServiceUnavailable(503, 'UNAVAILABLE', 'Controlled outage')
        with tempfile.TemporaryDirectory() as folder:
            config = Config(); config.runs = Path(folder)
            state = new_state(config, 'Windows endpoint discovery', ROOT / 'input/target_profile.json', 'keyword')
            flow = Workflow(config, Outage())
            result = flow.step('parse', state)
            self.assertEqual(result['status'], 'waiting_service')
            self.assertEqual(result['resume_phase'], 'parse')
            self.assertEqual(result['parse_attempts'], 0)
            with patch.object(flow, 'run', side_effect=AssertionError('Cooldown must prevent another API call')):
                resumed = flow.resume(result['run_id'])
            self.assertEqual(resumed['retry_not_before'], result['retry_not_before'])

    def test_known_unavailable_executor_is_filtered_but_unknown_is_retained(self):
        with connect(self.config.catalog) as db:
            record = ability(db, '1324aaa7-be78-5e70-8434-ab514ca75915')
        target = copy.deepcopy(self.target)
        target['capabilities']['powershell_ready'] = False
        self.assertFalse(any(ex['name'] == 'psh' for ex in compatible_executors(record, target)))
        target['capabilities']['powershell_ready'] = None
        self.assertTrue(any(ex['name'] == 'psh' for ex in compatible_executors(record, target)))

    def test_long_adversary_remains_adaptation_candidate(self):
        result = eligible(self.config, [{'kind': 'adversary', 'id': self.chain['id']}], self.target, {'max_tests': 2})
        self.assertEqual(result[0]['ordering'], self.chain['ordering'])
        self.assertFalse(result[0]['reuse_eligible'])
        self.assertTrue(result[0]['adaptation_required'])

    def test_explicit_keep_remaining_allows_only_requested_deletion(self):
        request = {'text': 'Bỏ bước WMIC, giữ nguyên các bước còn lại.', 'constraints': {'additional_constraints': []}}
        check_adaptation([self.chain], self.chain['ordering'][1:], request)
        with self.assertRaisesRegex(ValueError, 'preserve-remaining'):
            check_adaptation([self.chain], self.chain['ordering'][2:], request)
        with self.assertRaisesRegex(ValueError, 'subsequence'):
            check_adaptation([self.chain], [ABILITY], request)

    def test_unresolved_removal_does_not_silently_accept_edit(self):
        request = {'text': 'Bỏ bước không xác định, giữ nguyên các bước còn lại.'}
        with self.assertRaisesRegex(ValueError, 'clarify'):
            check_adaptation([self.chain], self.chain['ordering'][1:], request)

    def test_missing_requested_technique_is_rejected(self):
        state = new_state(self.config, 'Endpoint Windows', ROOT / 'input/target_profile.json', 'keyword')
        request = fixture_request(state); request['requested_techniques'] = ['T1082']
        with self.assertRaisesRegex(ValueError, 'requested techniques'):
            validate_plan(self.config, fixture_plan(state, self.record), request, self.target,
                          {'abilities': [{'record': self.record}], 'adversaries': []}, state['plan_id'])


if __name__ == '__main__':
    unittest.main()
