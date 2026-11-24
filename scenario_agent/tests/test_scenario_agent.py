"""Offline tests: real catalog/contracts, explicit simulated LLM responses.

These tests DO NOT validate Gemini output quality or E5 relevance.
"""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from scenario_agent.catalog import ability, adversary, compatible_executors, connect
from scenario_agent.config import Config, ROOT
from scenario_agent.llm import QuotaExceeded
from scenario_agent.models import validate_contract
from scenario_agent.rag import load_corpus, retrieve
from scenario_agent.validation import validate_plan, validate_request
from scenario_agent.workflow import Workflow, new_state
from scenario_agent.cli import error_message

ABILITY = '30fe7c15-fca4-4af8-aced-4d245bc51c94'

def fixture_request(state):
    return {'id': state['request_id'], 'text': state['text'], 'target_id': state['target']['id'],
            'objective': 'Xác định người dùng Windows để đánh giá SOC', 'requested_techniques': ['T1033'],
            'scope': ['endpoint'], 'max_tests': 1, 'mode': 'plan_only',
            'constraints': {**{k: None for k in ('baseline_required', 'cleanup_required', 'rollback_required',
                'health_check_required', 'avoid_service_disruption', 'service_changes_require_separate_approval',
                'variants_require_approval', 'setup_cleanup_count_toward_max_tests', 'exploitation_success_required',
                'detection_evaluation_requested')}, 'additional_constraints': []}, 'clarifications_needed': []}

def fixture_plan(state, record):
    a = record['ability']
    return {'id': state['plan_id'], 'name': 'OFFLINE FIXTURE — Windows user discovery',
            'description': 'Dữ liệu kiểm thử validator, không phải kết quả Gemini.', 'atomic_ordering': [ABILITY],
            'metadata': {'schema_version': '1.0', 'request_id': state['request_id'], 'target_id': state['target']['id'],
                'mode': 'plan_only', 'goal': 'Xác định người dùng Windows',
                'selection': {'strategy': 'compose_abilities', 'reason': 'Fixture một ability thật để kiểm tra hợp đồng.', 'sources': [record['provenance']]},
                'readiness': 'needs_information', 'blockers': ['Chưa kiểm chứng executor, quyền và telemetry.'], 'assumptions': [],
                'steps': [{'step_index': 1, 'ability_id': ABILITY, 'name': a['name'], 'role': 'test',
                    'technique_ids': ['T1033'], 'reason': 'Kiểm tra ngữ cảnh người dùng.',
                    'executor': {'platform': 'windows', 'name': 'cmd', 'privilege': None}, 'parameters': {},
                    'prerequisites': [{'condition': 'Xác minh agent, executor và quyền User.', 'status': 'unknown', 'evidence': None}],
                    'readiness': 'needs_information', 'behavior_verification': ['Đối chiếu danh tính người dùng trả về với target.'],
                    'expected_telemetry': [{'source': 'Sysmon', 'observable': 'Process creation', 'availability': 'assumed'}],
                    'baseline': ['Ghi nhận người dùng và tình trạng agent.'],
                    'cleanup_and_rollback': ['Lệnh chỉ đọc danh tính; kiểm tra không phát sinh thay đổi.'],
                    'health_checks': ['Kiểm tra agent và Wazuh còn hoạt động.'], 'sources': [record['provenance']]}],
                'execution_context': {'planner': None, 'agent_group': None, 'agent_paw': None, 'requirements': ['Xác minh operation và facts sau khi duyệt.']},
                'limitations': ['OFFLINE FIXTURE: không gọi Gemini hoặc thực thi ability.']}}

class AgentTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec('huggingface_hub'), 'Hugging Face Hub not installed')
    def test_snapshot_commit_uses_cache_without_transformers_private_fields(self):
        from unittest.mock import patch
        from scenario_agent.rag import model_snapshot_revision
        commit = 'a' * 40
        with patch('huggingface_hub.try_to_load_from_cache', return_value='/cache/models--e5/snapshots/' + commit + '/modules.json'), patch('huggingface_hub.hf_hub_download', side_effect=AssertionError('No network needed')):
            self.assertEqual(model_snapshot_revision(Config()), commit)
        with patch('huggingface_hub.try_to_load_from_cache', return_value='/cache/blobs/' + commit):
            with self.assertRaises(ValueError):
                model_snapshot_revision(Config())

    def test_import_error_preserves_real_cause(self):
        try:
            try:
                raise AttributeError("module 'PIL.Image' has no attribute 'Resampling'")
            except AttributeError as cause:
                raise ModuleNotFoundError('Could not import module PreTrainedModel') from cause
        except ModuleNotFoundError as error:
            message = error_message(error)
        self.assertIn('Resampling', message)
        self.assertNotIn('Missing dependency: None', message)

    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.target = json.loads((ROOT / 'input/target_profile.json').read_text())
        with connect(cls.config.catalog) as db:
            cls.record = ability(db, ABILITY)
        cls.state = new_state(cls.config, 'Kiểm tra người dùng Windows T1033, endpoint, tối đa 1 test.', ROOT / 'input/target_profile.json', 'keyword')
        cls.request = fixture_request(cls.state)
        cls.retrieval = {'abilities': [{'record': cls.record}], 'adversaries': []}

    def test_request_matches_schema(self):
        self.assertEqual(validate_request(self.config, self.request, self.target), [])
        r = copy.deepcopy(self.request); r['max_tests'] = True
        with self.assertRaises(Exception):
            validate_contract(ROOT, 'request', r)

    def test_missing_scope_asks_question(self):
        r = copy.deepcopy(self.request); r['scope'] = []
        self.assertTrue(validate_request(self.config, r, self.target))

    def test_real_catalog_resolution_and_executor_filter(self):
        self.assertEqual(self.record['ability']['technique_id'], 'T1033')
        self.assertTrue(compatible_executors(self.record, self.target))
        target = copy.deepcopy(self.target); target['os']['name'] = 'Linux'
        self.assertFalse(compatible_executors(self.record, target))
        elevated = copy.deepcopy(self.record); elevated['ability']['privilege'] = 'Elevated'
        self.assertFalse(compatible_executors(elevated, self.target))

    def test_conflicting_adversary_excluded(self):
        with connect(self.config.catalog) as db:
            with self.assertRaises(LookupError):
                adversary(db, 'ef4d997c-a0d1-4067-9efa-87c58682db71')

    def test_exact_id_retrieval(self):
        request = copy.deepcopy(self.request); request['text'] = ABILITY
        result = retrieve(self.config, request, self.target, 'keyword', limit=1)
        self.assertEqual(result['abilities'][0]['record']['canonical_id'], ABILITY)
        self.assertEqual(result['mode'], 'keyword')

    def test_corpus_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            config = Config(); config.index = Path(d)
            for name in ('passages.json', 'corpus_manifest.json'):
                (config.index / name).write_bytes((self.config.index / name).read_bytes())
            (config.index / 'passages.json').write_text('[]')
            with self.assertRaises(ValueError):
                load_corpus(config)

    def check_plan(self, plan):
        return validate_plan(self.config, plan, self.request, self.target, self.retrieval, self.state['plan_id'])

    def test_valid_fixture_and_unknown_privilege(self):
        self.check_plan(fixture_plan(self.state, self.record))

    def test_plan_hallucinations_rejected(self):
        for field, value in [('ability_id', 'made-up'), ('technique_ids', ['T9999']), ('sources', []), ('parameters', {'new_fact': None})]:
            with self.subTest(field=field):
                plan = fixture_plan(self.state, self.record); plan['metadata']['steps'][0][field] = value
                with self.assertRaises(Exception):
                    self.check_plan(plan)

    def test_false_verified_and_ready_rejected(self):
        plan = fixture_plan(self.state, self.record)
        plan['metadata']['steps'][0]['prerequisites'][0].update(status='verified', evidence='invented')
        with self.assertRaises(ValueError):
            self.check_plan(plan)

    def test_max_tests_and_reuse_order(self):
        plan = fixture_plan(self.state, self.record)
        plan['atomic_ordering'] *= 2; plan['metadata']['steps'] *= 2
        with self.assertRaises(ValueError):
            self.check_plan(plan)
        plan = fixture_plan(self.state, self.record)
        plan['metadata']['selection']['strategy'] = 'reuse_adversary'
        with self.assertRaises(ValueError):
            self.check_plan(plan)

    def test_quota_checkpoint_resume_phase(self):
        class QuotaLLM:
            def generate(self, *args):
                raise QuotaExceeded()
        with tempfile.TemporaryDirectory() as d:
            config = Config(); config.runs = Path(d)
            s = Workflow(config, QuotaLLM()).step('parse', self.state)
            self.assertEqual(s['status'], 'waiting_quota')
            self.assertEqual(s['resume_phase'], 'parse')
            saved = json.loads((config.runs / s['run_id'] / 'state.json').read_text())
            self.assertEqual(saved['next'], 'END')

    @unittest.skipUnless(importlib.util.find_spec('langgraph'), 'LangGraph not installed')
    def test_actual_langgraph_with_fixture_llm(self):
        state, record = copy.deepcopy(self.state), self.record
        class FixtureLLM:
            def generate(self, instruction, data, schema):
                return fixture_request(state) if 'app_context' in data and 'request' not in data else fixture_plan(state, record)
        with tempfile.TemporaryDirectory() as d:
            config = Config(); config.runs = Path(d)
            # Exact ID ensures the real record is retrieved for the fixture.
            state['text'] += ' ' + ABILITY
            result = Workflow(config, FixtureLLM()).run(state)
            self.assertEqual(result['status'], 'completed', result.get('validation_errors'))
            self.assertTrue(Path(result['output']).is_file())

if __name__ == '__main__':
    unittest.main()
