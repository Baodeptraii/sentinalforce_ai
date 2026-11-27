#!/usr/bin/env python3
"""Acceptance checks for an installed Scenario Agent. Never executes abilities.

Controlled-LLM workflow checks, real catalog/RAG, explicit negative controls,
and optional bounded Gemini runs are recorded separately.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation.fixtures import with_analysis, ground_fixture, coverage_fixture

ENUMERATOR = 'd6ea4c1e-7959-4eb1-a292-b6fd2b06c73e'
USER = '30fe7c15-fca4-4af8-aced-4d245bc51c94'
SYSTEM = '1324aaa7-be78-5e70-8434-ab514ca75915'
VERSION = '29451844-9b76-4e16-a9ee-d6feab4b24db'

def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')

def require(condition, message):
    if not condition:
        raise AssertionError(message)

class Evaluation:
    def __init__(self, root, output, only=None, append=False):
        self.root, self.output = root, output
        from scenario_agent.config import Config, sha256
        from scenario_agent.catalog import connect, ability, adversary
        self.config = Config(root)
        self.config.runs = output / 'runs'
        self.target_path = root / 'input/target_profile.json'
        self.target = json.loads(self.target_path.read_text())
        self.sha256 = sha256
        self.results = json.loads((output / 'results.json').read_text())['results'] if append and (output / 'results.json').exists() else []
        self.only = set(only.split(',')) if only else None
        self.before = self.source_fingerprints()
        with connect(self.config.catalog) as db:
            self.chain = adversary(db, ENUMERATOR)
            self.records = {i: ability(db, i) for i in (USER, SYSTEM, VERSION)}
        self.retrieval_cache = {}
        # Cache only the model object in this evaluation process; do not change
        # production rankings, filtering, vectors, or application files.
        import scenario_agent.rag as rag
        original_encoder = rag.encoder
        models = {}
        def cached_encoder(config, revision=None):
            key = (str(config.cache), config.embedding_model, revision)
            if key not in models:
                models[key] = original_encoder(config, revision)
            return models[key]
        rag.encoder = cached_encoder

    def source_fingerprints(self):
        paths = [self.config.catalog, self.root / 'data/catalog_manifest.json', self.target_path]
        paths += list((self.root / 'data/rag').glob('*'))
        paths += [p for p in (self.root / 'input/schema').glob('*') if p.is_file()]
        entries = json.loads((self.root / 'data/catalog_manifest.json').read_text())['files']
        paths += [self.root / entry['original_path'] for entry in entries]
        paths += list((self.root / 'scenario_agent').glob('*.py'))
        paths += list((self.root / 'tests').glob('*.py'))
        return {str(p.relative_to(self.root)): self.sha256(p) for p in paths}

    def request(self, state, *, objective='Đánh giá SOC bằng discovery trên Windows', scope=None,
                techniques=None, max_tests=None, additional=None):
        from scenario_agent.models import read_schema
        schema = read_schema(self.root, 'request')
        constraints = {key: None for key in schema['properties']['constraints']['required']}
        constraints['additional_constraints'] = additional or []
        return {'id': state['request_id'], 'text': state['text'], 'target_id': state['target']['id'],
                'objective': objective, 'scope': ['endpoint'] if scope is None else scope,
                'requested_techniques': techniques or [], 'max_tests': max_tests,
                'mode': 'plan_only', 'constraints': constraints, 'clarifications_needed': []}

    def state(self, text, target=None, phase='parse'):
        from scenario_agent.workflow import new_state
        path = self.target_path
        if target is not None:
            path = self.output / 'targets' / (target['id'] + '.json')
            dump(path, target)
        state = new_state(self.config, text, path, 'keyword')
        state.update(next=phase, phase=phase)
        return state

    def retrieve(self, request, target=None, mode='keyword'):
        from scenario_agent.rag import retrieve
        target = target or self.target
        key = json.dumps([request, target, mode], sort_keys=True)
        if key not in self.retrieval_cache:
            self.retrieval_cache[key] = retrieve(self.config, request, target, mode, 8)
        return copy.deepcopy(self.retrieval_cache[key])

    @staticmethod
    def records_in(retrieval):
        records = {x['record']['canonical_id']: x['record'] for x in retrieval['abilities']}
        for chain in retrieval['adversaries']:
            records.update({r['canonical_id']: r for r in chain['record']['abilities']})
        return records

    def plan(self, state, request, retrieval, ids, strategy='compose_abilities', chain=None):
        from scenario_agent.catalog import compatible_executors
        records = self.records_in(retrieval)
        sources = [chain['provenance']] if chain else [records[i]['provenance'] for i in ids]
        steps = []
        for pos, identifier in enumerate(ids, 1):
            record = records[identifier]
            a = record['ability']
            executors = compatible_executors(record, state['target'])
            require(bool(executors), 'Fixture cannot select a target-compatible executor')
            ex = next((e for e in executors if e['name'] in ('psh', 'cmd', 'sh')), executors[0])
            steps.append({'step_index': pos, 'ability_id': identifier, 'name': a['name'], 'role': 'test',
                          'technique_ids': [a['technique_id']] if a.get('technique_id') else [],
                          'reason': 'EVAL FIXTURE: selected by the controlled test response.',
                          'executor': {'platform': ex['platform'], 'name': ex['name'], 'privilege': a.get('privilege') or None},
                          'parameters': {k: None for k in ex.get('fact_placeholders', [])},
                          'prerequisites': [{'condition': 'EVAL FIXTURE: verify executor, privilege, scope and per-test dependencies.', 'status': 'unknown', 'evidence': None}],
                          'readiness': 'needs_information',
                          'behavior_verification': ['EVAL FIXTURE: review expected behavior against the catalog before execution.'],
                          'expected_telemetry': [{'source': 'Sysmon', 'observable': 'EVAL FIXTURE: expected process events, not observed results.', 'availability': 'unknown'}],
                          'baseline': ['EVAL FIXTURE: record the initial lab state.'],
                          'cleanup_and_rollback': ['EVAL FIXTURE: review source cleanup and rollback requirements.'],
                          'health_checks': ['EVAL FIXTURE: verify agent/service health.'], 'sources': [record['provenance']]})
        return {'id': state['plan_id'], 'name': 'EVAL FIXTURE — controlled plan',
                'description': 'Controlled LLM response for acceptance testing; not a Gemini-generated scenario.',
                'atomic_ordering': ids,
                'metadata': {'schema_version': '1.0', 'request_id': request['id'], 'target_id': state['target']['id'],
                             'mode': 'plan_only', 'goal': request['objective'] or 'EVAL FIXTURE',
                             'selection': {'strategy': strategy, 'reason': 'EVAL FIXTURE: test the requested selection branch.', 'sources': sources},
                             'readiness': 'needs_information', 'blockers': ['EVAL FIXTURE: environment and ability conditions have not been verified.'],
                             'assumptions': [], 'steps': steps,
                             'execution_context': {'planner': None, 'agent_group': None, 'agent_paw': None, 'requirements': ['Prepare facts and operation only after review.']},
                             'limitations': ['EVAL FIXTURE: no attack commands, live verification or detection result.']}}

    def fixture_record(self, identifier):
        from scenario_agent.catalog import connect, ability
        with connect(self.config.catalog) as db:
            return ability(db,identifier)

    def execute_controlled(self, text, ids, *, strategy='compose_abilities', chain=None, request_args=None,
                           target=None, mode='keyword'):
        from scenario_agent.workflow import Workflow
        evaluation = self
        state = self.state(text, target)
        state['mode'] = mode
        calls = []
        class ControlledLLM:
            def generate(self, instruction, data, schema):
                if data.get('task')=='ground_behaviors':
                    calls.append('ground_behaviors')
                    return ground_fixture(data)
                if 'request' not in data:
                    calls.append('parse')
                    active = dict(state, text=data['app_context']['text'])
                    return with_analysis(evaluation.request(active, **(request_args or {})), [evaluation.fixture_record(i) for i in ids])
                calls.append('build_plan')
                return evaluation.plan(state, data['request'], data['retrieval'], ids, strategy, chain)
        result = Workflow(self.config, ControlledLLM()).run(state)
        return result, calls

    def record(self, case_id, category, mode, function, expected):
        if self.only and case_id not in self.only:
            return
        start = time.monotonic()
        row = {'id': case_id, 'category': category, 'mode': mode, 'expected': expected}
        try:
            row['evidence'] = function()
            row['status'] = 'PASS'
        except AssertionError as error:
            row.update(status='FAIL', detail=str(error))
        except Exception as error:
            from scenario_agent.errors import error_message
            row.update(status='ERROR', detail=error_message(error))
        row['seconds'] = round(time.monotonic() - start, 3)
        self.results.append(row)
        self.save()
        print(case_id + ': ' + row['status'], flush=True)

    def save(self):
        self.results = list({r['id']: r for r in self.results}.values())
        summary = {'agent_root': str(self.root), 'generated_at': datetime.now(timezone.utc).isoformat(),
                   'method': 'Controlled LLM workflow tests, real catalog/RAG, negative business-rule probes, saved live-plan review; not CALDERA execution.',
                   'counts': {s: sum(r['status'] == s for r in self.results) for s in ('PASS', 'FAIL', 'ERROR', 'BLOCKED', 'NOT_RUN')},
                   'results': self.results}
        dump(self.output / 'results.json', summary)

    def validate(self, state, request, retrieval, plan):
        from scenario_agent.validation import validate_plan
        retrieval=copy.deepcopy(retrieval)
        if 'behavior_coverage' not in retrieval:
            retrieval['behavior_coverage']=coverage_fixture(request,list(self.records_in(retrieval).values()),state['target'])
        return validate_plan(self.config, plan, request, state['target'], retrieval, state['plan_id'])

    def run_offline(self):
        from scenario_agent.workflow import Workflow
        from scenario_agent.catalog import connect, adversary, compatible_executors
        from scenario_agent.models import read_schema
        from scenario_agent.llm import Gemini, QuotaExceeded

        def baseline():
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
            process = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                                     cwd=self.root, env=env, text=True, capture_output=True, timeout=90)
            (self.output / 'baseline_tests.log').write_text(process.stdout + process.stderr)
            require(process.returncode == 0, 'Existing test suite failed; see baseline_tests.log')
            return {'exit_code': 0, 'log': 'baseline_tests.log'}
        self.record('BASELINE', 'regression', 'offline_actual_tests', baseline, 'Existing tests pass')

        reuse_text = f'Dùng nguyên chuỗi Enumerator {ENUMERATOR} trên Windows endpoint, giữ thứ tự, tối đa 5 test.'
        def reuse():
            result, calls = self.execute_controlled(reuse_text, self.chain['ordering'], strategy='reuse_adversary', chain=self.chain, request_args={'max_tests': 5})
            require(result['status'] == 'completed', str(result.get('validation_errors', result.get('error'))))
            require(result['plan']['atomic_ordering'] == self.chain['ordering'], 'Reuse changed source ordering')
            return {'strategy': 'reuse_adversary', 'source_id': ENUMERATOR, 'steps': 5, 'model_calls_simulated': calls, 'output': result['output']}
        self.record('REUSE', 'reuse', 'controlled_LLM_actual_workflow_keyword_RAG', reuse, 'Reuse the complete catalog chain in source order')

        def adapt():
            ids = self.chain['ordering'][1:]
            result, calls = self.execute_controlled(f'Điều chỉnh Enumerator {ENUMERATOR} trên endpoint: bỏ bước WMIC, giữ nguyên các bước còn lại.', ids,
                strategy='adapt_adversary', chain=self.chain, request_args={'additional': ['Bỏ bước WMIC đầu tiên, giữ nguyên thứ tự các bước còn lại.']})
            require(result['status'] == 'completed', str(result.get('validation_errors', result.get('error'))))
            require(result['plan']['atomic_ordering'] == ids, 'Adapted steps do not match the requested removal')
            return {'strategy': 'adapt_adversary', 'source_id': ENUMERATOR, 'source_steps': 5, 'result_steps': 4, 'output': result['output']}
        self.record('ADAPT', 'adapt', 'controlled_LLM_actual_workflow_keyword_RAG', adapt, 'Remove one source step, preserve remaining order')

        def reject_reordered_reuse():
            state = self.state(reuse_text)
            request = self.request(state, max_tests=5)
            retrieval = {'abilities': [], 'adversaries': [{'record': self.chain}]}
            plan = self.plan(state, request, retrieval, list(reversed(self.chain['ordering'])), 'reuse_adversary', self.chain)
            try:
                self.validate(state, request, retrieval, plan)
            except ValueError as error:
                return {'rejected': True, 'reason': str(error)}
            raise AssertionError('Reuse was allowed to reorder a source chain')
        self.record('REUSE_ORDER_GUARD', 'reuse', 'adversarial_validator_probe', reject_reordered_reuse, 'Reject reordered steps labeled reuse_adversary')

        compose_text = f'Ghép 2 ability {USER} và {SYSTEM} cho Windows endpoint; khảo sát người dùng T1033 và hệ thống T1082; tối đa 2 test.'
        def compose():
            with connect(self.config.catalog) as db:
                exact = []
                for row in db.execute('SELECT adversary_id FROM adversary_retrieval').fetchall():
                    try:
                        chain = adversary(db, row[0])
                        if len(chain['ordering']) == 2 and set(chain['ordering']) == {USER, SYSTEM}:
                            exact.append(chain['id'])
                    except LookupError:
                        continue
            require(not exact, 'The test pair already exists as a complete 2-step adversary')
            result, _ = self.execute_controlled(compose_text, [USER, SYSTEM], request_args={'max_tests': 2, 'techniques': ['T1033', 'T1082']})
            require(result['status'] == 'completed', str(result.get('validation_errors', result.get('error'))))
            return {'strategy': 'compose_abilities', 'exact_existing_complete_chain': exact, 'output': result['output']}
        self.record('COMPOSE', 'compose', 'controlled_LLM_actual_workflow_keyword_RAG', compose, 'Compose two real abilities without an exact existing complete chain')

        def hybrid():
            state = self.state(reuse_text)
            result = self.retrieve(self.request(state, max_tests=5), mode='hybrid')
            ids = [x['record']['id'] for x in result['adversaries']]
            require(ENUMERATOR in ids, 'Explicit existing adversary not retrieved')
            return {'mode': 'hybrid', 'adversary_ids': ids, 'expected_rank': ids.index(ENUMERATOR) + 1}
        self.record('HYBRID_REUSE', 'retrieval', 'real_E5_FAISS_SQLite', hybrid, 'Find a named/ID-specified eligible adversary through actual hybrid retrieval')

        for case_id, text, technique in [
            ('NATURAL_USER', 'Khảo sát thông tin người dùng Windows', 'T1033'),
            ('NATURAL_SYSTEM', 'Khảo sát cấu hình và thông tin hệ thống Windows', 'T1082'),
            ('NATURAL_PROCESS', 'Liệt kê các tiến trình đang chạy trên Windows', 'T1057'),
        ]:
            def natural_query(text=text, technique=technique):
                state = self.state(text)
                request = self.request(state, objective=None, max_tests=2)
                result = self.retrieve(request, mode='hybrid')
                candidates = result['abilities']
                labels = [x['record']['ability'].get('technique_id') for x in candidates]
                evidence = {'query': text, 'expected_catalog_label': technique,
                            'hit_at_1': technique in labels[:1], 'hit_at_3': technique in labels[:3], 'hit_at_8': technique in labels[:8],
                            'top': [{'id': x['record']['canonical_id'], 'name': x['record']['ability']['name'], 'technique': x['record']['ability'].get('technique_id')} for x in candidates],
                            'limitation': 'Catalog-label recall only; combined-behavior abilities can cover a goal under another technique label. Not a full semantic accuracy score.'}
                dump(self.output / (technique + '_natural_retrieval.json'), evidence)
                require(evidence['hit_at_8'], f'No {technique} catalog label in top 8 for the natural-language query; see {technique}_natural_retrieval.json')
                return evidence
            self.record(case_id, 'retrieval_quality', 'real_E5_FAISS_SQLite_natural_language', natural_query,
                        'Retrieve at least one catalog-labeled relevant technique in top 8 without supplying IDs')

        def clarify():
            result, calls = self.execute_controlled('Giúp tôi tạo kịch bản.', [], request_args={'scope': [], 'objective': None})
            require(result['status'] == 'needs_information', 'Missing scope/objective did not stop for clarification')
            require(calls == ['parse'] and not any(e['node'] == 'retrieve' for e in result['events']), 'Retrieval/build ran before clarification')
            self.clarification_checkpoint = result
            return {'run_id': result['run_id'], 'status': result['status'], 'questions': result['questions'], 'events': result['events']}
        self.record('CLARIFY', 'clarification', 'controlled_LLM_actual_workflow', clarify, 'Stop before retrieval when objective and scope are missing')

        def clarify_resume():
            state = self.clarification_checkpoint
            evaluation = self
            calls = []
            class ReplyLLM:
                def generate(self, instruction, data, schema):
                    if data.get('task')=='ground_behaviors': return ground_fixture(data)
                    if 'request' not in data:
                        calls.append('parse')
                        require('Bổ sung của người dùng:' in data['app_context']['text'], 'Clarification was not appended to the original request')
                        active = dict(state, text=data['app_context']['text'])
                        return with_analysis(evaluation.request(active, max_tests=1, techniques=['T1033']),[evaluation.records[USER]])
                    calls.append('build_plan')
                    return evaluation.plan(state, data['request'], data['retrieval'], [USER])
            result = Workflow(self.config, ReplyLLM()).resume(state['run_id'], 'Tôi chọn Windows endpoint; xác định người dùng T1033, tối đa 1 test, ability ' + USER)
            require(result['status'] == 'completed', 'Clarification checkpoint did not resume to a validated plan')
            from scenario_agent.run_storage import load_run
            resolved, _ = load_run(self.config.runs, state['run_folder'])
            require(result['run_id'] == state['run_id'] and resolved['run_id'] == state['run_id'], 'Clarification lost its original run identity/old-folder lookup')
            self.resumed_clarification = result
            return {'same_run_id': True, 'same_run_folder': result['run_folder'] == state['run_folder'], 'old_folder_lookup_preserved': True, 'status': result['status'], 'simulated_model_calls': calls,
                    'questions_remaining_in_state': result.get('questions', [])}
        self.record('CLARIFY_RESUME', 'clarification', 'controlled_LLM_actual_workflow', clarify_resume, 'Resume the same run after the missing information is supplied')

        def no_stale_questions():
            result = self.resumed_clarification
            require(not result.get('questions'), 'Completed run still contains old unanswered questions; CLI will display them after successful clarification.')
            return {'questions_remaining': []}
        self.record('CLARIFY_PENDING_CLEARED', 'clarification_ui', 'controlled_LLM_actual_workflow', no_stale_questions,
                    'Remove pending clarification questions once the answer is accepted and the plan is completed')

        def scope_mismatch():
            target = copy.deepcopy(self.target); target['id'] = 'eval-no-authorized-surfaces'
            target['capabilities']['execution_scope']['allowed_surfaces'] = []
            result, calls = self.execute_controlled('Kiểm thử endpoint Windows để đánh giá SOC.', [], target=target)
            require(result['status'] == 'needs_information' and calls == ['parse'], 'Out-of-scope target did not stop before retrieval')
            return {'status': result['status'], 'questions': result['questions']}
        self.record('TARGET_SCOPE', 'target', 'controlled_LLM_synthetic_target', scope_mismatch, 'Ask for clarification when endpoint scope is not authorized')

        def unsupported_os():
            target = copy.deepcopy(self.target); target['id'] = 'eval-unsupported-os'; target['os']['name'] = 'UnknownOS'
            result, _ = self.execute_controlled('Khảo sát hệ thống trên endpoint.', [], target=target)
            require(result['status'] == 'no_candidates' and 'plan' not in result, 'Unsupported target OS produced a plan')
            return {'status': result['status'], 'eligible': result['retrieval']['eligible']}
        self.record('TARGET_OS', 'target', 'controlled_LLM_real_filter_synthetic_target', unsupported_os, 'Return no candidates for an unsupported executor platform')

        def elevated():
            record = copy.deepcopy(self.records[SYSTEM]); record['ability']['privilege'] = 'Elevated'
            require(not compatible_executors(record, self.target), 'Known Elevated ability passed a non-admin target filter')
            return {'admin_ready': self.target['capabilities']['admin_ready'], 'known_required_privilege': 'Elevated', 'compatible_executors': 0}
        self.record('ELEVATED_FILTER', 'target', 'synthetic_privilege_real_filter', elevated, 'Exclude an explicitly Elevated ability on a non-admin target')

        def quota():
            from types import SimpleNamespace
            from unittest.mock import Mock
            from google.genai import errors
            state = self.state(f'Khảo sát người dùng Windows endpoint {USER}, tối đa 1 test.')
            llm = Gemini.__new__(Gemini); llm.model = 'mocked-gemini-no-network'
            sdk_error = errors.ClientError(429, {'error': {'code': 429, 'status': 'RESOURCE_EXHAUSTED', 'message': 'Simulated quota exhausted'}})
            llm.client = SimpleNamespace(models=SimpleNamespace(generate_content=Mock(side_effect=sdk_error)))
            paused = Workflow(self.config, llm).run(state)
            require(paused['status'] == 'waiting_quota' and paused['resume_phase'] == 'parse', 'SDK 429 did not preserve the parse checkpoint')
            require(paused['parse_attempts'] == 0, 'Failed API call spent a successful-response repair budget')
            evaluation = self
            class RecoveryLLM:
                def generate(self, instruction, data, schema):
                    if data.get('task')=='ground_behaviors': return ground_fixture(data)
                    if 'request' not in data:
                        return with_analysis(evaluation.request(state, max_tests=1),[evaluation.records[USER]])
                    return evaluation.plan(state, data['request'], data['retrieval'], [USER])
            recovered = Workflow(self.config, RecoveryLLM()).resume(state['run_id'])
            require(recovered['status'] == 'completed', 'Quota checkpoint could not resume to completion')
            return {'simulated_http_status': 429, 'paused': paused['status'], 'resumed': recovered['status'], 'same_run_id': recovered['run_id'] == state['run_id']}
        self.record('QUOTA_RESUME', 'quota', 'mocked_SDK_429_actual_workflow', quota, 'Save checkpoint on SDK 429 and resume after quota recovers')

        def quota_at_build():
            from types import SimpleNamespace
            from unittest.mock import Mock
            from google.genai import errors
            evaluation = self
            state = self.state(f'Khảo sát người dùng Windows endpoint {USER}, tối đa 1 test.')
            sdk = Gemini.__new__(Gemini); sdk.model = 'mocked-gemini-no-network'
            sdk.client = SimpleNamespace(models=SimpleNamespace(generate_content=Mock(side_effect=errors.ClientError(429, {'error': {'code': 429, 'status': 'RESOURCE_EXHAUSTED', 'message': 'Simulated quota at build_plan'}}))))
            class PauseAtPlan:
                def generate(self, instruction, data, schema):
                    if data.get('task')=='ground_behaviors': return ground_fixture(data)
                    if 'request' not in data:
                        return with_analysis(evaluation.request(state, max_tests=1),[evaluation.records[USER]])
                    return sdk.generate(instruction, data, schema)
            paused = Workflow(self.config, PauseAtPlan()).run(state)
            require(paused['status'] == 'waiting_quota' and paused['resume_phase'] == 'build_plan', 'Did not save the plan-generation quota checkpoint')
            require(paused['parse_attempts'] == 1 and paused['plan_attempts'] == 0, 'Quota consumed the wrong retry budget')
            class ResumePlanOnly:
                def generate(self, instruction, data, schema):
                    require('request' in data, 'Resume incorrectly repeated request parsing')
                    return evaluation.plan(state, data['request'], data['retrieval'], [USER])
            recovered = Workflow(self.config, ResumePlanOnly()).resume(state['run_id'])
            require(recovered['status'] == 'completed' and recovered['parse_attempts'] == 1, 'Failed to resume only the plan-generation stage')
            return {'paused_at': 'build_plan', 'status': recovered['status'], 'request_parsing_repeated': False}
        self.record('QUOTA_BUILD_RESUME', 'quota', 'mocked_SDK_429_actual_workflow', quota_at_build, 'Resume after plan-stage quota without paying for parsing again')

        def rejected_fake_verification():
            state = self.state('Khảo sát thông tin người dùng Windows trên endpoint.')
            request = self.request(state, max_tests=1)
            retrieval = {'abilities': [{'record': self.records[USER]}], 'adversaries': []}
            plan = self.plan(state, request, retrieval, [USER])
            plan['metadata']['steps'][0]['prerequisites'][0].update(status='verified', evidence='Invented evidence')
            try:
                self.validate(state, request, retrieval, plan)
            except ValueError as error:
                return {'rejected': True, 'reason': str(error)}
            raise AssertionError('Validator accepted fabricated verified prerequisite evidence')
        self.record('FALSE_EVIDENCE', 'readiness', 'adversarial_validator_probe', rejected_fake_verification, 'Reject invented verification evidence')

        # The following are desired acceptance rules, not expected failures.
        # A FAIL means a demonstrated gap; do not count acceptance of a bad plan as a pass.
        def adapt_limit():
            state = self.state(f'Điều chỉnh Enumerator {ENUMERATOR} cho endpoint Windows, tối đa 2 test.')
            result = self.retrieve(self.request(state, max_tests=2), mode='hybrid')
            ids = [x['record']['id'] for x in result['adversaries']]
            require(ENUMERATOR in ids, 'The 5-step source adversary disappears when max_tests=2, so the planner cannot cite it for adaptation.')
            return {'adversary_ids': ids}
        self.record('ADAPT_LIMIT_SOURCE', 'adapt', 'real_E5_FAISS_SQLite', adapt_limit, 'Keep a source chain retrievable for adaptation even when its original length exceeds the requested plan limit')

        def technique_coverage():
            state = self.state('Endpoint Windows: chỉ kiểm thử xác định người dùng bằng T1033, tối đa 1 test.')
            request = self.request(state, max_tests=1, techniques=['T1033'])
            retrieval = {'abilities': [{'record': self.records[USER]}, {'record': self.records[VERSION]}], 'adversaries': []}
            plan = self.plan(state, request, retrieval, [VERSION])
            try:
                self.validate(state, request, retrieval, plan)
            except ValueError as error:
                return {'rejected': True, 'reason': str(error)}
            raise AssertionError('Validator accepted T1082 PowerShell-version plan although the request explicitly requires T1033.')
        self.record('GOAL_TECHNIQUE_COVERAGE', 'goal', 'adversarial_validator_probe', technique_coverage, 'Reject a plan that omits explicitly requested techniques')

        def changed_adapt():
            state = self.state(f'Bỏ đúng bước WMIC của Enumerator {ENUMERATOR}, giữ nguyên các bước còn lại.')
            request = self.request(state, additional=['Chỉ bỏ WMIC, không thêm hoặc thay thế các bước khác.'])
            retrieval = {'abilities': [{'record': self.records[USER]}], 'adversaries': [{'record': self.chain}]}
            plan = self.plan(state, request, retrieval, [USER], 'adapt_adversary', self.chain)
            try:
                self.validate(state, request, retrieval, plan)
            except ValueError as error:
                return {'rejected': True, 'reason': str(error)}
            raise AssertionError('Validator accepted a completely different one-step chain tagged adapt_adversary, violating the explicit keep-remaining-steps constraint.')
        self.record('ADAPT_CONSTRAINT', 'adapt', 'adversarial_validator_probe', changed_adapt, 'Verify requested changes to the source chain, not just its provenance label')

        def unavailable_executor():
            target = copy.deepcopy(self.target)
            target['id'] = 'eval-known-powershell-unavailable'
            target['capabilities']['powershell_ready'] = False
            state = self.state('Khảo sát thông tin hệ thống Windows endpoint bằng PowerShell.', target)
            request = self.request(state, max_tests=1)
            retrieval = {'abilities': [{'record': self.records[SYSTEM]}], 'adversaries': []}
            # Build the invalid proposal with the original available executor,
            # then test it against the target where that executor is known absent.
            proposal_state = copy.deepcopy(state)
            proposal_state['target']['capabilities']['powershell_ready'] = True
            plan = self.plan(proposal_state, request, retrieval, [SYSTEM])
            try:
                self.validate(state, request, retrieval, plan)
            except ValueError as error:
                return {'rejected': True, 'reason': str(error)}
            raise AssertionError('Validator accepted a psh step as needs_information even though target.powershell_ready is explicitly false; the known unmet condition was not enforced.')
        self.record('KNOWN_EXECUTOR_UNAVAILABLE', 'readiness', 'adversarial_validator_probe_modified_target', unavailable_executor, 'Reject or explicitly block an executor already known to be unavailable')

        self.review_saved_live_plan()
        def verify_source_integrity():
            after = self.source_fingerprints()
            dump(self.output / 'source_integrity.json', {'unchanged': self.before == after, 'before': self.before, 'after': after})
            require(self.before == after, 'Agent/catalog/index/scenario/schema/target source hashes changed')
            return {'unchanged': True, 'files_checked': len(after), 'fingerprints': 'source_integrity.json'}
        self.record('SOURCE_INTEGRITY', 'integrity', 'actual_hash_comparison', verify_source_integrity,
                    'Keep catalog, index manifest and original scenario files unchanged')

    def review_saved_live_plan(self):
        from scenario_agent.validation import validate_plan
        states = []
        for path in (self.root / 'outputs/runs').glob('*/state.json'):
            state = json.loads(path.read_text())
            if state.get('run_id') == 'af421588-b6ce-4661-853c-29e3f409a44a':
                states.append((path, state))
        def review():
            require(len(states) == 1, 'Expected the known completed live run checkpoint')
            path, state = states[0]
            require(state['status'] == 'completed', 'Saved live run is not completed')
            require(state['catalog_sha256'] == self.sha256(self.config.catalog), 'Saved live plan was generated against another catalog version')
            require(state['target_sha256'] == self.sha256(self.target_path), 'Saved live plan target profile has changed')
            records = self.records_in(state['retrieval'])
            if 'behavior_coverage' not in state['retrieval']:
                step=state['plan']['metadata']['steps'][0]
                command=next(ex.get('command') or ex.get('code') or '' for ex in records[step['ability_id']]['ability']['executors'] if (ex['platform'],ex['name'])==(step['executor']['platform'],step['executor']['name']))
                require('whoami' in command.lower(),'Legacy plan has no identity-discovery command to review')
                state['retrieval']['behavior_coverage']={'analysis':{'ordered':False,'behaviors':[{'id':'B1','description':'User identity discovery'}]},
                    'coverage':[{'behavior_id':'B1','matches':[{'ability_id':step['ability_id'],'platform':step['executor']['platform'],'executor':step['executor']['name'],'command_quote':command}]}],
                    'method':'manual_legacy_catalog_command_review','unmodeled_requirements':[]}
            result = validate_plan(self.config, state['plan'], state['request'], state['target'], state['retrieval'], state['plan_id'])
            commands = '\n'.join(str(e.get('command') or '') for i in result['atomic_ordering'] for e in records[i]['ability']['executors'])
            require('whoami' in commands.lower(), 'Chosen ability has no user-identity discovery command')
            require(len(result['atomic_ordering']) <= state['request']['max_tests'], 'Test limit exceeded')
            require(result['metadata']['readiness'] == 'needs_information' and not state['execution_authorized'], 'Saved run falsely claims execution readiness/authorization')
            return {'run_id': state['run_id'], 'state': str(path), 'output': state['output'],
                    'selection': result['metadata']['selection']['strategy'], 'steps': len(result['atomic_ordering']),
                    'identity_discovery_supported_by_catalog_command': True, 'unknown_privilege_preserved': result['metadata']['steps'][0]['executor']['privilege'] is None,
                    'readiness': result['metadata']['readiness'],
                    'manual_review_notes': ['Source command includes nested Invoke-AtomicTest T1082 test 1; verify its dependencies separately.',
                                            'Telemetry remains expected/assumed, not observed detection results.',
                                            'One saved live run is not a multi-case Gemini accuracy benchmark.']}
        self.record('SAVED_LIVE_PLAN_REVIEW', 'goal', 'saved_real_Gemini_output_plus_catalog_review', review,
                    'Saved live plan covers user identity discovery, respects count and retains unverified readiness')

    def live_cases(self):
        return [
            {'id': 'LIVE_REUSE', 'text': f'Dùng nguyên chuỗi Enumerator {ENUMERATOR} để khảo sát tiến trình và trạng thái UAC trên Windows endpoint trong lab, giữ nguyên thứ tự, tối đa 5 test. Chỉ lập kế hoạch.', 'strategy': 'reuse_adversary'},
            {'id': 'LIVE_ADAPT', 'text': f'Điều chỉnh Enumerator {ENUMERATOR} cho Windows endpoint: bỏ bước WMIC đầu tiên, giữ nguyên toàn bộ các bước còn lại và thứ tự. Chỉ lập kế hoạch.', 'strategy': 'adapt_adversary'},
            {'id': 'LIVE_COMPOSE', 'text': f'Không dùng adversary có sẵn. Ghép ability {USER} và {SYSTEM} để khảo sát người dùng T1033 và hệ thống T1082 trên Windows endpoint, tối đa 2 test. Chỉ lập kế hoạch.', 'strategy': 'compose_abilities'},
            {'id': 'LIVE_CLARIFY', 'text': 'Tôi muốn tạo kịch bản.', 'status': 'needs_information'},
            {'id': 'LIVE_INCOMPATIBLE', 'text': 'Tôi muốn chạy khảo sát Linux bằng bash T1059.004 trên target Windows này; không được giả định có WSL hoặc agent Linux. Chỉ lập kế hoạch.', 'status': 'needs_information_or_blocked'},
        ]

    def run_live(self, max_cases, resume_live=False):
        cases = self.live_cases()[:max_cases]
        try:
            socket.getaddrinfo('generativelanguage.googleapis.com', 443)
        except socket.gaierror as error:
            self.results.append({'id': 'GEMINI_CONNECTIVITY', 'category': 'live', 'mode': 'real_network_probe',
                                 'status': 'BLOCKED', 'detail': f'DNS resolution failed ({error.errno}); no Gemini generation requested.'})
            for case in cases:
                self.results.append({'id': case['id'], 'category': 'live', 'mode': 'real_Gemini', 'status': 'NOT_RUN', 'detail': 'Gemini endpoint unavailable from this execution environment.'})
            self.save()
            return
        self.results.append({'id': 'GEMINI_CONNECTIVITY', 'category': 'live', 'mode': 'real_network_probe',
                             'status': 'PASS', 'detail': 'DNS resolved; generation outcomes are checked separately.'})
        from scenario_agent.workflow import Workflow
        for index, case in enumerate(cases):
            previous = next((row for row in reversed(self.results) if row['id'] == case['id']), None)
            if resume_live and previous and previous.get('status') == 'PASS':
                print(f'[{index + 1}/{len(cases)}] {case["id"]}: already PASS; skipped', flush=True)
                continue
            print(f'[{index + 1}/{len(cases)}] {case["id"]}: started', flush=True)
            if resume_live and previous and previous.get('status') == 'BLOCKED' and previous.get('run_id'):
                print(f'  Resuming checkpoint {previous["run_id"]}', flush=True)
                result = Workflow(self.config).resume(previous['run_id'])
            else:
                state = self.state(case['text'])
                state['mode'] = 'hybrid'
                print(f'  Run ID: {state["run_id"]}', flush=True)
                result = Workflow(self.config).run(state)
            row = {'id': case['id'], 'category': 'live', 'mode': 'real_Gemini', 'run_id': result['run_id'], 'observed_status': result['status']}
            if result['status'] in ('waiting_quota', 'waiting_service', 'error'):
                row.update(status='BLOCKED', detail=result.get('error'), output=result.get('output'))
                self.results.append(row)
                for rest in cases[index + 1:]:
                    self.results.append({'id': rest['id'], 'category': 'live', 'mode': 'real_Gemini', 'status': 'NOT_RUN', 'detail': 'Stopped after quota/API/infrastructure error; no automatic model fallback.'})
                self.save()
                print(f'{case["id"]}: BLOCKED — {result.get("error")}', flush=True)
                break
            try:
                if 'strategy' in case:
                    require(result['status'] == 'completed', str(result.get('validation_errors', result.get('error'))))
                    plan = result['plan']
                    require(plan['metadata']['selection']['strategy'] == case['strategy'], 'Observed selection strategy differs from requested behavior')
                    if case['id'] == 'LIVE_REUSE': require(plan['atomic_ordering'] == self.chain['ordering'], 'Reuse ordering differs')
                    if case['id'] == 'LIVE_ADAPT': require(plan['atomic_ordering'] == self.chain['ordering'][1:], 'Adaptation did not preserve requested remaining steps')
                    if case['id'] == 'LIVE_COMPOSE': require(set(plan['atomic_ordering']) == {USER, SYSTEM} and len(plan['atomic_ordering']) == 2, 'Composed IDs differ from request')
                    row['output'] = result.get('output')
                elif case['id'] == 'LIVE_CLARIFY':
                    require(result['status'] == 'needs_information', 'Vague request did not ask for clarification')
                else:
                    require(result['status'] in ('needs_information', 'no_candidates') or
                            result.get('plan', {}).get('metadata', {}).get('readiness') == 'blocked',
                            'Known incompatible Linux execution request was not explicitly stopped/blocked')
                row['status'] = 'PASS'
            except AssertionError as error:
                row.update(status='FAIL', detail=str(error))
            self.results.append(row)
            self.save()
            print(case['id'] + ': ' + row['status'], flush=True)

    def markdown(self):
        lines = ['# Kết quả kiểm chứng Scenario Agent', '',
                 'Mỗi kết quả có nhãn phương pháp. Kiểm thử LLM mô phỏng không chứng minh Gemini tự chọn đúng; tìm kiếm E5/FAISS và catalog là dữ liệu thật. Không thực thi ability/CALDERA.', '',
                 '| Case | Phương pháp | Kết quả | Ghi nhận |', '|---|---|---|---|']
        for row in self.results:
            detail = row.get('detail') or row.get('expected') or ''
            lines.append('| ' + ' | '.join(str(x).replace('|', '/').replace('\n', ' ') for x in
                                          (row['id'], row['mode'], row['status'], detail)) + ' |')
        lines += ['', '## Cách đọc kết quả', '',
                  '- PASS ở controlled_LLM: nhánh workflow/validator chạy được với phản hồi được kiểm soát; chưa chứng minh chất lượng suy luận Gemini.',
                  '- FAIL ở adversarial_validator_probe: phản ví dụ cho thấy thiếu kiểm tra nghiệp vụ, không phải đã thực thi một hành vi trên target.',
                  '- BLOCKED/NOT_RUN ở real_Gemini: chưa có bằng chứng thực tế cho case đó; không suy ra agent đạt hoặc không đạt.',
                  '- Review plan đã lưu chỉ chứng minh một yêu cầu thực tế; cần benchmark nhiều yêu cầu và kiểm tra dependencies trước khi duyệt.', '',
                  'Chi tiết và đường dẫn artifact trong `results.json`. Bộ kiểm chứng giữ nguyên YAML/catalog/index nguồn.']
        (self.output / 'RESULTS.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        by_id = {row['id']: row for row in self.results}
        summary = ['# Kết luận kiểm chứng Scenario Agent', '',
                   'Kết quả được tính từ từng case; kiểm thử mô phỏng và Gemini thực tế được ghi riêng. Không thực thi CALDERA.', '',
                   '## Các điều kiện nghiệp vụ đã kiểm tra', '']
        checks = {
            'GOAL_TECHNIQUE_COVERAGE': 'Chặn plan bỏ sót technique được chỉ định.',
            'KNOWN_EXECUTOR_UNAVAILABLE': 'Chặn executor được target khai báo không sẵn sàng.',
            'ADAPT_LIMIT_SOURCE': 'Giữ nguồn chuỗi dài để điều chỉnh theo giới hạn test.',
            'ADAPT_CONSTRAINT': 'Chặn thay toàn bộ chuỗi khi yêu cầu giữ các bước còn lại.',
            'CLARIFY_PENDING_CLEARED': 'Xóa câu hỏi đang chờ sau khi đã làm rõ.'}
        for case_id, description in checks.items():
            row = by_id.get(case_id)
            if row:
                summary.append(f'- **{case_id}: {row["status"]}**. {description}')
        failures = [row['id'] for row in self.results if row['status'] in ('FAIL', 'ERROR')]
        summary += ['', 'Case chưa đạt/lỗi: ' + (', '.join(failures) if failures else 'Không có trong phạm vi lần chạy này.')]
        natural = [by_id[k] for k in ('NATURAL_USER', 'NATURAL_SYSTEM', 'NATURAL_PROCESS') if k in by_id]
        if natural:
            first = sum(bool(row.get('evidence', {}).get('hit_at_1')) for row in natural)
            eighth = sum(bool(row.get('evidence', {}).get('hit_at_8')) for row in natural)
            summary += ['', '## Truy hồi tiếng Việt', '',
                        f'Trên {len(natural)} câu discovery mẫu không cung cấp ID: {first}/{len(natural)} có nhãn technique mong đợi ở top 1, {eighth}/{len(natural)} ở top 8. Đây là phép thử nhỏ theo nhãn catalog, không phải độ chính xác ngữ nghĩa tổng thể; một ability có thể kết hợp nhiều hành vi.']
        live_rows = [row for row in self.results if row['mode'] == 'real_Gemini']
        if live_rows:
            summary += ['', '## Kiểm chứng bằng Gemini mới', '',
                        'Các kết quả logic không thay thế kết quả Gemini thực tế. Năm case live gồm reuse, adapt, compose, hỏi lại và Linux/bash trên target Windows.']
            for row in live_rows:
                summary.append(f'- {row["id"]}: **{row["status"]}**. ' + str(row.get('detail') or row.get('observed_status') or ''))
        else:
            summary += ['', '## Kiểm chứng bằng Gemini mới', '', 'Chưa yêu cầu chạy case Gemini mới trong lượt đánh giá này.']
        summary += ['',
                    'Chi tiết từng case, phản hồi, event và đường dẫn plan nằm trong `results.json`; bảng đầy đủ ở `RESULTS.md`. Các plan có nhãn EVAL FIXTURE là dữ liệu kiểm thử, không phải kịch bản đã được Gemini chọn hoặc phê duyệt.']
        if not any(row['mode'].startswith('controlled_LLM') for row in self.results):
            summary = ['# Kết quả các case Gemini thực tế', '',
                       'Báo cáo này chỉ ghi các case live. Xem kết quả offline riêng để biết những phản ví dụ của validator; không suy ra toàn bộ hệ thống hoàn thiện từ một số case live đạt.', '']
            for row in self.results:
                summary.append(f'- **{row["id"]}: {row["status"]}**. ' + str(row.get('detail') or row.get('observed_status') or ''))
            summary += ['', 'Chi tiết, run_id và đường dẫn plan: `results.json`. Không thực thi CALDERA.']
        (self.output / 'SUMMARY.md').write_text('\n'.join(summary) + '\n', encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-root', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--live', action='store_true', help='May consume Gemini project quota; stops on 429/API error')
    parser.add_argument('--max-live-cases', type=int, choices=range(1, 6), default=5)
    parser.add_argument('--live-only', action='store_true')
    parser.add_argument('--only', help='Comma-separated offline case IDs; CLARIFY_RESUME also needs CLARIFY')
    parser.add_argument('--append', action='store_true', help='Keep existing results and replace cases rerun by ID')
    parser.add_argument('--resume-live', action='store_true', help='With --append, resume blocked live checkpoints and skip already-passing cases')
    args = parser.parse_args()
    if args.resume_live and not (args.live and args.append):
        parser.error('--resume-live requires --live and --append')
    root = args.agent_root.resolve(); output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(root))
    os.environ.setdefault('HF_HUB_OFFLINE', '1')
    os.environ.setdefault('TRANSFORMERS_OFFLINE', '1')
    if args.live:
        os.environ.setdefault('GEMINI_PROGRESS', '1')
    evaluation = Evaluation(root, output, args.only, args.append)
    dump(output / 'live_cases.json', evaluation.live_cases())
    if not args.live_only:
        evaluation.run_offline()
    if args.live:
        evaluation.run_live(args.max_live_cases, args.resume_live)
    evaluation.save(); evaluation.markdown()
    print(json.dumps({'report': str(output / 'RESULTS.md'),
                      'counts': {s: sum(r['status'] == s for r in evaluation.results) for s in ('PASS', 'FAIL', 'ERROR', 'BLOCKED', 'NOT_RUN')}}, ensure_ascii=False, indent=2))
    if any(row['status'] in ('FAIL', 'ERROR') for row in evaluation.results):
        return 1
    if args.live and any(row['status'] in ('BLOCKED', 'NOT_RUN') for row in evaluation.results):
        return 2
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
