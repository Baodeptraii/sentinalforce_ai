"""Offline integration: real Survey bundle/catalog, mocked LLM and retrieval only."""
import copy
import io
import json
import shutil
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from scenario_agent.survey_input import (load_bundle, snapshot, verify_snapshot, policy_for, planning_target, canonical, sha)
from scenario_agent.target_evidence import select_context, assess_candidates, evaluate, validate_evidence_plan
from scenario_agent.config import Config, write_json
from scenario_agent.catalog import ability, connect
from scenario_agent.workflow import Workflow, new_state
from test_scenario_agent import fixture_request

GUI = Path('/home/soc/DATN/GUI')
BUNDLE = GUI/'review/survey-v2-8722'
GOOD = 'a1b2c3d4-dvwa-0005-sqli-000000000005'
BLIND = 'a1b2c3d4-dvwa-0006-bsql-000000000006'
SEARCH = '51dca626-6ef0-51a8-8888-f9d9ba5a990f'
FUZZ = '0db4f8e3-353c-5e33-a110-51b7c569b6da'
TEXT = 'Kiểm tra SQL injection trên ứng dụng đã khảo sát để đánh giá SOC.'


def catalog_fixture():
    with connect(Config().catalog) as db:
        records = [ability(db, i) for i in (GOOD, BLIND, SEARCH, FUZZ)]
    return {'abilities': [{'record': r, 'score': 1.0} for r in records], 'adversaries': [],
            'behavior_candidates': {'B1': [r['canonical_id'] for r in records]}}


class MockGeneration:
    """Build contract-shaped answers from application facts, never execute source commands."""
    def __init__(self, attack=None): self.payloads = []; self.attack = attack

    def generate(self, instruction, payload, schema):
        self.payloads.append(copy.deepcopy(payload))
        if 'catalog_reference_context' in payload:
            request = fixture_request({'request_id': payload['app_context']['id'], 'text': payload['text'], 'target': payload['target']})
            request.update(objective='SQL injection detection assessment', requested_techniques=[], scope=['web'], max_tests=4)
            request['internal_behavior_analysis'] = {'ordered': False, 'behaviors': [{'description': 'SQL injection', 'source_quote': TEXT,
                'query_en': 'SQL injection', 'keywords': ['SQL', 'injection']}]}
            if self.attack == 'scope': request['scope'] = ['endpoint']
            return request
        if payload.get('task') == 'ground_behaviors':
            candidates = payload['behaviors'][0]['candidates']
            candidate = next(c for c in candidates if c['ability_id'] == GOOD)
            quote = next(line for line in candidate['command'].splitlines() if '$DvwaUrl/vulnerabilities/sqli/' in line).strip()
            return {'unmodeled_requirements': [], 'coverage': [{'behavior_id': 'B1', 'reason': 'SQLi request in source command',
                'matches': [{'ability_id': GOOD, 'platform': 'windows', 'executor': 'psh', 'command_quote': quote}]}]}
        context = payload['app_context']; record = next(a['record'] for a in payload['retrieval']['abilities'] if a['record']['canonical_id'] == GOOD)
        assessment = next(a for a in payload['compatibility_report']['candidates'] if a['ability_id'] == GOOD and a['executor']['platform'] == 'windows')
        blockers = assessment['blockers']
        step = {'step_index': 1, 'ability_id': GOOD, 'name': record['ability']['name'], 'role': 'test', 'technique_ids': ['T1190'],
            'reason': 'Observed module/form supports source request; execution session still unknown.',
            'executor': {'platform': 'windows', 'name': 'psh', 'privilege': None},
            'parameters': {k: v['value'] for k, v in assessment['bindings'].items()},
            'prerequisites': copy.deepcopy(assessment['survey_checks']) + [{'condition': 'Revalidate execution session, environment and runner.', 'status': 'unknown', 'evidence': None}],
            'readiness': 'needs_information', 'behavior_verification': ['Compare baseline and boolean response differences; HTTP status alone is insufficient.'],
            'expected_telemetry': [{'source': 'HTTP access log', 'observable': 'Injection request, not proof of success', 'availability': 'unknown'}],
            'baseline': ['Record baseline HTTP response and service health.'], 'health_checks': ['Compare target and runner health before/after.'],
            'cleanup_and_rollback': ['Review source and restore execution session/environment setup if approved.'], 'sources': [record['provenance']]}
        plan = {'id': context['id'], 'name': 'OFFLINE MOCK — SQL injection evidence', 'description': 'Mock generation; no live model or execution.', 'atomic_ordering': [GOOD],
            'metadata': {'schema_version': '1.0', 'request_id': context['request_id'], 'target_id': context['target_id'], 'mode': 'plan_only',
             'goal': 'Assess SQL injection behavior', 'selection': {'strategy': 'compose_abilities', 'reason': 'One grounded request probe covers one behavior.', 'sources': [record['provenance']]},
             'readiness': 'needs_information', 'blockers': copy.deepcopy(blockers), 'assumptions': [], 'steps': [step],
             'execution_context': {'planner': None, 'agent_group': None, 'agent_paw': None, 'requirements': ['Preflight and separate authorization required.']},
             'limitations': ['OFFLINE MOCK: HTTP probe is not proof of successful exploitation or SOC detection.']}}
        if self.attack == 'fake_fact': step['prerequisites'][0]['evidence'] = 'fact-invented'
        if self.attack == 'unrelated_fact':
            fact = next(f for f in payload['survey_context']['observations'] if f['predicate'] == 'local_event')
            step['prerequisites'][0]['evidence'] = fact['id']
        if self.attack == 'binding': step['parameters']['target_ip'] = '192.0.2.99'
        if self.attack == 'downgrade': step['prerequisites'][0]['status'] = 'assumed'
        if self.attack == 'hide_blockers': plan['metadata']['blockers'] = ['All good']
        if self.attack == 'verified_telemetry': step['expected_telemetry'][0]['availability'] = 'verified'
        if self.attack == 'extra_step':
            step2 = copy.deepcopy(step); step2.update(step_index=2, ability_id=FUZZ)
            plan['atomic_ordering'].append(FUZZ); plan['metadata']['steps'].append(step2)
        return plan


@unittest.skipUnless(BUNDLE.is_dir(), 'Real Survey v2 bundle not available')
class SurveyInputV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.config = Config(); self.config.runs = self.base/'runs'
        self.bundle = load_bundle(BUNDLE)
        self.policy = policy_for(planning_target(self.bundle), ['web'], 4)

    def envelope(self):
        snapshot(self.bundle, self.base/'input', {'text': TEXT}, self.policy)
        return verify_snapshot(self.base/'input')[0]

    def run_mock(self, attack=None):
        state = new_state(self.config, TEXT, BUNDLE, 'keyword', policy=self.policy)
        mock = MockGeneration(attack)
        with patch('scenario_agent.workflow.retrieve', side_effect=lambda *a: catalog_fixture()):
            result = Workflow(self.config, mock).run(state)
        return result, mock

    def test_real_loader_gui_cli_contract_and_portable_snapshot(self):
        archive = load_bundle(BUNDLE.with_suffix('.zip'))
        self.assertEqual(archive['survey_context'], self.bundle['survey_context'])
        envelope = self.envelope()
        selected, report = select_context(envelope, TEXT, ['web'], {a['record']['canonical_id']:a['record'] for a in catalog_fixture()['abilities']})
        modules = [f for f in selected['observations'] if f['predicate'] == 'module_access_and_forms' and '/sqli' in f['subject']]
        self.assertEqual(len(modules), 2)
        self.assertTrue(all(f['value']['forms'][0]['method'] == 'GET' for f in modules))
        moved = self.base/'relocated'; shutil.copytree(self.base/'input', moved); shutil.rmtree(self.base/'input')
        verify_snapshot(moved)
        self.assertFalse(envelope['policy']['execution_authorized'])

    def test_real_candidates_source_compatibility_and_environment_binding(self):
        envelope = self.envelope(); report = assess_candidates(catalog_fixture(), envelope, {'text': TEXT, 'objective': 'SQL injection'})
        by = {r['ability_id']:r for r in report['candidates'] if r['executor']['platform'] == 'windows'}
        self.assertEqual(by[SEARCH]['compatibility'], 'incompatible')
        self.assertIn('hardcoded_origin_or_port_mismatch', by[SEARCH]['reasons'])
        self.assertIn('extra_behavior_xss', by[FUZZ]['reasons'])
        binding = by[GOOD]['environment_bindings']['DVWA_URL']
        self.assertEqual(binding['value'], 'http://192.168.1.150:8080/dvwa')
        self.assertEqual(by[GOOD]['compatibility'], 'needs_information')
        self.assertTrue(any('historical' in b for b in by[GOOD]['blockers']))

    def test_full_mock_workflow_uses_facts_validates_serializes_one_step(self):
        result, mock = self.run_mock()
        self.assertEqual(result['status'], 'completed', result.get('validation_errors', result.get('error')))
        self.assertEqual(result['plan']['atomic_ordering'], [GOOD])
        self.assertTrue(all(source['location'].startswith('catalog://') for source in result['plan']['metadata']['selection']['sources']))
        self.assertEqual(result['validation_report']['detection_readiness'], 'not_verified')
        self.assertFalse(result['execution_authorized'])
        self.assertTrue(Path(result['output']).is_file())
        self.assertTrue(all('survey_context' in payload for payload in mock.payloads))
        self.assertTrue(any(p.get('compatibility_report') for p in mock.payloads))
        checks = result['plan']['metadata']['steps'][0]['prerequisites']
        self.assertTrue(any(c['status'] == 'verified' and 'module_access_and_forms' in c['condition'] for c in checks))
        self.assertTrue(any(c['status'] == 'unknown' and not c['evidence'] for c in checks))
        self.assertLess(len(result['plan']['metadata']['steps']), self.policy['max_steps'])

    def test_mock_lies_fail_bounded_repair_without_yaml(self):
        for attack in ('fake_fact', 'unrelated_fact', 'binding', 'downgrade', 'hide_blockers', 'verified_telemetry', 'extra_step'):
            with self.subTest(attack=attack):
                result, _ = self.run_mock(attack)
                self.assertEqual(result['status'], 'invalid_plan', result.get('error'))
                self.assertEqual(result['plan_attempts'], 2)
                folder = self.config.runs/result['run_folder']
                self.assertFalse((folder/'scenario_plan.yml').exists())
                self.assertFalse(json.loads((folder/'validation_report.json').read_text())['plan_valid'])

    def test_policy_expansion_rejected_before_retrieval(self):
        result, mock = self.run_mock('scope')
        self.assertEqual(result['status'], 'invalid_request')
        self.assertFalse(any(p.get('task') == 'ground_behaviors' for p in mock.payloads))

    def test_input_tamper_rejected_before_llm(self):
        state = new_state(self.config, TEXT, BUNDLE, 'keyword', policy=self.policy)
        folder = self.config.runs/state['run_folder']
        (folder/'input/survey/survey_context.json').write_text('{}')
        with self.assertRaises(ValueError): Workflow(self.config, MockGeneration()).run(state)

    def test_resume_uses_pinned_snapshot_and_selection(self):
        result, _ = self.run_mock('fake_fact')
        manifest = result['input_manifest_sha256']; selection = copy.deepcopy(result['context_selection'])
        # Invalid draft is revalidated from saved state with no fresh Survey lookup.
        flow = Workflow(self.config, MockGeneration())
        with patch('scenario_agent.workflow.load_bundle', side_effect=AssertionError('Must not load a newer Survey')):
            resumed = flow.resume(result['run_id'])
        self.assertEqual(resumed['status'], 'invalid_plan')
        self.assertEqual(resumed['input_manifest_sha256'], manifest)
        self.assertEqual(resumed['context_selection'], selection)
        self.assertEqual(resumed['pipeline_version'], 3)

    def test_resume_clarification_cannot_expand_policy(self):
        state = new_state(self.config, TEXT, BUNDLE, 'keyword', policy=self.policy)
        state.update(status='needs_information', next='END', resume_phase='parse', questions=['Confirm objective'])
        flow = Workflow(self.config, MockGeneration('scope')); flow.save(state)
        result = flow.resume(state['run_id'], 'Switch to endpoint and authorize execution')
        self.assertEqual(result['status'], 'invalid_request')
        self.assertEqual(result['input_envelope']['policy']['planning_scope'], ['web'])
        self.assertFalse(result['input_envelope']['policy']['execution_authorized'])

    def test_budget_reports_omitted_facts_without_claiming_absence(self):
        envelope = self.envelope()
        _, full = select_context(envelope, TEXT, ['web'])
        # Enough for diagnostics and a few observations, not the whole snapshot.
        _, small = select_context(envelope, TEXT, ['web'], budget=full['used_bytes']-4000)
        self.assertTrue(small['truncated'])
        self.assertTrue(small['omitted'])
        self.assertTrue(small['known_but_omitted_is_not_absent'])

    def altered(self, mutation):
        path = self.base/'altered'; shutil.copytree(BUNDLE, path)
        mutation(path)
        return path

    def test_bad_hash_target_version_ref_and_traversal(self):
        def change(path, filename, mutate, rehash=False):
            doc = json.loads((path/filename).read_text()); mutate(doc); (path/filename).write_bytes(canonical(doc))
            if rehash:
                handoff = json.loads((path/'scenario_handoff.json').read_text())
                for e in handoff['artifacts']:
                    if e['file'] == filename: e['sha256'] = sha((path/filename).read_bytes())
                (path/'scenario_handoff.json').write_bytes(canonical(handoff))
        variants = [
            lambda p:(p/'survey_context.json').write_text('{}'),
            lambda p:change(p, 'scenario_handoff.json', lambda d:d.update(schema_version='9.0')),
            lambda p:change(p, 'survey_context.json', lambda d:d.update(target_ip='192.0.2.99'), True),
            lambda p:change(p, 'survey_context.json', lambda d:d['observations'][0]['evidence_refs'][0].update(pointer='/absent'), True),
            lambda p:change(p, 'scenario_handoff.json', lambda d:d['artifacts'][0].update(file='../outside.json')),
            lambda p:change(p, 'survey_context.json', lambda d:next(f for f in d['observations'] if f['predicate']=='executors').update(status='observed'), True),
            lambda p:change(p, 'survey_context.json', lambda d:next(f for f in d['observations'] if f['predicate']=='module_access_and_forms').update(observed_at='2099-01-01T00:00:00Z'), True)]
        for i, mutation in enumerate(variants):
            path = self.base/str(i); shutil.copytree(BUNDLE, path); mutation(path)
            with self.subTest(i=i), self.assertRaises((ValueError, OSError)): load_bundle(path)

    def test_typed_placeholder_bindings_preserve_ip_scheme_port_and_path(self):
        envelope = self.envelope()
        record = catalog_fixture()['abilities'][0]['record']
        ex = copy.deepcopy(next(e for e in record['ability']['executors'] if e['platform'] == 'windows'))
        # Contract-only fixture, never inserted into catalog and never executed.
        ex['command'] = 'Inspect source placeholder contract #{target_ip} #{port} #{scheme} #{base_url}'
        ex['fact_placeholders'] = ['target_ip', 'port', 'scheme', 'base_url', 'unresolved_input']
        report = evaluate(record, ex, envelope, {'text': TEXT, 'objective': 'SQL injection'})
        self.assertEqual(report['bindings']['target_ip']['value'], '192.168.1.150')
        self.assertEqual(report['bindings']['port']['value'], '8080')
        self.assertEqual(report['bindings']['scheme']['value'], 'http')
        self.assertEqual(report['bindings']['base_url']['value'], 'http://192.168.1.150:8080/dvwa/')
        self.assertIsNone(report['bindings']['unresolved_input']['value'])
        self.assertTrue(any('unresolved_input' in b for b in report['blockers']))

    def test_session_conflict_and_missing_observations_remain_blockers(self):
        envelope = self.envelope()
        modules = [f for f in envelope['survey_context']['observations'] if f['predicate'] == 'module_access_and_forms']
        sqli = next(f for f in modules if f['subject'].endswith('/sqli/'))
        envelope['survey_context']['conflicts'].append({'observation_ids': [sqli['id']]})
        envelope['survey_context']['gaps'].append({'subject': 'web', 'reason': 'truncated', 'detail': 'fixture'})
        record = catalog_fixture()['abilities'][0]['record']
        ex = next(e for e in record['ability']['executors'] if e['platform'] == 'windows')
        assessment = evaluate(record, ex, envelope, {'text': TEXT, 'objective': 'SQL injection'})
        self.assertTrue(any('truncated' in b for b in assessment['blockers']))
        self.assertTrue(any('conflicting' in b for b in assessment['blockers']))
        sqli['value']['forms'][0]['action_path'] = '/different-observed-action'
        for f in envelope['survey_context']['observations']:
            if f['predicate'] == 'survey_session': f['value']['current_security_level'] = None
        assessment = evaluate(record, ex, envelope, {'text': TEXT, 'objective': 'SQL injection'})
        self.assertTrue(any('verify routing' in b for b in assessment['blockers']))
        self.assertTrue(any('security level required' in b for b in assessment['blockers']))
        envelope['survey_context']['observations'] = [f for f in envelope['survey_context']['observations'] if f['predicate'] != 'module_access_and_forms']
        assessment = evaluate(record, ex, envelope, {'text': TEXT, 'objective': 'SQL injection'})
        self.assertTrue(any('no observed form' in b for b in assessment['blockers']))
        self.assertFalse(any(f['predicate'] == 'manager_ingestion' for f in envelope['survey_context']['observations']))

    def test_gui_bridge_worker_api_share_loader_and_immutable_snapshot(self):
        import sys
        sys.path.insert(0, str(GUI))
        from engine import scenario_bridge as bridge
        from engine.scenario_worker import run_planning
        from engine.survey import load_config
        import app
        jobs = self.base/'jobs'; jobs.mkdir()
        body = {'survey_run_id': self.bundle['survey_context']['survey_run_id'], 'text': TEXT, 'scope': ['web'], 'max_steps': 4}
        with patch.object(bridge, 'OUTPUTS', jobs), patch.object(bridge, 'ACTIVE', None), patch.object(bridge.threading, 'Thread'):
            job = bridge.start(body, dict(load_config(), scenario_root=str(self.config.root)))
            folder = jobs/job['id']
            original = (folder/'input/input_manifest.json').read_bytes()
            with patch('scenario_agent.workflow.retrieve', side_effect=lambda *a: catalog_fixture()):
                state = run_planning(self.config.root, folder, llm=MockGeneration(), mode='keyword')
            self.assertEqual(state['status'], 'completed', state.get('validation_errors', state.get('error')))
            saved = bridge.read(folder/'job.json'); saved['status'] = state['status']; write_json(folder/'job.json', saved)
            handler = object.__new__(app.Handler); handler.path = '/api/scenarios/'+job['id']; captured = []
            handler.send = lambda value, *a, **kw: captured.append(value)
            handler.do_GET()
            self.assertEqual(captured[0]['input_source'], 'survey_v2')
            self.assertEqual(captured[0]['result']['evidence_validation'], 'schema_hash_pointer_and_typed_predicates')
            self.assertEqual(captured[0]['result']['steps'], 1)
            self.assertIn('step_evidence.json', captured[0]['files'])
            self.assertEqual(original, (folder/'input/input_manifest.json').read_bytes())
            self.assertTrue(bridge.checked_download(folder, 'input/survey/tool_04_inspect_dvwa_modules.json').is_file())
            for name in ('input/survey/../../config.json', '../config.json', 'worker.log'):
                with self.assertRaises(ValueError): bridge.checked_download(folder, name)
            with self.assertRaises(ValueError): bridge.start(body, dict(load_config(), scenario_root=str(self.config.root)))

    def test_archive_rejects_duplicate_symlink_traversal_and_bomb(self):
        for kind in ('traversal', 'duplicate', 'symlink', 'bomb'):
            path = self.base/(kind+'.zip')
            with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
                if kind == 'traversal': archive.writestr('../outside.json', '{}')
                elif kind == 'duplicate':
                    archive.writestr('a.json', '{}'); archive.writestr('a.json', '{}')
                elif kind == 'symlink':
                    info = zipfile.ZipInfo('link.json'); info.external_attr = (stat.S_IFLNK | 0o777) << 16; archive.writestr(info, '/etc/passwd')
                else: archive.writestr('huge.json', 'x'*8_000_001)
            with self.subTest(kind=kind), self.assertRaises(ValueError): load_bundle(path)
        path = self.base/'symlink-folder'; path.symlink_to(BUNDLE, target_is_directory=True)
        with self.assertRaises(ValueError): load_bundle(path)


if __name__ == '__main__': unittest.main()
