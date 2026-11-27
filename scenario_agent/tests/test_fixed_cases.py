"""Deterministic fixed-case planning: the five demo cases build first-class
ScenarioPlans through the unchanged validators, with no LLM involved."""
import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yaml

from scenario_agent.config import Config, write_json
from scenario_agent.fixed_cases import CASES, CASE_ORDER, FixedWorkflow
from scenario_agent.survey_input import load_bundle, planning_target, policy_for, snapshot, verify_snapshot
from scenario_agent.models import validate_contract
from tests.test_context_requirements import fixture_snapshot  # noqa: E402  (tests use implicit sys.path)


class FixedCasePlanningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # The fixed sources are pinned to the lab host, so the synthetic
        # fixture must observe the same IP/port or the fixed-host check would
        # (correctly) mark them incompatible with an unrelated target.
        self.bundle_path = fixture_snapshot(self.root, ip='192.168.1.150', port=8080)
        self.bundle = load_bundle(self.bundle_path)
        self.target = planning_target(self.bundle)

    def build(self, case_id):
        case = CASES[case_id]
        policy = policy_for(self.target, case['scope'], max(8, len(case['chain'])))
        folder = self.root / ('job-' + case_id)
        folder.mkdir()
        snapshot(self.bundle, folder / 'input', {'text': case['request_text']}, policy)
        write_json(folder / 'policy.json', policy)
        write_json(folder / 'request.json', {'text': case['request_text'], 'scope': case['scope'],
                                             'max_steps': policy['max_steps'], 'input_kind': 'survey_v2',
                                             'fixed_case': case_id})
        write_json(folder / 'fixed_case.json', {'case_id': case_id, 'spec_version': 1})
        config = Config(Path(__file__).resolve().parents[1])
        config.runs = folder / 'runs'
        workflow = FixedWorkflow(config, case_id)
        from scenario_agent.workflow import new_state
        state = new_state(config, case['request_text'], folder / 'input/survey', 'hybrid', policy=policy)
        state = workflow.run(state)
        return workflow, state, policy

    def test_all_cases_complete_without_llm(self):
        for case_id in CASE_ORDER:
            workflow, state, policy = self.build(case_id)
            self.assertEqual(state['status'], 'completed', case_id + ': ' + str(state.get('error')))
            case = CASES[case_id]
            self.assertEqual(state['next'], 'END')
            self.assertEqual(state['plan']['atomic_ordering'], case['chain'])
            self.assertEqual(state['plan']['metadata']['readiness'], 'needs_information')
            self.assertEqual(len(state['plan']['metadata']['steps']), len(case['chain']))
            # The plan artifact on disk is a valid contract and matches the state.
            plan = yaml.safe_load((workflow.run_directory(state) / 'scenario_plan.yml').read_text())
            validate_contract(Config(Path(__file__).resolve().parents[1]).root, 'plan', plan)
            self.assertEqual(plan, state['plan'])
            for report in ('validation_report.json', 'step_evidence.json', 'compatibility_report.json',
                           'context_selection.json', 'behavior_coverage.json'):
                self.assertTrue((workflow.run_directory(state) / report).is_file(), case_id + ':' + report)
            for step in plan['metadata']['steps']:
                self.assertEqual(step['parameters'], {})
                self.assertEqual(step['role'], 'test')
                self.assertTrue(step['behavior_verification'])
                self.assertTrue(step['prerequisites'])

    def test_plan_is_not_ready_for_review(self):
        _, state, _ = self.build('EP-02')
        self.assertNotEqual(state['plan']['metadata']['readiness'], 'ready_for_review')
        self.assertTrue(state['plan']['metadata']['blockers'])

    def test_fixed_case_marker_is_required_for_planner_choice(self):
        # The worker (GUI side) only selects FixedWorkflow when fixed_case.json
        # exists; here we assert the planner raises on unknown case ids.
        config = Config(Path(__file__).resolve().parents[1])
        with self.assertRaises(ValueError):
            FixedWorkflow(config, 'EP-99')


if __name__ == '__main__':
    unittest.main()
