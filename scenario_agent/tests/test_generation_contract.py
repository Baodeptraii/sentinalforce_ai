"""Reject the identifier/objective mistakes seen in live Gemini responses."""
import copy
import unittest
from unittest.mock import Mock
from jsonschema import Draft202012Validator, ValidationError

from scenario_agent.catalog import ability, connect
from scenario_agent.config import Config, ROOT
from scenario_agent.models import read_schema, api_schema, plan_generation_schema
from scenario_agent.validation import validate_plan
from scenario_agent.workflow import Workflow, new_state
from test_scenario_agent import ABILITY, fixture_request, fixture_plan


class GenerationContractTests(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.state = new_state(self.config, 'Khảo sát người dùng Windows endpoint T1033, tối đa 1 test.',
                               ROOT / 'input/target_profile.json', 'keyword')
        with connect(self.config.catalog) as db:
            self.record = ability(db, ABILITY)
        self.context = {'id': self.state['plan_id'], 'request_id': self.state['request_id'],
                        'target_id': self.state['target']['id']}
        self.source = read_schema(ROOT, 'plan')
        self.plan = fixture_plan(self.state, self.record)
        self.validator = Draft202012Validator(api_schema(plan_generation_schema(self.source, self.context)))

    def test_response_contract_rejects_source_id_in_any_app_identifier(self):
        self.validator.validate(self.plan)
        for path in (('id',), ('metadata', 'request_id'), ('metadata', 'target_id')):
            bad = copy.deepcopy(self.plan)
            node = bad
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = 'd6ea4c1e-7959-4eb1-a292-b6fd2b06c73e'
            with self.subTest(path=path), self.assertRaises(ValidationError):
                self.validator.validate(bad)

    def test_response_contract_rejects_root_objective_but_retains_metadata_goal(self):
        bad = copy.deepcopy(self.plan)
        bad['objective'] = 'Khảo sát người dùng T1033'
        with self.assertRaises(ValidationError):
            self.validator.validate(bad)
        self.validator.validate(self.plan)
        self.assertIn('goal', self.plan['metadata'])

    def test_source_contract_and_validator_remain_independent(self):
        before = copy.deepcopy(self.source)
        plan_generation_schema(self.source, self.context)
        self.assertEqual(self.source, before)
        self.assertIn('objective', self.source['properties'])
        retrieval = {'abilities': [{'record': self.record}], 'adversaries': []}
        bad = copy.deepcopy(self.plan); bad['id'] = 'source-adversary-id'
        with self.assertRaisesRegex(ValueError, 'identifiers changed'):
            validate_plan(self.config, bad, fixture_request(self.state), self.state['target'],
                          retrieval, self.state['plan_id'])
        bad = copy.deepcopy(self.plan); bad['objective'] = 'fake-objective'
        with self.assertRaisesRegex(ValueError, 'objective catalog'):
            validate_plan(self.config, bad, fixture_request(self.state), self.state['target'],
                          retrieval, self.state['plan_id'])

    def test_workflow_sends_bound_contract_and_keeps_raw_response(self):
        llm = Mock(); llm.generate.return_value = copy.deepcopy(self.plan)
        self.state.update(request=fixture_request(self.state),
                          retrieval={'abilities': [{'record': self.record}], 'adversaries': []})
        Workflow(self.config, llm).node_build_plan(self.state)
        instruction, payload, schema = llm.generate.call_args.args
        bound = Draft202012Validator(api_schema(schema))
        bound.validate(self.plan)
        bad = copy.deepcopy(self.plan); bad['id'] = 'source-adversary-id'
        with self.assertRaises(ValidationError):
            bound.validate(bad)
        self.assertNotIn('objective', schema['properties'])
        self.assertEqual(payload['app_context'], self.context)
        self.assertEqual(self.state['raw_plan'], llm.generate.return_value)


if __name__ == '__main__':
    unittest.main()
