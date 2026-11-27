"""Regression checks for unsupported verification, guessed privilege and exact technique coverage."""
import copy
import unittest
from jsonschema import Draft202012Validator, ValidationError
from scenario_agent.catalog import ability, connect, technique_abilities
from scenario_agent.config import Config, ROOT
from scenario_agent.models import read_schema, plan_generation_schema, api_schema
from scenario_agent.rag import retrieve
from scenario_agent.workflow import new_state
from test_scenario_agent import ABILITY, fixture_plan

SYSTEM = '1324aaa7-be78-5e70-8434-ab514ca75915'

class CatalogGroundingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config=Config()
        cls.state=new_state(cls.config,'Tôi muốn tạo kịch bản. Bổ sung: xác định người dùng T1033 trên endpoint Windows, tối đa 1 test.',ROOT/'input/target_profile.json','keyword')
        cls.target=cls.state['target']
        with connect(cls.config.catalog) as db:
            cls.user=ability(db,ABILITY)
            cls.system=ability(db,SYSTEM)

    def bound(self, records):
        context={'id':self.state['plan_id'],'request_id':self.state['request_id'],'target_id':self.target['id']}
        schema=plan_generation_schema(read_schema(ROOT,'plan'),context,
            {'abilities':[{'record':a} for a in records],'adversaries':[]})
        return Draft202012Validator(api_schema(schema))

    def test_generation_rejects_verified_prerequisite_and_telemetry(self):
        validator=self.bound([self.user]);plan=fixture_plan(self.state,self.user)
        validator.validate(plan)
        prerequisite=copy.deepcopy(plan)
        prerequisite['metadata']['steps'][0]['prerequisites'][0].update(status='verified',evidence='PowerShell version reported in target profile')
        telemetry=copy.deepcopy(plan)
        telemetry['metadata']['steps'][0]['expected_telemetry'][0]['availability']='verified'
        for bad in (prerequisite,telemetry):
            with self.assertRaises(ValidationError):validator.validate(bad)

    def test_privilege_is_bound_to_ability_even_when_known_and_unknown_are_mixed(self):
        known=copy.deepcopy(self.user)
        known['canonical_id']='11111111-1111-4111-8111-111111111111'
        known['ability']['privilege']='User'
        validator=self.bound([self.user,known]);plan=fixture_plan(self.state,self.user)
        validator.validate(plan)
        unknown_bad=copy.deepcopy(plan)
        unknown_bad['metadata']['steps'][0]['executor']['privilege']='User'
        with self.assertRaises(ValidationError):validator.validate(unknown_bad)
        known_plan=copy.deepcopy(plan)
        known_plan['atomic_ordering']=[known['canonical_id']]
        known_plan['metadata']['steps'][0].update(ability_id=known['canonical_id'])
        known_plan['metadata']['steps'][0]['executor']['privilege']='User'
        validator.validate(known_plan)
        known_plan['metadata']['steps'][0]['executor']['privilege']=None
        with self.assertRaises(ValidationError):validator.validate(known_plan)

    def test_generation_constraints_preserve_source_schema_and_records(self):
        source=read_schema(ROOT,'plan');before=copy.deepcopy(source)
        records={'abilities':[{'record':self.user}],'adversaries':[]};saved=copy.deepcopy(records)
        plan_generation_schema(source,{'id':'plan','request_id':'request','target_id':'target'},records)
        self.assertEqual(source,before);self.assertEqual(records,saved)
        self.assertIn('verified',source['$defs']['check']['properties']['status']['enum'])

    def test_exact_sql_technique_lookup_enforces_target_and_direction(self):
        with connect(self.config.catalog) as db:
            result=technique_abilities(db,['T1033'],self.target)
            self.assertIn(ABILITY,result['T1033'])
            unknown=copy.deepcopy(self.target);unknown['os']['name']='unsupported'
            self.assertEqual(technique_abilities(db,['T1033'],unknown),{'T1033':{}})
            no_cmd=copy.deepcopy(self.target);no_cmd['capabilities']['cmd_ready']=False
            self.assertNotIn(ABILITY,technique_abilities(db,['T1033'],no_cmd)['T1033'])
            parent=technique_abilities(db,['T1059'],self.target)['T1059']
            self.assertTrue(any(r['ability']['technique_id'].startswith('T1059.') for r in parent.values()))
            child=technique_abilities(db,['T1059.001'],self.target)['T1059.001']
            self.assertTrue(child)
            self.assertTrue(all(r['ability']['technique_id']=='T1059.001' for r in child.values()))

    def test_clarified_request_pins_T1033_despite_distracting_text(self):
        result=retrieve(self.config,{'text':self.state['text']+' kịch bản hệ thống PowerShell Windows SOC',
            'objective':'khảo sát người dùng','requested_techniques':['T1033'],'max_tests':1},self.target,'keyword',1)
        self.assertEqual(len(result['abilities']),1)
        self.assertEqual(result['abilities'][0]['record']['ability']['technique_id'],'T1033')
        self.assertIn(ABILITY,result['technique_lookup']['eligible_ids']['T1033'])
        self.assertEqual(result['technique_lookup']['missing_compatible'],[])

    def test_each_requested_technique_has_an_anchor_even_with_small_retrieval_budget(self):
        result=retrieve(self.config,{'text':'Windows endpoint discovery','objective':None,
            'requested_techniques':['T1033','T1082'],'max_tests':None},self.target,'keyword',1)
        covered={x['record']['ability']['technique_id'] for x in result['abilities']}
        self.assertTrue({'T1033','T1082'}<=covered)

    def test_missing_technique_is_reported_without_fabricated_ability(self):
        result=retrieve(self.config,{'text':'Windows T9999','objective':None,
            'requested_techniques':['T9999'],'max_tests':1},self.target,'keyword',2)
        self.assertEqual(result['technique_lookup']['missing_compatible'],['T9999'])
        self.assertEqual(result['technique_lookup']['eligible_ids']['T9999'],[])
        self.assertFalse(any(x['record']['ability'].get('technique_id')=='T9999' for x in result['abilities']))

if __name__=='__main__':unittest.main()
