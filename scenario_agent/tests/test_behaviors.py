"""Natural-language behavior coverage regression; no network or commands executed."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from scenario_agent.behaviors import (validate_analysis, validate_grounding, grounding_payload,
    check_plan_coverage, parse_generation_schema)
from scenario_agent.catalog import ability, connect
from scenario_agent.config import Config,ROOT
from scenario_agent.models import validate_contract
from scenario_agent.rag import retrieve
from scenario_agent.workflow import Workflow,new_state
from scenario_agent.validation import validate_plan
from test_scenario_agent import fixture_request, fixture_plan, ABILITY

CLIP='b007fe0c-c6b0-4fda-915c-255bbc070de2'
PRINTER='5587e77f0c806e9d6f9c4fc5bd58a22f'
PROCESS='eca19cf8-2d3f-5d4b-aa6c-2092f913702c'

class BehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config=Config();cls.target=json.loads((ROOT/'input/target_profile.json').read_text())
        with connect(cls.config.catalog) as db:cls.records={i:ability(db,i) for i in (CLIP,PRINTER,PROCESS,ABILITY)}
    def setUp(self):
        self.text='Đọc clipboard rồi liệt kê máy in trên Windows.'
        self.analysis=validate_analysis({'ordered':True,'behaviors':[
            {'description':'Đọc clipboard','source_quote':'Đọc clipboard','query_en':'read clipboard contents','keywords':['clipboard']},
            {'description':'Liệt kê máy in','source_quote':'liệt kê máy in','query_en':'enumerate installed printers','keywords':['printer']}]},self.text)
        self.retrieval={'abilities':[{'record':r} for r in self.records.values()],'adversaries':[],
                        'behavior_candidates':{'B1':[CLIP,PROCESS],'B2':[PRINTER]}}
        self.response={'coverage':[
            {'behavior_id':'B1','reason':'Read command','matches':[{'ability_id':CLIP,'platform':'windows','executor':'psh','command_quote':'Get-Clipboard -raw'}]},
            {'behavior_id':'B2','reason':'Printer enumeration command','matches':[{'ability_id':PRINTER,'platform':'windows','executor':'psh','command_quote':'Get-Printer'}]}],
            'unmodeled_requirements':[]}
        self.coverage=validate_grounding(self.response,self.analysis,self.retrieval,self.target)
        self.plan={'metadata':{'steps':[{'ability_id':identifier,'executor':{'platform':'windows','name':'psh'}} for identifier in (CLIP,PRINTER)]}}

    def test_english_queries_find_both_intents_without_user_ids_or_techniques(self):
        result=retrieve(self.config,{'text':self.text,'objective':None,'requested_techniques':[],'max_tests':None,
            '_behavior_queries':self.analysis['behaviors']},self.target,'keyword')
        self.assertIn(CLIP,result['behavior_candidates']['B1'])
        self.assertIn(PRINTER,result['behavior_candidates']['B2'])

    def test_query_rewriting_generalizes_to_process_and_network_discovery(self):
        result=retrieve(self.config,{'text':'Xem tiến trình và cấu hình mạng','objective':None,'requested_techniques':[],'max_tests':None,
            '_behavior_queries':[{'id':'B1','query_en':'enumerate running processes','keywords':['process']},
                                 {'id':'B2','query_en':'network adapter configuration ipconfig','keywords':['adapter','ipconfig']}]},self.target,'keyword')
        records={a['record']['canonical_id']:a['record'] for a in result['abilities']}
        self.assertTrue(any('process' in records[i]['ability']['name'].lower() for i in result['behavior_candidates']['B1']))
        self.assertTrue(any('ipconfig' in str(records[i]['ability']['executors']).lower() or 'adapter' in str(records[i]['ability']['executors']).lower() for i in result['behavior_candidates']['B2']))

    def test_missing_or_invented_source_quote_is_rejected(self):
        bad={'ordered':False,'behaviors':[{'description':'extra task','source_quote':'not in user text','query_en':'do more','keywords':['extra']}]}
        with self.assertRaises(ValueError):validate_analysis(bad,self.text)

    def test_wrong_process_command_cannot_ground_clipboard_behavior(self):
        response=copy.deepcopy(self.response)
        response['coverage'][0]['matches'][0].update(ability_id=PROCESS,command_quote='Get-Process')
        with self.assertRaisesRegex(ValueError,'keyword'):validate_grounding(response,self.analysis,self.retrieval,self.target)

    def test_fabricated_command_quote_is_rejected(self):
        response=copy.deepcopy(self.response);response['coverage'][1]['matches'][0]['command_quote']='Get-Printer | invented-code'
        with self.assertRaisesRegex(ValueError,'literal'):validate_grounding(response,self.analysis,self.retrieval,self.target)

    def test_each_behavior_must_be_assessed(self):
        response=copy.deepcopy(self.response);response['coverage'].pop()
        with self.assertRaisesRegex(ValueError,'every behavior'):validate_grounding(response,self.analysis,self.retrieval,self.target)

    def test_plan_must_cover_each_behavior_using_the_reviewed_executor(self):
        self.assertTrue(check_plan_coverage(self.plan,self.coverage))
        for mutation in ('omit','executor','replace'):
            bad=copy.deepcopy(self.plan)
            if mutation=='omit':bad['metadata']['steps'].pop()
            elif mutation=='executor':bad['metadata']['steps'][1]['executor']['name']='cmd'
            else:bad['metadata']['steps'][0]['ability_id']=PROCESS
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):check_plan_coverage(bad,self.coverage)

    def test_plan_order_and_unrequested_extra_steps_are_rejected(self):
        bad=copy.deepcopy(self.plan);bad['metadata']['steps'].reverse()
        with self.assertRaisesRegex(ValueError,'order'):check_plan_coverage(bad,self.coverage)
        bad=copy.deepcopy(self.plan);bad['metadata']['steps'].append({'ability_id':PROCESS,'executor':{'platform':'windows','name':'psh'}})
        with self.assertRaisesRegex(ValueError,'unsupported'):check_plan_coverage(bad,self.coverage)

    def test_partial_coverage_stops_before_plan_generation(self):
        response=copy.deepcopy(self.response);response['coverage'][1]['matches']=[]
        llm=Mock();llm.generate.return_value=response
        with tempfile.TemporaryDirectory() as folder:
            config=Config();config.runs=Path(folder)
            state=new_state(config,self.text,ROOT/'input/target_profile.json','keyword')
            state.update(behavior_analysis=self.analysis,retrieval=self.retrieval)
            result=Workflow(config,llm).step('ground_behaviors',state)
            self.assertEqual(result['status'],'insufficient_coverage')
            self.assertEqual(result['next'],'END');self.assertEqual(result['plan_attempts'],0)
            self.assertEqual(result['uncovered_behaviors'],['Liệt kê máy in'])
            self.assertFalse((config.runs/result['run_folder']/'scenario_plan.yml').exists())
            self.assertEqual(llm.generate.call_count,1)

    def test_unmodeled_requirement_blocks_completion(self):
        bad=copy.deepcopy(self.coverage);bad['unmodeled_requirements']=['additional user task']
        with self.assertRaisesRegex(ValueError,'Unmodeled'):check_plan_coverage(self.plan,bad)

    def test_legacy_plan_without_semantic_coverage_is_not_certified(self):
        state=new_state(self.config,'Khảo sát người dùng',ROOT/'input/target_profile.json','keyword')
        request=fixture_request(state);request['requested_techniques']=[]
        with self.assertRaisesRegex(ValueError,'Missing behavior'):
            validate_plan(self.config,fixture_plan(state,self.records[ABILITY]),request,self.target,
                          {'abilities':[{'record':self.records[ABILITY]}],'adversaries':[]},state['plan_id'])

    def test_planning_context_drops_unrelated_profiles_but_preserves_adaptable_sources(self):
        from scenario_agent.behaviors import planning_view
        retrieval=copy.deepcopy(self.retrieval);retrieval['behavior_coverage']=self.coverage
        retrieval['adversaries']=[{'record':{'id':'unrelated','ordering':[PROCESS],'abilities':[]}},
            {'record':{'id':'adaptable','ordering':[CLIP,PROCESS,PRINTER],'abilities':[]}}]
        view=planning_view(retrieval)
        self.assertEqual({a['record']['canonical_id'] for a in view['abilities']},{CLIP,PRINTER})
        self.assertEqual([a['record']['id'] for a in view['adversaries']],['adaptable'])
        self.assertFalse(view['adversaries'][0]['record']['behavior_reuse_eligible'])
        self.assertEqual(retrieval['adversaries'][1]['record']['ordering'],[CLIP,PROCESS,PRINTER])

    def test_generation_contract_binds_source_tuple_and_grounded_ids(self):
        from scenario_agent.models import plan_generation_schema,api_schema,read_schema
        from scenario_agent.behaviors import planning_view
        from jsonschema import Draft202012Validator,ValidationError
        retrieval=copy.deepcopy(self.retrieval);retrieval['behavior_coverage']=self.coverage
        schema=api_schema(plan_generation_schema(read_schema(ROOT,'plan'),{'id':'plan','request_id':'request','target_id':'target'},planning_view(retrieval)))
        source=copy.deepcopy(self.records[PRINTER]['provenance'])
        validator=Draft202012Validator({'$defs':schema['$defs'],'$ref':'#/$defs/source'})
        validator.validate(source)
        source['kind']='caldera_ability' if source['kind']!='caldera_ability' else 'converted_atomic'
        with self.assertRaises(ValidationError):validator.validate(source)

    def test_source_reference_transport_expands_only_registered_catalog_facts(self):
        from scenario_agent.models import wire_source_contract,expand_source_references,plan_generation_schema,read_schema
        from scenario_agent.behaviors import planning_view
        retrieval=copy.deepcopy(self.retrieval);retrieval['behavior_coverage']=self.coverage
        view=planning_view(retrieval)
        schema=plan_generation_schema(read_schema(ROOT,'plan'),{'id':'plan','request_id':'request','target_id':'target'},view)
        before=copy.deepcopy(view)
        data,wire,mapping=wire_source_contract({'request':{},'retrieval':view},schema)
        self.assertEqual(wire['$defs']['source']['type'],'string')
        self.assertEqual(view,before)
        reference=next(k for k,v in mapping.items() if v==self.records[PRINTER]['provenance'])
        draft={'metadata':{'selection':{'sources':[reference]},'steps':[{'sources':[reference]}]}}
        full=expand_source_references(draft,mapping)
        self.assertEqual(full['metadata']['steps'][0]['sources'],[self.records[PRINTER]['provenance']])
        self.assertEqual(draft['metadata']['steps'][0]['sources'],[reference])
        draft['metadata']['steps'][0]['sources']=['unknown']
        with self.assertRaises(ValueError):expand_source_references(draft,mapping)

    def test_provider_sends_compact_sources_and_preserves_raw_response(self):
        from types import SimpleNamespace
        from scenario_agent.models import plan_generation_schema,read_schema,wire_source_contract
        from scenario_agent.llm import Gemini
        state=new_state(self.config,'Khảo sát người dùng',ROOT/'input/target_profile.json','keyword')
        retrieval={'abilities':[{'record':self.records[ABILITY]}],'adversaries':[]}
        schema=plan_generation_schema(read_schema(ROOT,'plan'),{'id':state['plan_id'],'request_id':state['request_id'],'target_id':self.target['id']},retrieval)
        _,_,mapping=wire_source_contract({'request':{},'retrieval':retrieval},schema)
        ref=next(iter(mapping));draft=fixture_plan(state,self.records[ABILITY])
        draft['metadata']['selection']['sources']=[ref];draft['metadata']['steps'][0]['sources']=[ref]
        llm=Gemini.__new__(Gemini);llm.model='gemini-3.5-flash-lite';llm.progress=False
        generate=Mock(return_value=SimpleNamespace(text=json.dumps(draft)))
        llm.client=SimpleNamespace(models=SimpleNamespace(generate_content=generate))
        full=llm.generate('plan',{'request':{},'retrieval':retrieval},schema)
        self.assertEqual(llm.last_wire_response,draft)
        self.assertEqual(full['metadata']['steps'][0]['sources'],[self.records[ABILITY]['provenance']])
        self.assertEqual(generate.call_args.kwargs['config']['response_json_schema']['$defs']['source']['type'],'string')

    def test_rejected_optional_alternative_does_not_discard_valid_evidence(self):
        response=copy.deepcopy(self.response);retrieval=copy.deepcopy(self.retrieval)
        retrieval['behavior_candidates']['B2'].append(PROCESS)
        response['coverage'][1]['matches'].append({'ability_id':PROCESS,'platform':'windows','executor':'psh','command_quote':'Get-Process'})
        coverage=validate_grounding(response,self.analysis,retrieval,self.target)
        self.assertEqual([m['ability_id'] for m in coverage['coverage'][1]['matches']],[PRINTER])
        self.assertEqual(coverage['rejected_matches'][0]['ability_id'],PROCESS)
        self.assertTrue(check_plan_coverage(self.plan,coverage))

    def test_manual_resume_of_insufficient_coverage_is_bounded_and_accepts_clarification(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            config=Config();config.runs=Path(folder)
            s=new_state(config,self.text,ROOT/'input/target_profile.json','keyword')
            s.update(status='insufficient_coverage',next='END',ground_attempts=2)
            flow=Workflow(config,Mock());flow.save(s)
            with patch.object(flow,'run',side_effect=lambda value:value):
                resumed=flow.resume(s['run_id'])
                self.assertEqual(resumed['next'],'ground_behaviors');self.assertEqual(resumed['ground_attempts'],0)
                clarified=flow.resume(s['run_id'],'Chỉ đọc clipboard.')
                self.assertEqual(clarified['next'],'parse');self.assertIn('Chỉ đọc clipboard.',clarified['text'])

    def test_finalization_clears_stale_pending_state(self):
        from evaluation.fixtures import coverage_fixture
        with tempfile.TemporaryDirectory() as folder:
            config=Config();config.runs=Path(folder)
            s=new_state(config,'Khảo sát người dùng Windows',ROOT/'input/target_profile.json','keyword')
            request=fixture_request(s)
            s.update(plan=fixture_plan(s,self.records[ABILITY]),request=request,
                     retrieval={'abilities':[{'record':self.records[ABILITY]}],'adversaries':[],
                                'behavior_coverage':coverage_fixture(request,[self.records[ABILITY]],self.target)},
                     uncovered_behaviors=['old'],questions=['old'],resume_phase='ground_behaviors')
            result=Workflow(config,Mock()).step('finalize',s)
            self.assertEqual(result['status'],'completed')
            for key in ('uncovered_behaviors','questions','resume_phase'):self.assertNotIn(key,result)
