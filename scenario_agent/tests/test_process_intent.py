"""Offline regression of parent-child retrieval and ASCII Vietnamese grounding."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scenario_agent.behaviors import validate_analysis, validate_grounding, GroundingValidationError
from scenario_agent.intent_evidence import process_requirement, process_evidence
from scenario_agent.catalog import ability, connect
from scenario_agent.config import Config, ROOT
from scenario_agent.rag import retrieve
from scenario_agent.workflow import Workflow, new_state

CMD = '55678719-e76e-4df9-92aa-10655bbd1cf4'
TEXT = 'Kiem tra ghi nhan tien trinh powershell sinh tien trinh cmd doc hai'


def analysis(text=TEXT):
    return validate_analysis({'ordered':False,'behaviors':[{
        'description':'Tiến trình PowerShell sinh tiến trình cmd','source_quote':text,
        'query_en':'powershell spawning cmd','keywords':['powershell','cmd','process']}]}, text)


class ProcessIntentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config=Config()
        cls.target=json.loads((ROOT/'input/target_profile.json').read_text())
        with connect(cls.config.catalog) as db:cls.cmd=ability(db,CMD)

    def retrieval(self):
        return {'abilities':[{'record':self.cmd}],'adversaries':[], 'behavior_candidates':{'B1':[CMD]}}

    def response(self):
        return {'coverage':[{'behavior_id':'B1','reason':'Literal cmd launcher in psh source',
            'matches':[{'ability_id':CMD,'platform':'windows','executor':'psh',
            'command_quote':self.cmd['ability']['executors'][0]['command'].splitlines()[0]}]}],
            'unmodeled_requirements':[]}

    def test_ascii_accented_and_direction(self):
        for quote in (TEXT,'PowerShell sinh tiến trình cmd','powershell.exe spawns cmd.exe'):
            self.assertEqual(process_requirement({'source_quote':quote}),{'parent':'powershell','child':'cmd'})
        self.assertEqual(process_requirement({'source_quote':'cmd spawns powershell'}),{'parent':'cmd','child':'powershell'})
        self.assertIsNone(process_requirement({'source_quote':'PowerShell và cmd'}))

    def test_real_catalog_command_retrieved_without_rebuilding_index(self):
        result=retrieve(self.config,{'text':TEXT,'objective':None,'requested_techniques':[],
            '_behavior_queries':analysis()['behaviors']},self.target,'keyword')
        self.assertIn(CMD,result['behavior_candidates']['B1'])
        self.assertTrue(any(x['ability_id']==CMD for x in result['intent_candidates']['B1']))
        self.assertLessEqual(len(result['behavior_candidates']['B1']),6)

    def test_real_source_relation_is_static_evidence(self):
        result=validate_grounding(self.response(),analysis(),self.retrieval(),self.target)
        proof=result['coverage'][0]['matches'][0]['evidence_match']['intent_evidence']
        self.assertEqual(proof['child'],'cmd');self.assertFalse(proof['execution_observed'])

    def test_print_comment_assignment_other_child_and_wrong_executor_abstain(self):
        relation={'parent':'powershell','child':'cmd'}
        for command in ('Write-Host "cmd.exe /c test"', '# cmd.exe /c test',
                        '$x = "cmd.exe /c test"', 'Start-Process calc.exe',
                        'powershell.exe -Command "cmd.exe /c test"', '@"\ncmd.exe /c test\n"@'):
            self.assertIsNone(process_evidence(command,'psh',relation),command)
        self.assertIsNone(process_evidence('cmd.exe /c test','cmd',relation))
        self.assertIsNotNone(process_evidence('Start-Process -FilePath "cmd.exe"','psh',relation))

    def test_quote_inside_printed_string_cannot_certify_parent_child(self):
        retrieval=copy.deepcopy(self.retrieval())
        retrieval['abilities'][0]['record']['ability']['executors'][0]['command']='Write-Host "cmd.exe /c test"'
        response=self.response();response['coverage'][0]['matches'][0]['command_quote']='cmd.exe /c test'
        with self.assertRaisesRegex(ValueError,'parent/child'):
            validate_grounding(response,analysis(),retrieval,self.target)

    def test_english_query_supports_unaccented_vietnamese_file_modification(self):
        identifier='bdc2a80d621d3361ea727008644b1d15'
        with connect(self.config.catalog) as db:record=ability(db,identifier)
        a=validate_analysis({'ordered':False,'behaviors':[{'description':'Hành vi sửa file',
            'source_quote':'hanh vi tao , xoa , sua file','query_en':'file modification','keywords':['sua','file']}]},
            'hanh vi tao , xoa , sua file')
        r={'abilities':[{'record':record}],'adversaries':[],'behavior_candidates':{'B1':[identifier]}}
        response={'coverage':[{'behavior_id':'B1','reason':'Static evidence only, full ability scope requires separate review',
            'matches':[{'ability_id':identifier,'platform':'windows','executor':'psh',
            'command_quote':'Add-Content -Path $_.FullName -Value "Modification for Atomic Red Test" -ErrorAction Ignore'}]}],
            'unmodeled_requirements':[]}
        self.assertEqual(len(validate_grounding(response,a,r,self.target)['coverage'][0]['matches']),1)

    def test_partial_validation_retains_valid_rows_and_updates_counts(self):
        a=analysis();second=copy.deepcopy(a['behaviors'][0]);second.update(id='B2',description='Reverse relation',
            source_quote='cmd spawns powershell',query_en='cmd spawning powershell')
        a['behaviors'].append(second)
        r=self.retrieval();r['behavior_candidates']['B2']=[CMD]
        response=self.response();row=copy.deepcopy(response['coverage'][0]);row['behavior_id']='B2';response['coverage'].append(row)
        with self.assertRaises(GroundingValidationError) as error:
            validate_grounding(response,a,r,self.target)
        self.assertEqual([len(row['matches']) for row in error.exception.partial_coverage['coverage']],[1,0])
        with tempfile.TemporaryDirectory() as folder:
            config=Config();config.runs=Path(folder)
            state=new_state(config,TEXT,ROOT/'input/target_profile.json','keyword')
            state.update(behavior_analysis=a,retrieval=r,ground_attempts=1,coverage_summary={'required':99,'supported':99})
            llm=Mock();llm.generate.return_value=response
            result=Workflow(config,llm).step('ground_behaviors',state)
            self.assertEqual(result['coverage_summary'],{'required':2,'supported':1})
            self.assertEqual(result['uncovered_behaviors'],['Reverse relation'])
            self.assertEqual(result['plan_attempts'],0)
            self.assertEqual(result['grounding_diagnostics']['status'],'invalid_grounding')

    def test_resume_old_retrieval_refreshes_candidates(self):
        with tempfile.TemporaryDirectory() as folder:
            config=Config();config.runs=Path(folder)
            state=new_state(config,TEXT,ROOT/'input/target_profile.json','keyword')
            state.update(status='insufficient_coverage',next='END',behavior_analysis=analysis(),retrieval=self.retrieval())
            flow=Workflow(config,Mock());flow.save(state)
            with patch.object(flow,'run',side_effect=lambda s:s):
                self.assertEqual(flow.resume(state['run_id'])['next'],'retrieve')

    def test_reparse_clears_old_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            config=Config();config.runs=Path(folder)
            state=new_state(config,TEXT,ROOT/'input/target_profile.json','keyword')
            state.update(coverage_summary={'required':1,'supported':0},uncovered_behaviors=['old'],retrieval={'old':True})
            llm=Mock();llm.generate.return_value={'internal_behavior_analysis':{'behaviors':[],'ordered':False}}
            state=Workflow(config,llm).step('parse',state)
            for key in ('coverage_summary','uncovered_behaviors','retrieval'):self.assertNotIn(key,state)

if __name__=='__main__':unittest.main()
