import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from scenario_agent.config import Config, ROOT, write_json
from scenario_agent.run_storage import folder_name, load_run, rename_run, save_state
from scenario_agent.workflow import Workflow, new_state

RUN_ID='af421588-b6ce-4661-853c-29e3f409a44a'
TEXT='Khảo sát thông tin người dùng Windows trên endpoint để đánh giá SOC, tối đa 1 test.'
TIME='2026-11-11T15:30:00+07:00'
NAME='20261111_153000_khao-sat-nguoi-dung-windows_af421588'

class RunStorageTests(unittest.TestCase):
    def test_new_runs_receive_readable_stable_names(self):
        self.assertEqual(folder_name(TEXT,RUN_ID,TIME),NAME)
        state=new_state(Config(),TEXT,ROOT/'input/target_profile.json','keyword')
        self.assertIn('created_at',state)
        self.assertRegex(state['run_folder'],r'^\d{8}_\d{6}_khao-sat-nguoi-dung-windows_[0-9a-f]{8}$')

    def test_lookup_new_folder_by_uuid_or_name(self):
        with tempfile.TemporaryDirectory() as d:
            state={'run_id':RUN_ID,'run_folder':NAME}
            directory=save_state(Path(d),state)
            for key in (RUN_ID,NAME):
                found,path=load_run(Path(d),key)
                self.assertEqual(path,directory)
                self.assertEqual(found['run_id'],RUN_ID)

    def test_legacy_uuid_lookup_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            state={'run_id':RUN_ID,'status':'error'}
            write_json(Path(d)/RUN_ID/'state.json',state)
            found,path=load_run(Path(d),RUN_ID)
            self.assertEqual(found['run_folder'],RUN_ID)
            self.assertEqual(path.name,RUN_ID)

    def test_migration_preserves_files_and_updates_output(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);old=root/RUN_ID;old.mkdir()
            plan=b'id: example\nname: untouched\n'
            (old/'scenario_plan.yml').write_bytes(plan)
            state={'run_id':RUN_ID,'created_at':TIME,'status':'completed','text':TEXT,
                   'output':str(old/'scenario_plan.yml')}
            write_json(old/'state.json',state)
            result=rename_run(root,RUN_ID)
            self.assertEqual(result['run_folder'],NAME)
            self.assertFalse(old.exists())
            self.assertEqual((root/NAME/'scenario_plan.yml').read_bytes(),plan)
            found,_=load_run(root,RUN_ID)
            self.assertEqual(found['output'],str(root/NAME/'scenario_plan.yml'))
            self.assertEqual(found['run_id'],RUN_ID)
            self.assertFalse(rename_run(root,RUN_ID)['renamed'])

    def test_migration_uses_earliest_artifact_time(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);old=root/RUN_ID;old.mkdir()
            write_json(old/'state.json',{'run_id':RUN_ID,'status':'completed','text':TEXT})
            write_json(old/'user_request.json',{})
            early=datetime(2026,11,11,8,30,tzinfo=timezone.utc).timestamp()
            os.utime(old/'user_request.json',(early,early))
            os.utime(old/'state.json',(early+300,early+300))
            self.assertEqual(rename_run(root,RUN_ID)['run_folder'],NAME)

    def test_short_uuid_collision_keeps_both_checkpoints(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            first={'run_id':RUN_ID,'run_folder':NAME}
            save_state(root,first)
            second={'run_id':'af421588-0000-4000-8000-000000000001','run_folder':NAME}
            save_state(root,second)
            self.assertNotEqual(first['run_folder'],second['run_folder'])
            self.assertEqual(load_run(root,RUN_ID)[0]['run_id'],RUN_ID)
            self.assertEqual(load_run(root,second['run_id'])[0]['run_id'],second['run_id'])

    def test_invalid_paths_and_ambiguous_uuid_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for key in ('../outside','/tmp/outside','a/b','a\\b','..'):
                with self.subTest(key=key),self.assertRaises(ValueError):load_run(root,key)
            save_state(root,{'run_id':RUN_ID,'run_folder':NAME})
            second=NAME.replace('khao-sat','kiem-tra')
            save_state(root,{'run_id':RUN_ID,'run_folder':second})
            with self.assertRaises(ValueError):load_run(root,RUN_ID)
            self.assertEqual(load_run(root,NAME)[0]['run_id'],RUN_ID)

    def test_active_run_is_not_renamed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            write_json(root/RUN_ID/'state.json',{'run_id':RUN_ID,'status':'running','text':TEXT})
            with self.assertRaises(ValueError):rename_run(root,RUN_ID)
            self.assertTrue((root/RUN_ID/'state.json').exists())

    def semantic_state(self):
        return {'run_id':RUN_ID,'created_at':TIME,'status':'completed',
                'text':'Tôi muốn kiểm tra hệ thống SOC có ghi nhận được hành vi command injection trên DVWA.',
                'target':{'services':[{'name':'DVWA','url':'http://lab/dvwa/'}]},
                'behavior_analysis':{'behaviors':[{'description':'Thử khai thác lỗi command injection trên ứng dụng DVWA'}]}}

    def test_goal_label_uses_actions_and_application_context(self):
        from scenario_agent.run_storage import scenario_label
        self.assertEqual(scenario_label(self.semantic_state()),'dvwa-command-injection')
        state=self.semantic_state();state['target']={}
        state['behavior_analysis']['behaviors']=[{'description':'Đọc nội dung clipboard trên endpoint Windows'},
            {'description':'Liệt kê các máy in đã cài đặt trên endpoint Windows'}]
        self.assertEqual(scenario_label(state),'doc-clipboard-liet-ke-may-in')

    def test_label_does_not_trust_generated_plan_title(self):
        from scenario_agent.run_storage import scenario_label
        state=self.semantic_state();state['plan']={'name':'completely unrelated title'}
        self.assertEqual(scenario_label(state),'dvwa-command-injection')

    def test_auto_name_refinement_keeps_old_folder_lookup_and_then_stays_stable(self):
        from scenario_agent.run_storage import name_from_behaviors
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);state=self.semantic_state();state.update(status='running',run_folder=NAME)
            original=save_state(root,state)
            (original/'user_request.json').write_text('preserve exact bytes')
            name_from_behaviors(root,state)
            self.assertEqual(state['run_folder'],'20261111_153000_dvwa-command-injection_af421588')
            self.assertEqual(load_run(root,NAME)[0]['run_id'],RUN_ID)
            self.assertEqual((root/state['run_folder']/'user_request.json').read_text(),'preserve exact bytes')
            first=state['run_folder'];state['behavior_analysis']['behaviors'][0]['description']='XSS trên DVWA'
            name_from_behaviors(root,state)
            self.assertEqual(state['run_folder'],first)

    def test_refresh_updates_existing_readable_name_and_output_without_touching_plan(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);state=self.semantic_state();state.update(run_folder=NAME,output=str(root/NAME/'scenario_plan.yml'))
            directory=save_state(root,state);plan=b'id: unchanged\n'
            (directory/'scenario_plan.yml').write_bytes(plan)
            result=rename_run(root,RUN_ID,refresh_goal=True)
            self.assertTrue(result['renamed']);self.assertFalse(directory.exists())
            updated,_=load_run(root,NAME)
            self.assertEqual(updated['run_id'],RUN_ID)
            self.assertEqual(Path(updated['output']).read_bytes(),plan)
            self.assertFalse(rename_run(root,NAME,refresh_goal=True)['renamed'])

    def test_refinement_collision_preserves_other_uuid(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);state=self.semantic_state();state['run_folder']=NAME;save_state(root,state)
            destination='20261111_153000_dvwa-command-injection_af421588'
            other={'run_id':'af421588-0000-4000-8000-000000000001','run_folder':destination}
            save_state(root,other)
            result=rename_run(root,RUN_ID,refresh_goal=True)
            self.assertTrue(result['run_folder'].endswith(RUN_ID))
            self.assertEqual(load_run(root,other['run_id'])[0]['run_id'],other['run_id'])

    def test_failed_rename_rolls_back_folder_and_checkpoint(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);state=self.semantic_state();state['run_folder']=NAME
            directory=save_state(root,state);before=(directory/'state.json').read_bytes()
            with patch('scenario_agent.run_storage.write_json',side_effect=OSError('controlled failure')):
                with self.assertRaises(OSError):rename_run(root,RUN_ID,refresh_goal=True)
            self.assertTrue(directory.is_dir());self.assertEqual((directory/'state.json').read_bytes(),before)

    def test_ambiguous_old_folder_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for suffix,identifier in [('one',RUN_ID),('two','11111111-1111-4111-8111-111111111111')]:
                save_state(root,{'run_id':identifier,'run_folder':suffix,'run_folder_aliases':['old-name']})
            with self.assertRaises(ValueError):load_run(root,'old-name')

if __name__=='__main__':unittest.main()
