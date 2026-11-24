"""Bridge input validation happens before launching a Scenario worker."""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import scenario_bridge as bridge
from engine.survey import load_config

RUNTIME = Path('scenario_agent')
GUI = Path(__file__).resolve().parents[1]
BUNDLE = GUI/'review/survey-v2-8722'


@unittest.skipUnless((RUNTIME/'scenario_agent/survey_input.py').is_file() and BUNDLE.is_dir(), 'Runtime/sample unavailable')
class ScenarioInputBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); (self.root/'scenario_outputs').mkdir()
        self.identifier = 'a'*32
        self.run = self.root/'outputs'/self.identifier
        self.run.mkdir(parents=True)
        shutil.copytree(BUNDLE, self.run/'survey_v2')
        self.config = dict(load_config(), scenario_root=str(RUNTIME))
        self.data = {'survey_run_id': self.identifier, 'text': 'SQL injection', 'scope': ['web'], 'max_steps': 4}
        self.patches = [patch.object(bridge, 'ROOT', self.root), patch.object(bridge, 'OUTPUTS', self.root/'scenario_outputs'), patch.object(bridge, 'ACTIVE', None)]
        for p in self.patches: p.start(); self.addCleanup(p.stop)

    def test_invalid_bundle_is_not_downgraded_to_profile_only(self):
        (self.run/'survey_v2/survey_context.json').write_text('{}')
        with patch.object(bridge.threading, 'Thread') as thread, self.assertRaises(ValueError): bridge.start(self.data, self.config)
        thread.assert_not_called()
        self.assertEqual(list((self.root/'scenario_outputs').iterdir()), [])

    def test_run_traversal_and_scope_expansion_rejected_before_worker(self):
        for identifier in ('../review', '/etc', 'https://example.invalid'):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError): bridge.start(dict(self.data, survey_run_id=identifier), self.config)
        with patch.object(bridge.threading, 'Thread') as thread, self.assertRaises(ValueError):
            bridge.start(dict(self.data, scope=['web','invalid']), self.config)
        thread.assert_not_called()

    def test_legacy_profile_keeps_explicit_limited_mode(self):
        profile = json.loads((BUNDLE/'target_profile.json').read_text())
        body = {k:v for k,v in self.data.items() if k!='survey_run_id'} | {'profile': profile}
        with patch.object(bridge.threading, 'Thread'):
            identifier = bridge.start(body, self.config)['id']
        folder = bridge.directory(identifier)
        self.assertEqual(bridge.read(folder/'provenance.json')['source'], 'profile_only')
        self.assertFalse((folder/'input').exists())
        self.assertFalse(bridge.read(folder/'policy.json')['execution_authorized'])

    def test_historical_effective_request_includes_saved_clarification_without_writes(self):
        folder=bridge.directory('b'*32);run=folder/'runs'/'recorded';run.mkdir(parents=True)
        job={'id':'b'*32,'status':'insufficient_coverage'}
        result={'run_id':'recorded-run','uncovered_behaviors':['PowerShell sinh cmd']}
        state={'run_id':'recorded-run','text':'PowerShell sinh cmd\nBổ sung của người dùng: sua file',
               'behavior_analysis':{'behaviors':[{'id':'B1','description':'Sửa file','source_quote':'sua file'}]}}
        for name,value in [('job.json',job),('result.json',result),('runs/recorded/state.json',state)]:
            (folder/name).write_text(json.dumps(value))
        before={str(p):p.read_bytes() for p in folder.rglob('*.json')}
        public=bridge.public('b'*32)
        self.assertEqual(public['result']['effective_request_text'],state['text'])
        self.assertEqual(public['result']['analyzed_behaviors'],state['behavior_analysis']['behaviors'])
        self.assertEqual({str(p):p.read_bytes() for p in folder.rglob('*.json')},before)

    def test_historical_state_symlink_is_not_read(self):
        folder=bridge.directory('c'*32);run=folder/'runs'/'recorded';run.mkdir(parents=True)
        (folder/'job.json').write_text(json.dumps({'status':'insufficient_coverage'}))
        (folder/'result.json').write_text(json.dumps({'run_id':'external'}))
        external=self.root/'external.json';external.write_text(json.dumps({'run_id':'external','text':'outside'}))
        (run/'state.json').symlink_to(external)
        self.assertNotIn('effective_request_text',bridge.public('c'*32)['result'])

    def test_explicit_survey_selection_never_falls_back_and_pins_v2_context(self):
        with patch.object(bridge.threading,'Thread') as thread,self.assertRaisesRegex(ValueError,'survey_run_id'):
            bridge.start({'input_kind':'survey_v2','text':'Get processes','scope':['endpoint'],'max_steps':1},self.config)
        thread.assert_not_called()
        real_id=json.loads((BUNDLE/'survey_context.json').read_text())['survey_run_id']
        run=self.root/'outputs'/real_id
        shutil.copytree(BUNDLE,run/'survey_v2')
        with patch.object(bridge.threading,'Thread'):
            value=bridge.start({'input_kind':'survey_v2','survey_run_id':real_id,'text':'Get processes','scope':['endpoint'],'max_steps':1},self.config)
        folder=bridge.directory(value['id'])
        self.assertEqual(bridge.read(folder/'provenance.json')['survey_run_id'],real_id)
        self.assertEqual(bridge.read(folder/'request.json')['input_kind'],'survey_v2')
        loader=bridge.input_module(RUNTIME)
        envelope,target=loader.verify_snapshot(folder/'input',bridge.read(folder/'job.json')['input_manifest_sha256'])
        self.assertEqual(envelope['survey_context']['survey_run_id'],real_id)
        self.assertEqual(target['address'],bridge.read(folder/'job.json')['target_ip'])


if __name__ == '__main__': unittest.main()
