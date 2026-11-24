"""Offline contract/export tests: no model calls or target traffic."""
import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
import io
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine.survey_output_v2 import convert, verify, checked_ref, bundle_v2, select_context
from engine.runner import save


class SurveyV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root/'run'
        self.source.mkdir()
        save(self.source/'survey_request.json', {'target_ip': '192.0.2.5', 'survey_scope': ['web', 'endpoint']})
        save(self.source/'target_profile.json', {'id': 'fixture', 'address': '192.0.2.5', 'os': {}, 'services': [], 'capabilities': {}, 'telemetry': {'process_events': True}})
        save(self.source/'02_endpoint.json', {'data': {'os_name': 'Windows', 'collected_at': '2020-01-01T00:00:00Z', 'services': [{'name': 'Wazuh', 'state': 'Running'}]*300, 'listeners': []}})
        auth = {'base_url': 'http://192.0.2.5:8080/lab/', 'checked_at': '2020-01-01T00:00:00Z', 'session_ready': True,
                'cookie': 'secret-cookie', 'current_security_level': 'low', 'modules': [
                    {'path': 'vulnerabilities/'+name+'/', 'http_status': 200, 'authenticated': True,
                     'forms': [{'method': 'GET', 'action_path': '', 'csrf_present': False,
                                'inputs': [{'name': 'id', 'type': 'text', 'value': 'private-form-value'}, {'name': 'Submit', 'type': 'submit'}]}]}
                    for name in ('sqli', 'sqli_blind')]}
        save(self.source/'tool_01_inspect.json', {'tool': 'inspect_dvwa_modules', 'status': 'ok', 'data': {'authentication': auth}})
        save(self.source/'report.json', {'status': 'partial', 'finished_at': '2020-01-01T00:00:01Z'})

    def export(self, name='export'):
        dest = self.root/name
        return dest, convert(self.source, dest)

    def test_modules_secrets_provenance_unknowns_and_compact_inventory(self):
        before = {p.name: p.read_bytes() for p in self.source.iterdir()}
        dest, ctx = self.export()
        modules = [f for f in ctx['observations'] if f['predicate'] == 'module_access_and_forms']
        self.assertEqual(len(modules), 2)
        for f in modules:
            self.assertEqual(f['value']['forms'][0]['method'], 'GET')
            self.assertEqual([i['name'] for i in f['value']['forms'][0]['inputs']], ['id', 'Submit'])
            for r in f['evidence_refs']: checked_ref(dest, r)
        self.assertTrue(any(f['subject'] == 'http://192.0.2.5:8080/lab/' for f in ctx['observations']))
        all_json = '\n'.join(p.read_text() for p in dest.rglob('*.json'))
        self.assertNotIn('secret-cookie', all_json)
        self.assertNotIn('private-form-value', all_json)
        self.assertNotIn('search.php', all_json)
        self.assertTrue(any(g['subject'] == 'telemetry.detection' for g in ctx['gaps']))
        compact = (dest/'survey_context.json').read_text()
        self.assertNotIn('Running', compact)
        self.assertLess(len(compact), 17000)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.source.iterdir()})
        v2 = json.loads((dest/'target_profile_v2.json').read_text())
        self.assertFalse(v2['interpretation']['execution_authorized'])
        self.assertTrue(any(f['value'].get('reverify_before_execution') for f in ctx['observations'] if isinstance(f['value'], dict)))

    def test_deterministic_and_portable(self):
        one, ctx = self.export('one')
        two, ctx2 = self.export('two')
        self.assertEqual(ctx, ctx2)
        self.assertEqual((one/'scenario_handoff.json').read_bytes(), (two/'scenario_handoff.json').read_bytes())
        moved = self.root/'moved'
        with zipfile.ZipFile(io.BytesIO(bundle_v2(one))) as z: z.extractall(moved)
        shutil.rmtree(one)
        verify(moved)
        self.assertTrue(all(f['observed_at'] in (None, '2020-01-01T00:00:00Z') for f in ctx['observations']))
        example = select_context(ctx, ['web'], ['sqli'])
        self.assertTrue(any('sqli_blind' in f['subject'] for f in example['observations']))

    def test_refs_fail_closed(self):
        dest, ctx = self.export()
        good = ctx['observations'][0]['evidence_refs'][0]
        for change in ({'file': '../run/report.json'}, {'file': '/etc/passwd'}, {'pointer': '/missing'}, {'sha256': '0'*64}, {'file': 'missing.json'}):
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError, OSError)):
                checked_ref(dest, good | change)
        outside = self.root/'outside.json'; outside.write_text('{}')
        (dest/'link.json').symlink_to(outside)
        with self.assertRaises(ValueError): checked_ref(dest, good | {'file': 'link.json'})
        (dest/good['file']).write_text('{}')
        with self.assertRaises(ValueError): verify(dest)

    def test_error_truncation_conflict_and_untimed(self):
        record = json.loads((self.source/'tool_01_inspect.json').read_text())
        record['data']['authentication'].pop('checked_at')
        record['data']['authentication']['modules_truncated'] = True
        save(self.source/'tool_02_inspect.json', record)
        save(self.source/'tool_03_error.json', {'tool': 'probe_web', 'status': 'error'})
        record['data']['authentication']['session_ready'] = False
        save(self.source/'tool_04_inspect.json', record)
        dest, ctx = self.export()
        self.assertTrue(ctx['conflicts'])
        for reason in ('missing_time', 'truncated', 'tool_error'):
            self.assertTrue(any(g['reason'] == reason for g in ctx['gaps']))
        self.assertEqual(ctx['status'], 'partial')
        self.assertFalse(any(g['reason'] == 'stale' for g in ctx['gaps']))

    def test_original_hash_and_pointer_validation(self):
        save(self.source/'evidence_index.json', {'records': [{'file': 'report.json', 'sha256': '0'*64}]})
        with self.assertRaises(ValueError): self.export()
        self.assertFalse((self.root/'export').exists())
        (self.source/'evidence_index.json').unlink()
        profile = json.loads((self.source/'target_profile.json').read_text())
        profile['services'] = [{'evidence_ref': 'report.json#/missing'}]
        save(self.source/'target_profile.json', profile)
        with self.assertRaises(KeyError): self.export()

    def test_record_limit_reports_gap(self):
        with patch('engine.survey_output_v2.MAX_FACTS', 1):
            dest, ctx = self.export()
        self.assertEqual(len(ctx['observations']), 1)
        self.assertTrue(any(g['reason'] == 'truncated' for g in ctx['gaps']))

    def test_gui_finalize_and_bundle_use_v2(self):
        import app
        from engine.handoff import bundle
        job = {'id': 'run', 'request': {'target_ip': '192.0.2.5'}, 'created_at': '2020-01-01T00:00:00Z', 'logs': []}
        with patch.object(app, 'OUTPUTS', self.root), patch.object(app, 'execute', return_value=({}, [])):
            app.work(job, {})
        self.assertEqual(job['survey_output_v2'], 'survey_v2/scenario_handoff.json')
        with zipfile.ZipFile(io.BytesIO(bundle(self.source))) as archive:
            self.assertIn('survey_context.json', archive.namelist())
            self.assertIn('scenario_handoff.json', archive.namelist())
            self.assertNotIn('state.json', archive.namelist())

    def test_no_profile_partial_and_source_symlink(self):
        (self.source/'target_profile.json').unlink()
        dest, ctx = self.export()
        self.assertIsNone(ctx['target_id'])
        self.assertEqual(ctx['target_ip'], '192.0.2.5')
        (self.source/'evil.json').symlink_to(self.root/'export'/'report.json')
        with self.assertRaises(ValueError): self.export('unsafe')


if __name__ == '__main__': unittest.main()
