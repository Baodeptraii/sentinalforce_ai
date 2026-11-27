import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from engine.presentation import download_name, hydrate


class TestMergeDownloads(unittest.TestCase):
    def test_download_name_uses_recorded_utc_time_and_full_run_id(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            job = {'id': '1258e4a1534541a49a17557578bf6c13', 'request': {'target_ip': '192.168.73.130'},
                   'report': {'finished_at': '2026-11-11T00:57:14-08:00'}}
            expected = 'target_profile_192-168-73-130_20261111T085714Z_1258e4a1534541a49a17557578bf6c13.json'
            self.assertEqual(download_name(job, directory), expected)
            self.assertEqual(download_name(job, directory), expected)
            other = copy.deepcopy(job); other['id'] = job['id'][:8] + 'b' * 24
            self.assertNotEqual(download_name(job, directory), download_name(other, directory))

    def test_partial_report_overrides_old_completed_state_and_keeps_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / 'report.json').write_text(json.dumps({'status': 'partial', 'mode': 'ai', 'steps': 2,
                'stop_reason': 'llm_error', 'finished_at': '2026-11-11T08:57:14Z'}))
            (directory / 'ai_trace.json').write_text(json.dumps([{'event': 'llm_error', 'message': 'LLM HTTP 400', 'at': '2026-11-11T08:57:14Z'}]))
            (directory / 'target_profile.json').write_text('{}')
            job = hydrate({'id': 'a' * 32, 'status': 'completed', 'request': {'target_ip': '192.168.73.130'}}, directory)
            self.assertEqual(job['status'], 'partial')
            self.assertEqual(job['report']['failure']['turn'], 2)
            self.assertTrue(job['events'])
            self.assertIn('target_profile.json', job['files'])

    def test_download_repeated_keeps_exact_json_bytes_and_no_new_server_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); identifier = 'd' * 32; directory = root / identifier; directory.mkdir()
            original = b'{ "id": "existing", "capabilities": {"art_ready": null} }\n'
            (directory / 'target_profile.json').write_bytes(original)
            job = {'id': identifier, 'status': 'partial', 'created_at': '2026-11-11T08:57:14Z', 'request': {'target_ip': '192.168.73.130'}}
            before = sorted(p.name for p in directory.iterdir())
            names = []
            with patch.object(app, 'OUTPUTS', root), patch.object(app, 'JOBS', {identifier: job}):
                for _ in range(2):
                    handler = app.Handler.__new__(app.Handler)
                    handler.path = '/api/jobs/' + identifier + '/files/target_profile.json'
                    with patch.object(handler, 'send') as send:
                        handler.do_GET()
                        self.assertEqual(send.call_args.args[0], original)
                        names.append(send.call_args.kwargs['attachment'])
            self.assertEqual(names[0], names[1])
            self.assertEqual(before, sorted(p.name for p in directory.iterdir()))
            self.assertEqual((directory / 'target_profile.json').read_bytes(), original)

    def test_response_sets_content_disposition_filename(self):
        handler = app.Handler.__new__(app.Handler); handler.wfile = io.BytesIO()
        with patch.object(handler, 'send_response'), patch.object(handler, 'send_header') as header, patch.object(handler, 'end_headers'):
            handler.send(b'{}', attachment='target_profile_192-168-73-130_20261111T085714Z_test.json')
            self.assertIn(('Content-Disposition', 'attachment; filename="target_profile_192-168-73-130_20261111T085714Z_test.json"'), [call.args for call in header.call_args_list])

    def test_all_imported_histories_are_available_and_partial(self):
        expected = {'1258e4a1534541a49a17557578bf6c13', '2de999af2b524923a3f10f7d0091c0fc',
                    '9477a3c129eb49f7b2161eb59eb293a6', '9f423ae4758742328ad2d2bccc9e4b9e'}
        with tempfile.TemporaryDirectory() as temp, patch.object(app, 'OUTPUTS', Path(temp)), patch.object(app, 'JOBS', {}):
            for identifier in expected:
                directory = Path(temp) / identifier; directory.mkdir()
                (directory / 'state.json').write_text(json.dumps({'id': identifier, 'status': 'completed', 'warnings': []}))
                (directory / 'report.json').write_text(json.dumps({'status': 'partial'}))
            app.load_jobs()
            self.assertTrue(expected.issubset(app.JOBS))
            self.assertEqual(app.JOBS['1258e4a1534541a49a17557578bf6c13']['status'], 'partial')


if __name__ == '__main__': unittest.main()
