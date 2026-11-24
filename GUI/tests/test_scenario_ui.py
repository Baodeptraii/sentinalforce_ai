"""Read-only UI assets and source provenance; no sockets or lab calls."""
import json
import hashlib
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from final_template.contracts import validate_document

STATIC = app.ROOT / 'static'
PROJECT = app.ROOT.parent


class TestScenarioUI(unittest.TestCase):
    def test_snapshot_is_exact_existing_yaml_not_generated_content(self):
        data = json.loads((STATIC / 'scenario-data.json').read_text(encoding='utf-8'))
        self.assertEqual(data['mode'], 'ui_preview')
        self.assertTrue(data['preview_only'])
        self.assertEqual(len(data['items']), 113)
        self.assertEqual(len({item['id'] for item in data['items']}), 113)
        self.assertEqual(Counter(item['family'] for item in data['items']),
                         {'scenario': 69, 'caldera': 25, 'dvwa': 11, 'nckh': 8})
        for item in data['items'] + [data['template']]:
            hashes = json.loads((Path(__file__).parent / 'fixtures/scenario_source_hashes.json').read_text())
            self.assertEqual(hashlib.sha256(item['yaml'].encode()).hexdigest(), hashes[item['file']])
            self.assertEqual(len(item['abilities']), len(set(item['abilities'])))
        for entry in data['profiles']:
            validate_document(entry['profile'], 'target_profile')
        self.assertEqual(data['profileSchema'], json.loads((PROJECT / 'final_template/target_profile_schema.json').read_text()))

    def test_assets_are_served_without_running_survey_or_scenario(self):
        routes = {'/scenario.js': 'scenario.js', '/scenario-core.js': 'scenario-core.js',
                  '/scenario-data.json': 'scenario-data.json', '/flow.js': 'flow.js',
                  '/flow-core.js': 'flow-core.js', '/flow.css': 'flow.css'}
        for route, filename in routes.items():
            with self.subTest(route=route), patch.object(app, 'execute') as execute, patch.object(app, 'preflight') as preflight:
                handler = app.Handler.__new__(app.Handler); handler.path = route
                with patch.object(handler, 'send') as send:
                    handler.do_GET()
                    self.assertEqual(send.call_args[0][0], (STATIC / filename).read_bytes())
                execute.assert_not_called(); preflight.assert_not_called()

    def test_navigation_upload_and_preview_markup_have_unique_ids(self):
        class Parser(HTMLParser):
            def __init__(self):
                super().__init__(); self.ids = []
            def handle_starttag(self, tag, attrs):
                attributes = dict(attrs)
                if 'id' in attributes: self.ids.append(attributes['id'])
        parser = Parser(); parser.feed((STATIC / 'index.html').read_text(encoding='utf-8'))
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        for identifier in ['transfer-profile', 'scenario-view', 'library-view', 'profile-upload',
                           'scenario-request', 'yaml-preview', 'download-yaml', 'library-search']:
            self.assertIn(identifier, parser.ids)


if __name__ == '__main__':
    unittest.main()
