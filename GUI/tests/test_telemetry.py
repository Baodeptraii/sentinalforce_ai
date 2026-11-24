import copy
import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from engine import telemetry, survey
from engine.evidence_refs import validate_profile_refs
from engine.contracts import TargetProfile
from test_agent import endpoint


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.request = {'target_ip': '192.0.2.11', 'survey_scope': ['endpoint', 'web']}
        self.agent = {'host': 'FIXTURE', 'paw': 'fixture'}
        self.endpoint = endpoint(); self.endpoint['data']['listeners'] = []
        self.binding = {'agent_id': '001', 'hostname': 'FIXTURE', 'web_log_paths': ['C:\\xampp\\apache\\logs\\access.log']}
        self.config = {'telemetry': {'enabled': True, 'targets': {'192.0.2.11': self.binding}}}
        self.now = datetime.now(timezone.utc).isoformat()

    def run_collect(self, config=None):
        return telemetry.collect(self.request, self.agent, self.endpoint, self.config if config is None else config, self.directory, lambda *a: None, lambda *a: None)

    def raw(self):
        return {'format': 'wazuh_observation_v1', 'agent_id': '001', 'hostname': 'FIXTURE', 'checked_at': self.now,
                'sources': [{'status': 'read'}], 'samples': [{'field': 'wazuh_ingestion', 'agent_id': '001', 'agent_name': 'FIXTURE', 'timestamp': self.now,
                'channel': 'Microsoft-Windows-Sysmon/Operational', 'event_id': '1', 'source': 'alerts/alerts.json', 'location': 'EventChannel'}]}

    def test_local_events_not_equal_ingestion(self):
        self.endpoint['data']['telemetry_observations'] = {'process_events': {'kind': 'sysmon_event_1', 'event_time': self.now}}
        with patch.object(telemetry, 'manager_query') as query:
            result = self.run_collect({})
        query.assert_not_called()
        self.assertTrue(result['values']['process_events'])
        self.assertIsNone(result['values']['wazuh_ingestion'])

    def test_unknown_failure_and_target_mismatch_never_become_false_or_true(self):
        with patch.object(telemetry, 'manager_query', side_effect=TimeoutError('private-secret')):
            result = self.run_collect()
        self.assertTrue(all(v is None for v in result['values'].values()))
        self.assertNotIn('private-secret', json.dumps(result))
        self.binding['hostname'] = 'OTHER'
        with patch.object(telemetry, 'manager_query') as query: result = self.run_collect()
        query.assert_not_called(); self.assertEqual(result['manager']['status'], 'identity_mismatch')

    def test_manager_receipt_and_profile_evidence_gate(self):
        with patch.object(telemetry, 'manager_query', return_value=self.raw()): result = self.run_collect()
        self.assertTrue(result['values']['wazuh_ingestion'])
        profile = survey.build_profile(self.request, self.agent, self.endpoint, None)
        profile['telemetry'] = result['values']
        TargetProfile.model_validate(profile)
        validate_profile_refs(self.directory, profile)
        profile['telemetry']['network_events'] = True
        with self.assertRaises(ValueError): validate_profile_refs(self.directory, profile)

    def test_old_future_wrong_agent_or_wrong_channel_never_verified(self):
        for change in [{'timestamp': (datetime.now(timezone.utc)-timedelta(days=2)).isoformat()},
                       {'timestamp': (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()},
                       {'agent_id': '999'}, {'field': 'process_events', 'channel': 'Other'}]:
            raw = self.raw(); raw['samples'][0].update(change)
            with patch.object(telemetry, 'manager_query', return_value=raw): result = self.run_collect()
            self.assertTrue(all(v is None for v in result['values'].values()), change)

    def test_scope_and_cancel(self):
        self.request['survey_scope'] = ['web']
        self.endpoint['data']['telemetry_observations'] = {'process_events': {'kind': 'sysmon_event_1', 'event_time': self.now}}
        result = self.run_collect({})
        self.assertIsNone(result['values']['process_events']); self.assertEqual(result['checks']['process_events']['status'], 'out_of_scope')
        (self.directory / 'cancel.requested').touch()
        with patch.object(telemetry, 'manager_query') as query: result = self.run_collect()
        query.assert_not_called(); self.assertEqual(result['checks']['wazuh_ingestion']['status'], 'cancelled')

    def test_hostname_and_collection_time_bind_local_observations(self):
        self.endpoint['data']['telemetry_observations'] = {'process_events': {'kind': 'sysmon_event_1', 'event_time': self.now}}
        self.endpoint['data']['hostname'] = 'OTHER'
        self.assertIsNone(self.run_collect({})['values']['process_events'])

    def test_manager_scanner_accepts_wazuh_offset_and_requires_channel(self):
        from engine import wazuh_scan
        path = self.directory / 'alerts'; path.mkdir()
        event = {'agent': {'id': '001', 'name': 'FIXTURE'}, 'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
                 'location': 'EventChannel', 'data': {'win': {'system': {'channel': 'Microsoft-Windows-Sysmon/Operational', 'eventID': '1'}}}}
        other = copy.deepcopy(event); other['data']['win']['system']['channel'] = 'Other'
        (path / 'alerts.json').write_text(json.dumps(event) + '\n' + json.dumps(other) + '\n')
        with patch.object(wazuh_scan, 'Path', return_value=self.directory):
            result = wazuh_scan.scan(dict(self.binding, window_hours=24))
        self.assertEqual(result['counts']['process_events'], 1)
        self.assertEqual(result['counts']['wazuh_ingestion'], 2)


if __name__ == '__main__': unittest.main()
