import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from engine import execution_contracts as c, execution_telemetry as t, telemetry_identity as identity
from engine.wazuh_connector import ConnectorError


class ExpectedRealityTests(unittest.TestCase):
    def setUp(self):
        self.record={'id':'a'*32,'scenario_job_id':'b'*32,'plan_sha256':'hash',
            'target':{'ip':'192.0.2.1','host':'lab'},'created_at':'2026-11-23T09:00:00Z',
            'updated_at':'2026-11-23T09:01:00Z','state':'completed',
            'preflight':{'binding_sha256':'binding','steps':[{'index':1,'source_ability_id':'ability',
                'executor':{'platform':'windows','name':'cmd'},'command':'tasklist',
                'source':{'revision':'revision'},'technique_ids':['T1057']} ]},
            'steps':[{'index':1,'state':'completed','exit_code':'0'}]}
        self.state={'status':'complete','mode':'alerts_only','identity_policy':{'verified':True}}

    def test_expectation_independent_of_reality_and_repeated_steps(self):
        before=copy.deepcopy(self.record);one=c.expected(self.record)
        self.record['steps'][0].update(state='failed',exit_code=1)
        self.assertEqual(one,c.expected(self.record))
        self.record=before;self.record['preflight']['steps'].append(dict(self.record['preflight']['steps'][0],index=2))
        contract=c.expected(self.record)
        self.assertNotEqual(contract['steps'][0]['step_id'],contract['steps'][1]['step_id'])
        result=c.comparison(self.record,contract,self.state,[])
        self.assertEqual({'numerator':1,'denominator':2,'percent':50},result['execution_completion'])
        self.assertEqual(['T1057'],result['techniques']['expected'])
        self.assertIsNone(result['alert_coverage']['percent'])
        self.assertIsNone(result['telemetry_coverage']['percent'])

    def test_zero_denominator_undefined_profile_and_tamper(self):
        self.record['preflight']['steps'][0]['executor']['platform']='linux'
        expected=c.expected(self.record)
        self.assertEqual('not_defined',expected['steps'][0]['telemetry']['status'])
        c.verify_expected(expected,self.record)
        expected['steps'][0]['ability_id']='tampered'
        with self.assertRaises(ValueError):c.verify_expected(expected,self.record)

    def test_validation_artifact_preserves_prerequisites_and_schema(self):
        check={'checked_at':'2026-11-23T09:00:00Z','policy':{'preview_ttl_seconds':300},
            'plan_sha256':'hash','binding_sha256':'binding','target':self.record['target'],
            'survey':{'survey_run_id':'pinned'},'ready':False,'blockers':['Thiếu tham số'],
            'warnings':['Telemetry chưa xác minh'],
            'steps':[{'index':1,'source':{'revision':'abc'},'executor':{'name':'cmd'},
                'prerequisites':[{'condition':'dependency','status':'unknown'}],
                'blockers':['Dependency chưa hỗ trợ']}]}
        before=copy.deepcopy(check);artifact=c.validation(check)
        self.assertEqual(before,check)
        self.assertEqual('unsupported',artifact['steps'][0]['status'])
        self.assertEqual('unknown',artifact['steps'][0]['prerequisites'][0]['status'])
        self.assertEqual('telemetry_optional',artifact['warnings'][0]['category'])
        schemas=Path(__file__).resolve().parents[1]/'schemas'
        self.assertTrue(set(json.loads((schemas/'execution-validation-v1.schema.json').read_text())['required']) <= set(artifact))
        self.assertTrue(set(json.loads((schemas/'execution-expected-v1.schema.json').read_text())['required']) <= set(c.expected(self.record)))

    def event(self):
        return {'index':'wazuh-alerts-test','document_id':'a','agent':{'id':'x'},'source_timestamp':'t',
            'source':{'channel':'Security','event_id':'4688','record_id':'1','computer':'host'},
            'rule':{'id':'123'},'correlation':{'step_index':1,'ambiguous':False},'test_marker':False}

    def test_positive_evidence_partial_and_missing_source(self):
        state=dict(self.state,truncated=True)
        result=c.comparison(self.record,c.expected(self.record),state,[self.event()])
        self.assertEqual(1,result['telemetry_coverage']['numerator'])
        self.assertTrue(result['partial']);self.assertEqual('not_verified',result['steps'][0]['behavior_status'])
        state['identity_policy']={'verified':False}
        self.assertEqual(0,c.comparison(self.record,c.expected(self.record),state,[])['telemetry_coverage']['denominator'])

    def test_alert_documents_and_raw_events_dedup_and_unknown(self):
        event=self.event();archive=dict(event,index='wazuh-archives-test',document_id='other')
        state=dict(self.state,mode='alerts_and_archives')
        result=t.document_counts([event,event,archive],state)
        self.assertEqual(1,result['raw_event_count']);self.assertEqual(1,result['candidate_alert_documents'])
        self.assertIsNone(t.document_counts([event],self.state)['raw_event_count'])
        self.assertIsNone(t.document_counts([],{'status':'degraded','error':{'code':'http_403'}})['candidate_alert_documents'])
        self.assertEqual(0,t.document_counts([],self.state)['candidate_alert_documents'])
        self.assertIsNone(t.document_counts([],dict(self.state,identity_policy={'verified':False}))['correlated_alert_documents'])

    def test_binding_requires_window_hash_and_unique_admin_attestation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);evidence=root/'attestation.txt';evidence.write_text('Admin-reviewed historical mapping')
            binding={'target':self.record['target'],'agent':{'ip':'192.0.2.1','id':'x','name':'endpoint'},
                'verified_at':'2026-11-23T10:00:00Z','valid_from':'2026-11-23T08:00:00Z',
                'valid_until':'2026-11-23T10:00:00Z','verified_by':'lab-admin','purpose':'historical_identity',
                'evidence_refs':[{'file':'attestation.txt','sha256':hashlib.sha256(evidence.read_bytes()).hexdigest()}]}
            doc={'schema_version':'historical_identity_bindings_v1','bindings':[binding]}
            path=root/'telemetry_identity_bindings.json';path.write_text(json.dumps(doc))
            window={'start':self.record['created_at'],'end':self.record['updated_at']}
            self.assertEqual(binding,identity.resolve(root,self.record['target'],window))
            self.assertIsNone(identity.resolve(root,self.record['target'],dict(window,end='2026-11-24T10:00:00Z')))
            doc['bindings'].append(binding);path.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ConnectorError,'ambiguous'):identity.resolve(root,self.record['target'],window)
            doc['bindings'].pop();path.write_text(json.dumps(doc));evidence.write_text('changed')
            with self.assertRaisesRegex(ConnectorError,'changed'):identity.resolve(root,self.record['target'],window)

    def test_missing_api_collects_candidates_without_dispatch_or_identity_promotion(self):
        from engine import scenario_execution as e
        with tempfile.TemporaryDirectory() as temp,patch.object(t,'ROOT',Path(temp)),patch.object(e,'read',return_value=self.record),patch.object(e,'history',return_value=[]),patch.object(e,'run') as run:
            Path(temp,'telemetry_report.json').write_text(json.dumps({'enabled':True}))
            factory=Mock();client=factory.return_value;client.query_count=4
            client.identity.side_effect=ConnectorError('identity_unverified_api_credentials_missing')
            client.collect.return_value={'hits':[{'_index':'wazuh-alerts-test','_id':'a','_source':{
                'timestamp':self.record['created_at'],'agent':{'ip':'192.0.2.1','id':'x'},
                'rule':{'id':'1'},'data':{'soc':{'execution_id':self.record['id']}}}}],
                'mode':'alerts_only','truncated':False}
            result=t.collect(self.record['id'],factory)
            self.assertEqual(1,result['counts_v2']['candidate_alert_documents'])
            self.assertIsNone(result['counts_v2']['correlated_alert_documents'])
            self.assertTrue(result['evidence'][0]['correlation']['ambiguous'])
            self.assertEqual('unknown',result['behavior_status']);run.assert_not_called()
            self.assertTrue(list(Path(temp,'telemetry_reports',self.record['id']).glob('snapshot-*.json')))


if __name__=='__main__':unittest.main()
