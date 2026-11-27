"""Offline regression tests: no provider, victim or Wazuh access."""
import copy
import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch
from engine import execution_telemetry as t


class ReportSessionsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.addCleanup(patch.stopall)
        patch.object(t,'ROOT',Path(self.tmp.name)).start()
        self.settings={'enabled':True,'poll_interval_seconds':3,'ingest_grace_seconds':120}
        patch.object(t,'config',return_value=self.settings).start()
        date=datetime.now(timezone.utc)
        self.record={'id':'c'*32,'state':'running','target':{'ip':'192.0.2.1'},
            'created_at':t.iso(date-timedelta(seconds=20)), 'confirmed_at':t.iso(date-timedelta(seconds=20)),
            'updated_at':t.iso(date),'steps':[],'operation_id':'op'}
        patch('engine.scenario_execution.read',side_effect=lambda _:copy.deepcopy(self.record)).start()
        patch('engine.scenario_execution.history',return_value=[]).start()
        patch.object(t,'artifact_refs',return_value=[]).start()
        self.client=Mock();self.client.query_count=4
        self.client.identity.return_value={'id':'001','name':'lab','ip':'192.0.2.1'}
        self.client.collect.side_effect=lambda *_:{'hits':[],'pages':1,'truncated':False,'mode':'alerts_only'}

    def reset_cooldown(self):
        path=t.directory(self.record['id'])/'telemetry_state.json'
        state=t.load(path);state['last_attempt_epoch']=0;t.save(path,state)

    def test_event_window_separate_from_ingest_wait(self):
        self.record['state']='completed'
        w=t.window_for(self.record,self.settings)
        self.assertEqual(120,(t.timestamp(w['ingest_deadline'])-t.timestamp(w['end'])).total_seconds())
        self.assertEqual(w,t.window_for(self.record,self.settings,w))

    def test_active_poll_then_terminal_and_reopen_identity(self):
        first=t.collect(self.record['id'],lambda _:self.client)
        self.assertEqual('watching_execution',first['collection']['status'])
        self.assertTrue(first['collection']['identity_attestation'])
        self.reset_cooldown();self.record['state']='completed'
        second=t.collect(self.record['id'],lambda _:self.client)
        self.assertEqual('waiting_ingest',second['collection']['status'])
        self.assertEqual('execution_snapshot',second['collection']['identity_policy']['kind'])
        self.assertEqual(8,second['collection']['total_query_count'])

    def test_identity_drift_does_not_reuse_prior_correlation(self):
        t.collect(self.record['id'],lambda _:self.client);self.reset_cooldown()
        self.client.identity.return_value={'id':'002','name':'different','ip':'192.0.2.1'}
        report=t.collect(self.record['id'],lambda _:self.client)
        self.assertEqual('identity_binding_drift',report['collection']['error']['code'])
        self.assertFalse(report['collection']['identity_policy']['verified'])
        self.assertEqual([],report['evidence'])

    def test_process_launch_and_mitre_tag_are_not_detection(self):
        hit={'_id':'event','_index':'wazuh-alerts-test','_source':{
            'rule':{'id':'67027','mitre':{'id':['T1059','invalid']}},
            'data':{'soc':{'execution_id':self.record['id']},'win':{'system':{'eventID':'4688'}}}}}
        event=t.normalize(hit,self.record)
        report=t.build_report(self.record,{},[event])
        self.assertEqual(['T1059'],event['rule']['mitre_ids'])
        self.assertEqual('not_evaluable',report['assessment']['technique_detection'])
        self.assertEqual(0,report['assessment']['llm_requests'])
        self.assertEqual(1,report['assessment']['process_launch_alerts'])

    def test_one_worker_per_session_and_no_dispatch(self):
        gate=threading.Event()
        def collect(_):
            gate.wait(2)
            return {'collection':{'status':'complete'}}
        with patch.object(t,'collect',side_effect=collect),patch('engine.scenario_execution.run') as run:
            t.enqueue(self.record['id']);second=t.enqueue(self.record['id'])
            self.assertEqual('collecting',second['status'])
            threads=list(t.THREADS.values());gate.set()
            for thread in threads:thread.join(2)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            run.assert_not_called()

    def test_resume_active_and_journal_without_dispatch(self):
        t.save(t.directory(self.record['id'])/'telemetry_state.json',{'status':'watching_execution'})
        with patch.object(t,'enqueue') as enqueue,patch('engine.scenario_execution.run') as run:
            t.initialize();enqueue.assert_called_once_with(self.record['id']);run.assert_not_called()

    def test_stream_reads_cache_without_network(self):
        import app
        from http.server import ThreadingHTTPServer
        from urllib.request import urlopen
        with patch.object(t,'read',return_value={'execution_id':self.record['id']}),patch.object(t,'enqueue') as enqueue,patch.object(t,'collect') as collect:
            server=ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                with urlopen('http://127.0.0.1:%s/api/executions/%s/telemetry/stream'%(server.server_port,self.record['id']),timeout=5) as response:
                    self.assertIn('text/event-stream',response.headers['Content-Type'])
                    self.assertEqual(b'event: report\n',response.readline())
                    self.assertIn(self.record['id'].encode(),response.readline())
                enqueue.assert_not_called();collect.assert_not_called()
            finally:server.shutdown();server.server_close()
