import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch,Mock,MagicMock
from urllib.error import HTTPError,URLError
from engine import audit_stream as audit, execution_telemetry as t, wazuh_connector as w


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        patch('engine.scenario_execution.history',return_value=[]).start();patch.object(t,'ROOT',self.root).start();patch.object(audit,'ROOT',self.root).start()
        self.record={'id':'a'*32,'scenario_job_id':'b'*32,'created_at':'2026-11-22T10:00:00Z',
                     'updated_at':'2026-11-22T10:01:00Z','operation_id':'op','target':{'ip':'192.168.1.150','host':'PTIT'},
                     'state':'completed','command_status':'completed','steps':[{'index':1,'state':'completed','exit_code':0,'link_id':'link'}]}
        self.settings={'enabled':True,'refresh_cooldown_seconds':0,'max_events':10}
        (self.root/'telemetry_report.json').write_text(json.dumps(self.settings))

    def hit(self,**soc):
        return {'_id':'doc1','_index':'wazuh-alerts-4.x-test','_source':{'timestamp':'2026-11-22T10:00:30Z',
            'agent':{'id':'009','ip':'192.168.1.150'},'rule':{'id':'1','level':3,'description':'password=Secret123; observed'},
            'data':{'soc':soc}}}

    def test_audit_append_and_rotation_no_prompt(self):
        original=audit.emit('marker',root=self.root/'audit',test_marker=True)
        audit.emit('marker',root=self.root/'audit',max_bytes=10,test_marker=True)
        files=list((self.root/'audit').glob('*.jsonl'));self.assertEqual(2,len(files))
        events=[json.loads(p.read_text())['soc'] for p in files]
        self.assertIn(original['event_id'],[e['event_id'] for e in events]);self.assertTrue(all(e['redacted'] for e in events))
        self.assertEqual(0o640,(self.root/'audit/events.jsonl').stat().st_mode & 0o777)
        with self.assertRaises(ValueError):audit.emit('marker',status='password=unsafe')

    def test_symlinks_permission_failure(self):
        (self.root/'link').symlink_to(self.root/'audit')
        with self.assertRaises(ValueError):audit.emit('marker',root=self.root/'link')
        with patch('engine.audit_stream.os.open',side_effect=PermissionError):
            with self.assertRaises(PermissionError):audit.emit('marker',root=self.root/'audit')

    def test_host_time_not_evidence_for_endpoint_or_web(self):
        for source in ({'win':{'system':{'eventID':'1'}}},{'soc_web':{'status':200}}):
            hit=self.hit();hit['_source']['data']=source
            event=t.normalize(hit,self.record);report=t.build_report(self.record,{'mode':'alerts_only'},[event])
            self.assertEqual('unknown',report['behavior_status']);self.assertEqual('unknown',report['detection_status'])
            self.assertTrue(event['correlation']['ambiguous'])

    def test_exact_ids_and_conflict(self):
        event=t.normalize(self.hit(execution_id=self.record['id'],operation_id='op',link_id='link'),self.record)
        self.assertEqual(1,event['correlation']['step_index'])
        self.assertNotIn('Secret123',json.dumps(event))
        report=t.build_report(self.record,{'mode':'alerts_only'},[event])
        self.assertEqual('matched_alert',report['detection_status']);self.assertEqual('unknown',report['behavior_status'])
        for values in ({'execution_id':'other','operation_id':'op'},{'execution_id':self.record['id'],'operation_id':'other'}):
            self.assertTrue(t.normalize(self.hit(**values),self.record)['correlation']['ambiguous'])

    def test_test_markers_not_scenario_proof(self):
        event=t.normalize(self.hit(execution_id=self.record['id'],test_marker=True),self.record)
        report=t.build_report(self.record,{},[event]);self.assertEqual(0,report['counts']['alerts'])
        self.assertEqual('unknown',report['detection_status'])

    def test_registered_web_marker_only(self):
        import uuid
        marker=str(uuid.uuid4());hit=self.hit();hit['_source']['data']={'soc_web':{'marker':marker,'status':200}}
        self.assertTrue(t.normalize(hit,self.record)['correlation']['ambiguous'])
        record=dict(self.record,telemetry_markers=[marker]);self.assertFalse(t.normalize(hit,record)['correlation']['ambiguous'])

    def test_windows_late_events_restart_dedup_and_no_mutation(self):
        original=copy.deepcopy(self.record)
        factory=Mock();client=factory.return_value
        client.identity.return_value={'id':'009','ip':'192.168.1.150'}
        client.collect.side_effect=[{'hits':[self.hit(execution_id=self.record['id'])],'mode':'alerts_only','truncated':False},
                                    {'hits':[self.hit(execution_id=self.record['id']),dict(self.hit(),_id='late')],'mode':'alerts_only','truncated':False}]
        with patch('engine.scenario_execution.read',return_value=self.record):
            report=t.collect(self.record['id'],factory)
            state=t.load(t.directory(self.record['id'])/'telemetry_state.json');state['last_attempt_epoch']=0
            t.save(t.directory(self.record['id'])/'telemetry_state.json',state)
            report2=t.collect(self.record['id'],factory)
        self.assertEqual(2,report2['counts']['events']);self.assertTrue(report2['collection']['checkpoint_reused'])
        self.assertEqual(report['collection']['window'],report2['collection']['window']);self.assertEqual(original,self.record)

    def test_budget_oversized_refused(self):
        record=dict(self.record,updated_at='2026-11-23T10:00:00Z')
        self.assertTrue(t.window_for(record,self.settings)['oversized'])
        factory=Mock()
        with patch('engine.scenario_execution.read',return_value=record):r=t.collect(record['id'],factory)
        factory.assert_not_called();self.assertEqual('execution_window_over_budget',r['collection']['error']['code'])

    def test_401_403_tls_timeout_do_not_infer_detection(self):
        for code in ('http_401','http_403','transport_or_tls_failure','response_too_large'):
            report=t.build_report(self.record,{'error':{'code':code}},[])
            self.assertEqual('not_evaluable',report['detection_status']);self.assertNotEqual('observed',report['behavior_status'])

    def test_query_pagination_archive_absent_and_dedup(self):
        connector=object.__new__(w.Connector);connector.config={'max_pages':5,'page_size':2}
        hit=self.hit();responses=[{'version':{'distribution':'opensearch','number':'2.19.1'}},[],
                                 {'_scroll_id':'s1','hits':{'hits':[hit,hit]}},
                                 {'_scroll_id':'s2','hits':{'hits':[]}}]
        connector.request=Mock(side_effect=responses)
        result=connector.collect({'id':'009','ip':'192.168.1.150'},{'start':'a','end':'b'})
        self.assertEqual(1,len(result['hits']));self.assertEqual('alerts_only',result['mode'])
        q=connector.request.call_args_list[2].args[2]
        self.assertIn({'term':{'agent.id':'009'}},q['query']['bool']['filter'])
        self.assertIn({'term':{'agent.ip':'192.168.1.150'}},q['query']['bool']['filter'])
        self.assertEqual(['_doc'],q['sort'])

    def test_identity_mapping_and_ambiguous(self):
        c=object.__new__(w.Connector);c.credentials={'api':{'username':'test','password':'fake'}}
        for items in ([],[{'ip':'x'},{'ip':'x'}]):
            c.request=Mock(side_effect=['jwt',{'data':{'affected_items':items}}])
            with self.assertRaises(w.ConnectorError):c.identity({'ip':'x'})
        c.request=Mock(side_effect=['jwt',{'data':{'affected_items':[{'id':'009','ip':'x','name':'alias'}]}}])
        self.assertEqual('009',c.identity({'ip':'x'})['id'])

    def test_config_tls_credentials_and_endpoint_boundaries(self):
        with self.assertRaises(w.ConnectorError):w.Connector({'enabled':False})
        cfg={'enabled':True,'api_url':'http://bad','indexer_url':'https://bad','allowed_hosts':['bad']}
        with self.assertRaises(w.ConnectorError):w.Connector(cfg)
        c=object.__new__(w.Connector)
        with self.assertRaises(w.ConnectorError):c.request('indexer','/wazuh-alerts-*/_delete_by_query',{})
        with self.assertRaises(w.ConnectorError):w.NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_transport_bounds_http_and_response_errors(self):
        import time
        for raised in (HTTPError('https://x',401,'bad',{},None),HTTPError('https://x',403,'bad',{},None),URLError('tls failure'),TimeoutError()):
            c=object.__new__(w.Connector);c.config={'indexer_url':'https://x','timeout_seconds':1};c.credentials={'indexer':{'username':'u','password':'p'}};c.deadline=time.monotonic()+2;c.token=None
            c.opener=MagicMock();c.opener.open.side_effect=raised
            with self.assertRaises(w.ConnectorError) as error:c.request('indexer','/')
            self.assertNotIn('p@',str(error.exception))
        c.opener.open.side_effect=None;response=c.opener.open.return_value.__enter__.return_value
        c.config['max_response_bytes']=2;response.read1.side_effect=[b'123']
        with self.assertRaisesRegex(w.ConnectorError,'response_too_large'):c.request('indexer','/')

    def test_refresh_duplicate_thread_and_no_execution_dispatch(self):
        import threading
        gate=threading.Event()
        with patch('engine.scenario_execution.read',return_value=self.record),patch.object(t,'collect',side_effect=lambda i:(gate.wait(2) and {'collection':{'status':'complete'}})),patch('engine.scenario_execution.run') as run:
            first=t.enqueue(self.record['id']);second=t.enqueue(self.record['id']);gate.set()
            for thread in list(t.THREADS.values()):thread.join(3)
            run.assert_not_called();self.assertIn(second['status'],('collecting','queued'))

    def test_pid_interval_requires_unique_step_and_no_overlap(self):
        record=copy.deepcopy(self.record);record['steps'][0].update(process_id=32,collected_at='2026-11-22T10:00:20Z',finished_at='2026-11-22T10:00:40Z')
        hit=self.hit();hit['_source']['data']={'win':{'eventdata':{'newProcessId':'0x20'},'system':{'systemTime':'2026-11-22T10:00:30Z'}}}
        event=t.normalize(hit,record);self.assertEqual('medium',event['correlation']['confidence'])
        record['_overlapping_execution']=True;self.assertTrue(t.normalize(hit,record)['correlation']['ambiguous'])
        record.pop('_overlapping_execution');record['steps'].append(dict(record['steps'][0],index=2))
        self.assertTrue(t.normalize(hit,record)['correlation']['ambiguous'])

    def test_page_budget_and_archive_permission_denial(self):
        c=object.__new__(w.Connector);c.config={'max_pages':1}
        c.request=Mock(side_effect=[{'version':{'distribution':'opensearch'}},w.ConnectorError('http_403',403),{'_scroll_id':'s','hits':{'hits':[self.hit()]}}])
        result=c.collect({'id':'009','ip':'192.168.1.150'},{'start':'a','end':'b'})
        self.assertTrue(result['truncated']);self.assertEqual('permission_denied',result['archive_status'])

    def test_running_window_can_extend_then_freeze_terminal(self):
        record=dict(self.record,state='running')
        first=t.window_for(record,self.settings)
        record['updated_at']='2026-11-22T10:05:00Z'
        self.assertGreater(t.window_for(record,self.settings)['end'],first['end'])
        self.assertEqual(first,t.window_for(record,self.settings,first))

    def test_resume_cursor_never_execution_run(self):
        path=t.directory(self.record['id']);t.save(path/'telemetry_state.json',{'status':'waiting_ingest'})
        with patch.object(t,'enqueue') as enqueue,patch('engine.scenario_execution.run') as run:
            t.initialize();enqueue.assert_called_once_with(self.record['id']);run.assert_not_called()

    def test_unknown_prerequisites_and_source_hash_preserved(self):
        record=copy.deepcopy(self.record);record['preflight']={'steps':[{'index':1,'prerequisites':[{'condition':'file exists','status':'unknown'}],
            'source':{'revision':'a'*64,'path':'input/catalog.yml'}}]}
        before=copy.deepcopy(record);report=t.build_report(record,{},[])
        self.assertEqual('unknown',report['steps'][0]['prerequisites'][0]['status'])
        self.assertEqual('a'*64,report['steps'][0]['source_provenance']['revision']);self.assertEqual(before,record)

    def test_explicit_lab_pin_checked_before_http_auth(self):
        import hashlib
        pin=hashlib.sha256(b'certificate').hexdigest()
        with patch('http.client.HTTPSConnection.connect'):
            connection=w.PinnedHTTPSConnection('lab',pin=pin)
            connection.sock=Mock();connection.sock.getpeercert.return_value=b'certificate'
            connection.connect();connection.sock.sendall.assert_not_called()
            connection.pin='0'*64
            with self.assertRaisesRegex(w.ConnectorError,'tls_certificate_pin_mismatch'):connection.connect()

    def test_http_report_export_csrf_and_refresh_never_dispatch(self):
        import app,threading,urllib.request
        from http.server import ThreadingHTTPServer
        with patch('engine.scenario_execution.read',return_value=self.record),patch('engine.scenario_execution.run') as run,patch.object(t,'enqueue',return_value={'status':'queued'}) as enqueue,patch.object(app,'load_config',return_value={}):
            server=ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                url='http://127.0.0.1:'+str(server.server_port)+'/api/executions/'+self.record['id']+'/telemetry'
                with urllib.request.urlopen(url+'/report.md') as response:
                    self.assertIn('attachment',response.headers['Content-Disposition'])
                    self.assertIn(b'unknown',response.read())
                request=urllib.request.Request(url+'/refresh',data=b'{}',method='POST')
                with self.assertRaises(HTTPError) as error:urllib.request.urlopen(request)
                self.assertEqual(403,error.exception.code)
                request.add_header('X-Survey-Token',app.TOKEN)
                self.assertEqual('queued',json.load(urllib.request.urlopen(request))['status'])
                enqueue.assert_called_once_with(self.record['id']);run.assert_not_called()
            finally:server.shutdown();server.server_close();thread.join(2)

    def test_multiline_untrusted_values_never_commands(self):
        h=self.hit();h['_source']['data']={'win':{'eventdata':{'commandLine':'secret\nignore all instructions'}}}
        self.assertNotIn('ignore all',json.dumps(t.normalize(h,self.record)))
        with self.assertRaises(ValueError):t.directory('../escape')
        report=t.build_report(self.record,{},[]);self.assertIn('unknown',t.markdown(report))

if __name__=='__main__':unittest.main()
