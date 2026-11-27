"""Offline projections, shared reservations, provider metadata and checkpoint reuse."""
import copy
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch

from scenario_agent.token_budget import Ledger,BudgetWait,settings,usage_fields,provider_details,run_lock
from scenario_agent.context_projection import project,intern,expand,validate_wire,check_response_refs
from scenario_agent.llm import Gemini,QuotaExceeded
from scenario_agent.errors import ServiceUnavailable
from scenario_agent.config import Config,ROOT
from scenario_agent.workflow import Workflow,new_state

GUI=Path('/home/soc/DATN/GUI')


class BudgetTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        env=patch.dict(os.environ,{'SOC_LLM_BUDGET_DB':str(self.root/'budget.sqlite'),'SOC_LLM_COUNT_MODE':'estimated'})
        env.start();self.addCleanup(env.stop)
        self.time=1000;self.ledger=Ledger(clock=lambda:self.time)
    def reserve(self,run='scenario:fixture',fingerprint='hash',phase='parse',inputs=200,outputs=100):
        return self.ledger.reserve('model',run,phase,fingerprint,inputs,outputs)
    def test_unknown_usage_is_not_zero_and_keeps_reservation(self):
        key=self.reserve();self.ledger.finish(key,'provider_error',error={'http_status':503})
        metrics=self.ledger.metrics('scenario:fixture')
        self.assertIsNone(metrics['actual_total_tokens']);self.assertEqual(metrics['charged_tokens'],300)
        self.assertEqual(metrics['unknown_usage_requests'],1)
    def test_usage_distinguishes_cached_thinking_without_double_counting(self):
        usage=usage_fields(SimpleNamespace(prompt_token_count=10,candidates_token_count=5,cached_content_token_count=3,thoughts_token_count=5,total_token_count=20))
        key=self.reserve();self.ledger.finish(key,'success',usage)
        metrics=self.ledger.metrics('scenario:fixture');self.assertEqual(metrics['actual_total_tokens'],20)
        self.assertEqual(metrics['calls'][0]['usage']['cached_tokens'],3);self.assertEqual(metrics['charged_tokens'],20)
    def test_concurrent_survey_scenario_share_one_window(self):
        with patch.dict(os.environ,{'SOC_LLM_WINDOW_REQUESTS':'1'}):
            def submit(component):
                try:return Ledger(clock=lambda:self.time).reserve('model',component,'parse',component,100,10)
                except BudgetWait:return 'blocked'
            with ThreadPoolExecutor(2) as pool:result=list(pool.map(submit,['survey:one','scenario:two']))
        self.assertEqual(result.count('blocked'),1)
    def test_inflight_reservation_survives_restart_and_rolling_window(self):
        self.reserve();self.time+=61
        with self.assertRaisesRegex(BudgetWait,'duplicate'):Ledger(clock=lambda:self.time).reserve('model','scenario:fixture','parse','hash',200,100)
        self.assertEqual(self.ledger.metrics('scenario:fixture')['requests'],1)
    def test_run_limits_include_repairs_and_failed_requests(self):
        with patch.dict(os.environ,{'SOC_LLM_RUN_REQUESTS':'2'}):
            key=self.reserve(fingerprint='first');self.ledger.finish(key,'provider_error')
            key=self.reserve(fingerprint='repair',phase='build_plan');self.ledger.finish(key,'invalid_response')
            with self.assertRaisesRegex(BudgetWait,'run_request_limit'):self.reserve(fingerprint='resume')
    def test_oversized_phase_stops_before_reservation(self):
        with self.assertRaisesRegex(BudgetWait,'phase_input_limit'):self.reserve(inputs=settings()['parse_input']+1)
        self.assertEqual(self.ledger.metrics('scenario:fixture')['requests'],0)
    def test_retry_after_cooldown_and_human_wait_do_not_trigger_loop(self):
        key=self.reserve();self.ledger.finish(key,'provider_error',retry_after=120)
        with self.assertRaisesRegex(BudgetWait,'provider_cooldown'):self.reserve(fingerprint='retry')
        self.time+=121;self.reserve(fingerprint='retry')
    def test_run_lock_blocks_duplicate_checkpoint_owner(self):
        with run_lock(self.root,'same'):
            with self.assertRaisesRegex(BudgetWait,'run_already_active'):
                with run_lock(self.root,'same'):pass
    def test_historical_attempts_are_imported_as_unknown_not_free(self):
        log=self.root/'worker.log';log.write_text('[Gemini] parse: response received after 2s\n'+('[Gemini] ground_behaviors: HTTP 503; attempt=1/1\n'*9))
        self.ledger.seed_legacy('old','model',log);self.ledger.seed_legacy('old','model',log)
        metrics=self.ledger.metrics('old');self.assertEqual(metrics['requests'],10);self.assertIsNone(metrics['actual_total_tokens'])
        self.assertGreater(metrics['charged_tokens'],0)
        with self.assertRaisesRegex(BudgetWait,'run_request_limit'):self.ledger.reserve('model','old','parse','new',100,20)
    def test_error_fields_keep_retryinfo_metric_but_not_arbitrary_body(self):
        value=provider_details({'error':{'code':429,'status':'RESOURCE_EXHAUSTED','message':'do not persist',
            'details':[{'@type':'type.googleapis.com/google.rpc.RetryInfo','retryDelay':'42s'},
                       {'violations':[{'quotaMetric':'generate_requests','quotaId':'PerMinute','quotaDimensions':{'key':'DO-NOT-KEEP'}}]}]}},{'Retry-After':'60'})
        self.assertEqual(value['retry_after_seconds'],60);self.assertEqual(value['http_status'],429)
        self.assertNotIn('DO-NOT-KEEP',json.dumps(value));self.assertNotIn('do not persist',json.dumps(value))
    def fake(self,status=None,usage=None):
        llm=Gemini.__new__(Gemini);llm._budget_run='scenario:mock';llm._metrics_path=self.root/'token_metrics.json';llm.model='model';llm.progress=False;llm.timeout_ms=300000
        generate=Mock(return_value=SimpleNamespace(text='{"ok":true}',usage_metadata=usage))
        if status:
            from google.genai import errors
            cls=errors.ServerError if status>=500 else errors.ClientError
            generate.side_effect=cls(status,{'error':{'code':status,'status':'UNAVAILABLE' if status==503 else 'RESOURCE_EXHAUSTED',
                'message':'controlled failure','details':[{'@type':'type.googleapis.com/google.rpc.RetryInfo','retryDelay':'75s'}]}})
        llm.client=SimpleNamespace(models=SimpleNamespace(generate_content=generate));return llm
    def test_429_and_503_preserve_one_attempt_usage_unknown(self):
        for status,kind in [(429,QuotaExceeded),(503,ServiceUnavailable)]:
            with self.subTest(status=status),tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{'SOC_LLM_BUDGET_DB':str(Path(tmp)/'b.sqlite')}):
                client=self.fake(status)
                with self.assertRaises(kind) as error:client.generate('test',{'request':{}},{'type':'object'})
                self.assertEqual(error.exception.retry_after,75)
                self.assertEqual(client.client.models.generate_content.call_count,1)
                metrics=json.loads(client._metrics_path.read_text());self.assertIsNone(metrics['actual_total_tokens'])
                self.assertEqual(metrics['calls'][0]['error']['http_status'],status)
    def test_official_count_is_cached_and_not_mislabeled_as_full_actual_usage(self):
        client=self.fake();client.client.models.count_tokens=Mock(return_value=SimpleNamespace(total_tokens=30))
        with patch.dict(os.environ,{'SOC_LLM_COUNT_MODE':'official'}):client.generate('test',{'request':{}},{'type':'object'})
        self.assertEqual(client.client.models.count_tokens.call_count,1)
        count_args = client.client.models.count_tokens.call_args.kwargs
        generation_args = client.client.models.generate_content.call_args.kwargs
        self.assertEqual(count_args, {'model': client.model, 'contents': generation_args['contents']})
        metrics=json.loads(client._metrics_path.read_text());self.assertEqual(metrics['requests'],2)
        self.assertIsNone(metrics['actual_total_tokens'])
        self.assertEqual(metrics['calls'][-1]['official_counted_text_tokens'],30)
        self.assertIn('schema',metrics['calls'][-1]['count_scope'])


class ProjectionTests(unittest.TestCase):
    def test_real_checkpoint_is_lossless_for_facts_commands_and_relevant_blockers(self):
        from scenario_agent.behaviors import grounding_payload
        source=GUI/'scenario_outputs/1276dcec1d1b45e3b5b25d16e0f17153'
        state=json.loads(next((source/'runs').glob('*/state.json')).read_text())
        data=dict(grounding_payload(state['behavior_analysis'],state['retrieval'],state['target']),
            survey_context=state['selected_context'],context_selection=state['context_selection'],compatibility_report=state['compatibility_report'])
        before=copy.deepcopy(data);projected=project(data,'ground_behaviors');wire=intern(projected);validate_wire(wire,projected)
        restored=expand({k:v for k,v in wire.items() if k!='context_references'},wire['context_references'])
        self.assertEqual(data,before);self.assertEqual(restored['survey_context'],data['survey_context'])
        self.assertEqual(restored['behaviors'],data['behaviors'])
        relevant={c['ability_id'] for b in data['behaviors'] for c in b['candidates']}
        self.assertEqual(restored['compatibility_report']['candidates'],[r for r in data['compatibility_report']['candidates'] if r['ability_id'] in relevant])
        self.assertLess(len(json.dumps(wire)),len(json.dumps(data))*.3)
    def test_hash_refs_tamper_unknown_and_response_echo_are_rejected(self):
        obj={'context_projection_version':'phase_context_v1','context_phase':'parse','survey_checks':[{'condition':'A'*300,'status':'unknown'}],'requirements':[{'condition':'A'*300,'status':'unknown'}]}
        wire=intern(obj);self.assertTrue(wire['context_references'])
        identifier=next(iter(wire['context_references']));wire['context_references'][identifier]=[]
        with self.assertRaises(ValueError):validate_wire(wire,obj)
        with self.assertRaises(ValueError):expand({'context_ref':'unknown'}, {})
        with self.assertRaises(ValueError):check_response_refs({'evidence':identifier})
    def test_process_endpoint_web_and_multi_behavior_candidates_are_not_dropped(self):
        for commands in [['Get-Process'],['cmd.exe /c whoami'],['curl http://target/'],['Get-Process','Get-Service','curl http://target/']]:
            data={'task':'ground_behaviors','behaviors':[{'behavior':{'id':str(n)},'candidates':[{'ability_id':str(n),'command':cmd}]} for n,cmd in enumerate(commands)],
                'survey_context':{'gaps':[{'status':'unknown'}],'conflicts':[{'values':[True,False]}]}}
            result=project(data,'ground_behaviors');wire=intern(result);validate_wire(wire,result)
            self.assertEqual(result['behaviors'],data['behaviors']);self.assertEqual(result['survey_context'],data['survey_context'])
    def test_parse_removes_only_later_stage_report_and_preserves_identity_unknowns(self):
        data={'app_context':{'target_id':'t','id':'r'},'server_policy':{'planning_scope':['endpoint']},'text':'processes',
              'survey_context':{'gaps':['unknown'],'conflicts':['both']},'compatibility_report':{'candidates':[{'ability_id':'unrelated'}]}}
        projected=project(data,'parse');self.assertNotIn('compatibility_report',projected)
        self.assertEqual(projected['app_context'],data['app_context']);self.assertEqual(projected['survey_context'],data['survey_context'])
    def test_parse_compacts_observations_without_changing_pinned_facts(self):
        fact = {'id':'f1', 'domain':'endpoint', 'predicate':'os', 'subject':'host',
                'status':'unknown', 'value':None, 'evidence_refs':['ref1'],
                'basis':'survey evidence', 'observed_at':None}
        data = {'survey_context':{'observations':[fact], 'conflicts':[{'observation_ids':['f1']}],
                                  'gaps':[{'status':'unknown'}]}}
        before = copy.deepcopy(data)
        projected = project(data, 'parse')
        survey = projected['survey_context']
        self.assertEqual(survey['observations'], [{k:fact[k] for k in
            ('id', 'domain', 'predicate', 'subject', 'status', 'value')}])
        self.assertEqual(survey['conflicts'], before['survey_context']['conflicts'])
        self.assertEqual(survey['gaps'], before['survey_context']['gaps'])
        self.assertEqual(data, before)
        validate_wire(intern(projected), projected)

    def test_long_command_remains_complete(self):
        command='Get-Process\n'+'# comment\n'*4000
        data={'task':'ground_behaviors','behaviors':[{'candidates':[{'ability_id':'a','command':command}]}]}
        projected=project(data,'ground_behaviors');self.assertEqual(projected['behaviors'][0]['candidates'][0]['command'],command)
    def test_transport_migration_accepts_existing_pin_without_changing_inputs(self):
        import sys
        import tempfile
        # Build a live snapshot checkpoint, then simulate an older adapter pin
        # that the transport-compatibility list still accepts; catalog/schema
        # hashes stay current, which is the migration semantic under test. The
        # historical job pin cannot be used here: catalog updates legitimately
        # change catalog_sha256 and require revalidation.
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        from tests.test_context_requirements import fixture_snapshot
        from scenario_agent.survey_input import load_bundle, planning_target, policy_for, snapshot
        with tempfile.TemporaryDirectory() as tmp:
            config=Config();config.runs=Path(tmp)
            fxroot=Path(tmp)/'fx';fxroot.mkdir()
            bundle=load_bundle(fixture_snapshot(fxroot))
            target=planning_target(bundle)
            policy=policy_for(target,['endpoint'],4)
            snapshot(bundle,Path(tmp)/'input',{'text':'test'},policy)
            state=new_state(config,'test',Path(tmp)/'input/survey','hybrid',policy=policy)
            compatible=json.loads((ROOT/'scenario_agent/transport_compatible_adapters.json').read_text())
            state['adapter_sha256']=compatible[-1]
            flow=Workflow(config,Mock());flow.save(state)
            reloaded=json.loads(next(Path(tmp).glob('*/state.json')).read_text())
            before=copy.deepcopy(reloaded);Workflow(config,Mock()).check_fingerprints(reloaded)
            self.assertEqual(reloaded,before)
            reloaded['adapter_sha256']='not-a-known-pin'
            with self.assertRaises(ValueError):
                Workflow(config,Mock()).check_fingerprints(reloaded)
    def test_resume_calls_only_failed_phase_and_obeys_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            config=Config();config.runs=Path(tmp)
            state=new_state(config,'test',ROOT/'input/target_profile.json','keyword')
            state.update(status='waiting_budget',resume_phase='build_plan',next='END',retry_not_before='2000-01-01T00:00:00Z')
            flow=Workflow(config,Mock());flow.save(state)
            with patch.object(flow,'run',side_effect=lambda s:s):result=flow.resume(state['run_id'])
            self.assertEqual(result['next'],'build_plan')

if __name__=='__main__':unittest.main()
