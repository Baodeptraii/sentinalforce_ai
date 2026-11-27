"""General requirement matrix. Synthetic observations are explicitly labeled fixtures.
Real catalog commands are inspected, never executed. All generation is mocked.
"""
import copy
import json
import sys
import tempfile
import unittest
from unittest.mock import Mock
from pathlib import Path
from unittest.mock import patch
from scenario_agent.catalog import connect, ability
from scenario_agent.config import Config, write_json
from scenario_agent.survey_input import load_bundle, policy_for, planning_target, canonical
from scenario_agent.requirement_registry import build_registry, evaluate_requirements, source_analysis
from scenario_agent.target_evidence import select_context, assess_candidates, catalog_handles, validate_evidence_plan
from scenario_agent.workflow import Workflow, new_state
from test_scenario_agent import fixture_request

GUI = Path('/home/soc/DATN/GUI')
sys.path.insert(0, str(GUI))
from engine.runner import save
from engine.survey_output_v2 import convert

PROCESS = '94f21386-9547-43c4-99df-938ab05d45ce'
POST = 'a1b2c3d4-dvwa-0003-cmdi-000000000003'
DEPENDENCY = 'cc191baa-7472-4386-a2f4-42f203f1acfd'
MIXED = 'Liệt kê process và kiểm tra command injection trên ứng dụng web để đánh giá SOC.'


def get_record(identifier):
    with connect(Config().catalog) as db: return ability(db, identifier)


def fixture_snapshot(root, ip='192.0.2.77', port=8448, first='/alpha/', second='/beta/'):
    """Synthetic fixture, not claims about lab machines; normal producer creates its bundle."""
    source = root/'synthetic-source'; source.mkdir()
    save(source/'survey_request.json', {'target_ip':ip,'survey_scope':['endpoint','web']})
    save(source/'target_profile.json', {'id':'SYNTHETIC-TARGET','address':ip,
        'os':{'name':'Windows Fixture','version':None,'architecture':'64-bit','hostname':'fixture','status':'observed'},
        'services':[],'capabilities':{'sandcat_online':True,'powershell_ready':True,'admin_ready':False,'web_runner_ready':True,'web_reachable':True},'telemetry':{}})
    stamp = '2020-02-03T04:05:06Z'
    save(source/'01_agent.json', {'paw':'SYNTHETIC-RUNNER','executors':['psh','cmd'],'privilege':'User','last_seen':stamp,'platform':'windows'})
    save(source/'02_endpoint.json', {'data':{'os_name':'Windows Fixture','architecture':'64-bit','hostname':'fixture','is_elevated':False,
        'collected_at':stamp,'listeners':[],
        'processes':[{'pid':42,'name':'WidgetSvc.exe','executable_path':r'C:\Apps\WidgetSvc.exe'}, {'pid':43,'name':'Other.exe','executable_path':r'C:\Apps\Other.exe'}],
        'services':[{'name':'WidgetSvc','display_name':'Widget Fixture','state':'Running','process_id':42}],
        'resources': [{'path':r'C:\uncollected-acl','exists':None}],
        'telemetry_observations':{'process_events':{'kind':'sysmon_event_1','event_id':1,'event_time':stamp},
                                  'web_access_logs':{'kind':'apache_access_entry','event_time':stamp,'location':'shared-access.log'}}}})
    for i, (path, method, names, level, csrf) in enumerate([(first,'GET',['id','Submit'],'low',False),(second,'POST',['ip','Submit'],'high',True)]):
        save(source/f'tool_{i+1:02d}_application.json', {'tool':'fixture_web_metadata','target_ip':ip,'status':'ok','data':{'authentication':{
            'base_url':f'http://{ip}:{port}'+path,'checked_at':stamp,'session_ready':True,'status':'verified','current_security_level':level,
            'modules':[{'path':'action/','http_status':200,'authenticated':True,'forms':[{'method':method,'action_path':'',
                       'inputs':[{'name':n,'type':'text'} for n in names], 'csrf_present':csrf}]}]}}})
    save(source/'report.json', {'status':'completed_with_unknowns','finished_at':stamp,'warnings':['SYNTHETIC FIXTURE — never collected from a real target']})
    dest = root/'synthetic-bundle';convert(source,dest)
    return dest


def synthetic_record(command, parameters=(), privilege=None, name='SYNTHETIC source contract'):
    """Not in catalog; only used to cover unsupported/multi-app contracts."""
    return {'canonical_id':'SYNTHETIC-ABILITY','ability':{'name':name,'privilege':privilege,'requirements':[],
            'executors':[{'platform':'windows','name':'psh','command':command,'fact_placeholders':list(parameters),'payloads':[],'cleanup':[]}]},
            'provenance':{'kind':'caldera_ability','id':'SYNTHETIC-ABILITY','location':'fixture://contract','revision':'fixture'}}


class GeneralRequirementTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.bundle_path=fixture_snapshot(self.root)
        self.bundle=load_bundle(self.bundle_path)
        self.env={k:v for k,v in self.bundle.items() if k!='_contents'}
        self.env['policy']=policy_for(planning_target(self.bundle),['endpoint','web'],4)
        self.env['_fact_registry']=build_registry(self.env, contents=self.bundle['_contents'])

    def assess(self, record, text='Review source behavior'):
        ex=next(e for e in record['ability']['executors'] if e['platform']=='windows')
        return evaluate_requirements(record,ex,self.env,{'text':text})

    def test_real_process_ability_expands_attested_inventory_and_process_telemetry(self):
        report=self.assess(get_record(PROCESS),'Enumerate process')
        req=next(r for r in report['requirements'] if r['kind']=='endpoint.process_inventory')
        self.assertTrue(any(i.startswith('derived-') for i in req['fact_ids']))
        telemetry=next(r for r in report['requirements'] if r['kind']=='telemetry.process')
        self.assertTrue(telemetry['fact_ids'])
        selected,selection=select_context(self.env,'Enumerate process',['endpoint'],assessments={'candidates':[report]})
        self.assertEqual(selection['required_but_unselected'],[])
        self.assertTrue(any(f['predicate']=='inventory' for f in selected['observations']))
        self.assertTrue(any(row['requirement_links'] for row in selection['included']))
        self.assertEqual(report['compatibility'],'needs_information')

    def test_unique_resource_parameter_binding_and_ambiguous_resource(self):
        record=synthetic_record('Get-Item "#{file_path}"; Get-Process -Name "#{process_name}"', ['file_path','process_name'])
        resolved=self.assess(record,'Inspect WidgetSvc.exe process path')
        self.assertEqual(resolved['bindings']['file_path']['value'],r'C:\Apps\WidgetSvc.exe')
        self.assertEqual(resolved['bindings']['process_name']['value'],'WidgetSvc.exe')
        self.assertTrue(resolved['bindings']['file_path']['fact_ids'][0].startswith('derived-'))
        ambiguous=self.assess(record,'Inspect a process path')
        self.assertIsNone(ambiguous['bindings']['file_path']['value'])
        self.assertTrue(any(r['status']=='ambiguous' for r in ambiguous['requirements']))

    def test_listener_port_binding_uses_target_listener_not_application_port(self):
        env=copy.deepcopy(self.env)
        # Explicit synthetic listener fact for this resolver-only test (not a live observation).
        fact=copy.deepcopy(next(f for f in env['_fact_registry']['observations'] if f['predicate']=='os_name'))
        fact.update(id='fixture-listener',predicate='listener',subject='9123',value={'listener':{'LocalPort':9123,'OwningProcess':42},'processes':[],'services':[]})
        env['_fact_registry']['observations'].append(fact)
        record=synthetic_record('nmap -p #{remote.host.port} #{remote.host.ip}', ['remote.host.port','remote.host.ip'])
        report=evaluate_requirements(record,record['ability']['executors'][0],env,{'text':'Inspect port 9123'})
        self.assertEqual(report['bindings']['remote.host.port']['value'],'9123')
        self.assertNotEqual(report['bindings']['remote.host.port']['value'],'8448')
        self.assertTrue(any(r['kind']=='endpoint.listener' for r in report['requirements']))
        network=next(r for r in report['requirements'] if r['kind']=='telemetry.network')
        self.assertEqual(network['status'],'unknown')

    def test_named_service_state_is_selected_without_broadcasting_inventory(self):
        report=self.assess(synthetic_record('Get-Service -Name "WidgetSvc"'),'Check service')
        rows=[r for r in report['requirements'] if r['kind']=='endpoint.service_inventory' and r['subject']=='WidgetSvc']
        self.assertTrue(rows[0]['fact_ids'])
        facts={f['id']:f for f in self.env['_fact_registry']['observations']}
        self.assertEqual(facts[rows[0]['fact_ids'][0]]['value']['state'],'Running')
        self.assertFalse(any(r['kind']=='telemetry.web' for r in report['requirements']))

    def test_real_dependency_and_privilege_have_explicit_gaps(self):
        dep=self.assess(get_record(DEPENDENCY),'Enumerate processes with required dependency')
        self.assertTrue(any(r['kind']=='catalog.dependency' and r['status']=='unknown' for r in dep['requirements']))
        self.assertTrue(any(r['kind']=='endpoint.path' for r in dep['requirements']))
        record=synthetic_record('Get-Service',privilege='administrator')
        elevated=self.assess(record)
        self.assertEqual(elevated['compatibility'],'incompatible')
        self.assertIn('required_privilege_not_observed',elevated['reasons'])

    def test_architecture_alias_and_unknown_are_not_conflated_with_mismatch(self):
        record=synthetic_record('Get-Process')
        record['ability']['executors'][0]['architecture']='amd64'
        self.assertNotIn('executor_architecture_mismatch',self.assess(record)['reasons'])
        record['ability']['executors'][0]['architecture']='x86'
        self.assertIn('executor_architecture_mismatch',self.assess(record)['reasons'])
        for f in self.env['_fact_registry']['observations']:
            if f['predicate']=='architecture': f.update(value=None,status='unknown')
        self.assertNotIn('executor_architecture_mismatch',self.assess(record)['reasons'])

    def test_unsupported_network_construct_is_manual_review_not_false_endpoint_classification(self):
        record=synthetic_record('requests.get("#{base_url}")',['base_url'])
        self.env['policy']['planning_scope']=['web']
        report=self.assess(record,'Review web request')
        self.assertNotIn('endpoint_command_outside_planning_scope',report['reasons'])
        self.assertTrue(any(r['subject']=='source.network_construct' and r['status']=='unsupported' for r in report['requirements']))
        self.assertEqual(report['compatibility'],'needs_information')

    def test_literal_url_assignment_cannot_hide_host_constraint_behind_variable(self):
        record=synthetic_record('$Origin = "http://198.51.100.123:8448/alpha"\ncurl.exe "$Origin/action/"')
        report=self.assess(record,'Check http://192.0.2.77:8448/alpha/')
        self.assertIn('unapproved_external_or_fixed_host',report['reasons'])
        hidden=synthetic_record('$target = "198.51.100.123"\ncurl.exe "http://$target:8448/alpha/action/"')
        self.assertIn('unapproved_external_or_fixed_host',self.assess(hidden,'Check http://192.0.2.77:8448/alpha/')['reasons'])
        unresolved=self.assess(synthetic_record('curl.exe "$Unbound/action/"'),'Check http://192.0.2.77:8448/alpha/')
        self.assertTrue(any('Source URL variable' in b for b in unresolved['blockers']))

    def test_application_associations_do_not_mix_same_suffix_auth_method_or_csrf(self):
        # Source uses a variable + fallback, different app roots and one shared endpoint suffix.
        record=synthetic_record('$AppUrl = if ($env:APP_URL) { $env:APP_URL } else { "http://127.0.0.1:80/beta" }\n'
             'curl.exe -s -b "$SessionFile" -d "ip=fixture&Submit=Submit" "$AppUrl/action/"')
        report=self.assess(record,'Review application POST action')
        self.assertEqual(report['environment_bindings']['APP_URL']['value'],'http://192.0.2.77:8448/beta')
        ids=set(report['supporting_fact_ids']);facts={f['id']:f for f in self.env['_fact_registry']['observations']}
        self.assertTrue(any(r['kind']=='web.csrf' and r['status']=='unknown' for r in report['requirements']))
        self.assertTrue(any(r['kind']=='web.request' and r['expected']['method']=='POST' for r in report['requirements']))
        self.assertFalse(any('/alpha/' in facts[i]['subject'] for i in ids))
        # Other app's low session must not override beta/high.
        ex=record['ability']['executors'][0];ex['command']=ex['command'].replace('-s -b','-s -b "security=low" -b')
        mismatch=self.assess(record)
        self.assertIn('observed_security_level_mismatch',mismatch['reasons'])
        webtelemetry=next(r for r in report['requirements'] if r['kind']=='telemetry.web')
        self.assertFalse(webtelemetry['fact_ids'])
        self.assertEqual(webtelemetry['status'],'unknown')

    def test_two_apps_inside_one_source_keep_separate_environment_associations(self):
        record=synthetic_record('$A = if ($env:A_URL) { $env:A_URL } else { "http://127.0.0.1/alpha" }\n'
             '$B = if ($env:B_URL) { $env:B_URL } else { "http://127.0.0.1/beta" }\n'
             'curl.exe "$A/action/?id=fixture&Submit=Submit"\n'
             'curl.exe -d "ip=fixture&Submit=Submit" "$B/action/"')
        report=self.assess(record,'Review both application actions')
        self.assertTrue(report['environment_bindings']['A_URL']['value'].endswith('/alpha'))
        self.assertTrue(report['environment_bindings']['B_URL']['value'].endswith('/beta'))
        requests=[r for r in report['requirements'] if r['kind']=='web.request']
        self.assertEqual({r['expected']['method'] for r in requests},{'GET','POST'})
        self.assertEqual(len({r['expected']['application'] for r in requests}),2)
        # Resolver-only synthetic telemetry: an app A log must never establish app B availability.
        fact=copy.deepcopy(next(f for f in self.env['_fact_registry']['observations'] if f['predicate']=='local_event'))
        fact.update(id='fixture-app-a-log',predicate='local_event',value={'kind':'apache_access_entry','url':'http://192.0.2.77:8448/alpha/action/'})
        self.env['_fact_registry']['observations'].append(fact)
        report=self.assess(record,'Review both application actions')
        telemetry={r['subject']:r for r in report['requirements'] if r['kind']=='telemetry.web'}
        self.assertIn('fixture-app-a-log',telemetry['http://192.0.2.77:8448/alpha/']['fact_ids'])
        self.assertEqual(telemetry['http://192.0.2.77:8448/beta/']['fact_ids'],[])
        self.assertEqual(telemetry['http://192.0.2.77:8448/beta/']['status'],'unknown')

    def test_multi_application_ambiguity_never_defaults_first(self):
        report=self.assess(synthetic_record('curl.exe "#{base_url}/action/"',['base_url']))
        self.assertIsNone(report['bindings']['base_url']['value'])
        self.assertTrue(any(r['status']=='ambiguous' for r in report['requirements']))
        self.assertFalse(any(r['kind']=='web.authentication' for r in report['requirements']))

    def test_typed_url_and_module_parameters_preserve_source_join_semantics(self):
        record=synthetic_record('curl.exe "#{base_url}/#{module_path}?id=fixture&Submit=Submit"', ['base_url','module_path'])
        report=self.assess(record,'GET http://192.0.2.77:8448/alpha/')
        self.assertEqual(report['bindings']['base_url']['value'],'http://192.0.2.77:8448/alpha')
        self.assertEqual(report['bindings']['module_path']['value'],'action/')
        self.assertEqual(report['bindings']['base_url']['transform'],'remove_trailing_slash_for_source_suffix')
        self.assertTrue(report['bindings']['module_path']['fact_ids'])
        module=next(r for r in report['requirements'] if r['kind']=='web.request')
        self.assertEqual(module['subject'],'http://192.0.2.77:8448/alpha/action/')
        self.assertEqual(module['expected']['parameter_names'],['Submit','id'])
        wrong=synthetic_record('curl.exe "#{base_url}/action/?unsupported=fixture"',['base_url'])
        self.assertIn('observed_form_parameter_mismatch',self.assess(wrong,'GET http://192.0.2.77:8448/alpha/')['reasons'])

    def test_separate_scheme_ip_port_parameters_are_projected_without_rewriting_command(self):
        command='curl.exe "#{scheme}://#{target_ip}:#{port}/alpha/action/?id=fixture&Submit=Submit"'
        record=synthetic_record(command,['scheme','target_ip','port'])
        report=self.assess(record,'GET http://192.0.2.77:8448/alpha/')
        self.assertEqual({k:v['value'] for k,v in report['bindings'].items()}, {'scheme':'http','target_ip':'192.0.2.77','port':'8448'})
        self.assertNotIn('hardcoded_origin_or_port_mismatch',report['reasons'])
        self.assertEqual(record['ability']['executors'][0]['command'],command)

    def test_method_parameters_and_dynamic_body_are_checked_per_call(self):
        fixed='http://192.0.2.77:8448/alpha/action/'
        report=self.assess(synthetic_record('curl.exe -d "ip=fixture" "'+fixed+'"'))
        self.assertIn('observed_form_method_mismatch',report['reasons'])
        unknown=self.assess(synthetic_record('Invoke-WebRequest -Method POST -Body $body -Uri "http://192.0.2.77:8448/beta/action/"'))
        req=next(r for r in unknown['requirements'] if r['kind']=='web.request')
        self.assertEqual(req['status'],'unknown')
        self.assertTrue(any('method/body' in b for b in unknown['blockers']))

    def test_plain_http_evidence_does_not_require_dvwa_or_invent_form_and_auth(self):
        source=self.root/'http-only-source';source.mkdir()
        for name in ('survey_request.json','target_profile.json','02_endpoint.json','01_agent.json','report.json'):
            (source/name).write_bytes((self.root/'synthetic-source'/name).read_bytes())
        save(source/'tool_01_http.json',{'tool':'probe_web','status':'ok','target_ip':'192.0.2.77','data':{'requests':[
            {'requested_url':'http://192.0.2.77:8448/public/health','url':'http://192.0.2.77:8448/public/health','http_status':200,'checked_at':'2020-02-03T04:05:06Z'}]}})
        path=self.root/'http-only-bundle';convert(source,path);bundle=load_bundle(path)
        env={k:v for k,v in bundle.items() if k!='_contents'};env['policy']=self.env['policy']
        env['_fact_registry']=build_registry(env,contents=bundle['_contents'])
        record=synthetic_record('curl.exe "http://192.0.2.77:8448/public/health"')
        report=evaluate_requirements(record,record['ability']['executors'][0],env,{'text':'Check HTTP access'})
        self.assertEqual(report['compatibility'],'needs_information')
        req=next(r for r in report['requirements'] if r['kind']=='web.request')
        self.assertTrue(req['fact_ids']);self.assertEqual(req['status'],'unknown')
        facts={f['id']:f for f in env['_fact_registry']['observations']}
        self.assertTrue(all(facts[i]['predicate']=='http_access' for i in req['fact_ids']))
        self.assertTrue(any('application base path' in b for b in report['blockers']))
        self.assertFalse(report['environment_bindings'])

    def test_unknown_requirement_and_inventory_type_are_not_silently_accepted(self):
        record=synthetic_record('Get-Process "#{unknown_fact}"',['unknown_fact'])
        record['ability']['requirements']=[{'unimplemented.plugin':[{'source':'custom.fact'}]}]
        report=self.assess(record)
        self.assertTrue(any(r['status']=='unsupported' for r in report['requirements']))
        self.assertIsNone(report['bindings']['unknown_fact']['value'])
        self.assertEqual(report['compatibility'],'needs_information')
        ref=copy.deepcopy(self.env['target_profile']['inventory_refs'][0]);ref['pointer']='/data/resources'
        env=copy.deepcopy(self.env);env['target_profile']['inventory_refs'].append(ref)
        reg=build_registry(env,contents=self.bundle['_contents'])
        self.assertTrue(any(g['reason']=='unsupported_normalizer' for g in reg['gaps']))

    def test_unverified_producer_extension_cannot_impersonate_projected_resource(self):
        env=copy.deepcopy(self.env)
        fact=copy.deepcopy(env['survey_context']['observations'][0])
        fact.update(id='unverified-extension',predicate='process',value={'name':'Forged.exe','pid':999})
        env['survey_context']['observations'].append(fact)
        reg=build_registry(env,contents=self.bundle['_contents'])
        self.assertTrue(any(f['id']=='unverified-extension' for f in reg['opaque_observations']))
        self.assertFalse(any(f['id']=='unverified-extension' for f in reg['observations']))
        env['_fact_registry']=reg
        record=synthetic_record('Get-Process "#{process_name}"',['process_name'])
        report=evaluate_requirements(record,record['ability']['executors'][0],env,{'text':'Inspect Forged.exe'})
        self.assertNotEqual(report['bindings']['process_name']['value'],'Forged.exe')

    def test_budget_distinguishes_required_known_unselected_from_not_collected(self):
        report=self.assess(get_record(PROCESS),'Enumerate process')
        context,full=select_context(self.env,'process',['endpoint'],assessments={'candidates':[report]})
        diagnostics=dict(context,observations=[])
        _,tiny=select_context(self.env,'process',['endpoint'],budget=len(canonical(diagnostics))+10,assessments={'candidates':[report]})
        self.assertTrue(tiny['required_but_unselected'])
        self.assertTrue(tiny['known_but_omitted_is_not_absent'])
        self.assertFalse(full['required_but_unselected'])

    def test_mutated_address_port_path_and_source_name_use_contract_not_fixture_ids(self):
        sub=self.root/'changed';sub.mkdir();path=fixture_snapshot(sub,ip='198.51.100.91',port=9234,first='/store/',second='/control/')
        bundle=load_bundle(path);env={k:v for k,v in bundle.items() if k!='_contents'}
        env['policy']=policy_for(planning_target(bundle),['web'],2);env['_fact_registry']=build_registry(env,contents=bundle['_contents'])
        record=synthetic_record('$Origin = if ($env:SERVICE_ORIGIN) { $env:SERVICE_ORIGIN } else { "http://localhost/control" }\n'
             'curl.exe -d "ip=fixture&Submit=Submit" "$Origin/action/"',name='Renamed generic ability')
        report=evaluate_requirements(record,record['ability']['executors'][0],env,{'text':'POST action'})
        self.assertEqual(report['environment_bindings']['SERVICE_ORIGIN']['value'],'http://198.51.100.91:9234/control')
        self.assertNotIn('hardcoded_origin_or_port_mismatch',report['reasons'])

    def test_conflict_and_negative_evidence_not_erased_during_expansion(self):
        fact=next(f for f in self.env['_fact_registry']['observations'] if f['predicate']=='is_elevated')
        self.env['survey_context']['conflicts'].append({'observation_ids':[fact['id']]})
        report=self.assess(synthetic_record('Get-Service',privilege='administrator'))
        self.assertTrue(any(r['status']=='conflicting' for r in report['requirements']))
        selected,selection=select_context(self.env,'service',['endpoint'],assessments={'candidates':[dict(report,compatibility='needs_information')]})
        self.assertTrue(any(f['value'] is False for f in selected['observations']))
        self.assertTrue(selected['conflicts'])


class MixedMock:
    def __init__(self): self.payloads=[]
    def generate(self,instruction,payload,schema):
        self.payloads.append(copy.deepcopy(payload))
        if 'catalog_reference_context' in payload:
            request=fixture_request({'request_id':payload['app_context']['id'],'text':payload['text'],'target':payload['target']})
            request.update(objective='Process enumeration and web command injection assessment',scope=['endpoint','web'],requested_techniques=[],max_tests=4)
            request['internal_behavior_analysis']={'ordered':False,'behaviors':[
                {'description':'Enumerate process','source_quote':'Liệt kê process','query_en':'process enumeration','keywords':['process']},
                {'description':'Command injection','source_quote':'kiểm tra command injection','query_en':'web command injection','keywords':['injection']}]}
            return request
        if payload.get('task')=='ground_behaviors':
            coverage=[]
            for group,identifier in zip(payload['behaviors'],[PROCESS,POST]):
                candidate=next(c for c in group['candidates'] if c['ability_id']==identifier)
                # Quote a real complete source command; no command is executed or synthesized.
                coverage.append({'behavior_id':group['behavior']['id'],'reason':'Real source command supports fixture behavior',
                    'matches':[{'ability_id':identifier,'platform':'windows','executor':'psh','command_quote':candidate['command']}]})
            return {'coverage':coverage,'unmodeled_requirements':[]}
        records={a['record']['canonical_id']:a['record'] for a in payload['retrieval']['abilities']}
        steps=[];sources=[];blockers=[]
        for index,identifier in enumerate([PROCESS,POST],1):
            record=records[identifier];sources.append(record['provenance'])
            assessment=next(r for r in payload['compatibility_report']['candidates'] if r['ability_id']==identifier and r['executor']['platform']=='windows')
            blockers.extend(assessment['blockers'])
            steps.append({'step_index':index,'ability_id':identifier,'name':record['ability']['name'],'role':'test',
                'technique_ids':[record['ability']['technique_id']],'reason':'Offline multi-behavior evidence integration',
                'executor':{'platform':'windows','name':'psh','privilege':record['ability'].get('privilege') or None},
                'parameters':{k:v['value'] for k,v in assessment['bindings'].items()},
                'prerequisites':assessment['survey_checks']+[{'condition':'Revalidate execution context','status':'unknown','evidence':None}],
                'readiness':'needs_information','behavior_verification':['Compare baseline and observed results; request/exit status alone is insufficient.'],
                'expected_telemetry':[{'source':'Execution-specific log source','observable':'Requested behavior evidence','availability':'unknown'}],
                'baseline':['Collect baseline from scoped resources.'],'cleanup_and_rollback':['Review catalog cleanup and filesystem/session effects before approval.'],
                'health_checks':['Compare target/runner health before and after.'],'sources':[record['provenance']]})
        context=payload['app_context']
        return {'id':context['id'],'name':'OFFLINE MOCK — mixed endpoint/web','description':'Real Survey/catalog; mocked model, no execution.',
            'atomic_ordering':[PROCESS,POST], 'metadata':{'schema_version':'1.0','request_id':context['request_id'],'target_id':context['target_id'],
            'mode':'plan_only','goal':'Process baseline and web command injection','selection':{'strategy':'compose_abilities','reason':'Two distinct requested behaviors','sources':sources},
            'readiness':'needs_information','blockers':sorted(set(blockers)),'assumptions':[],'steps':steps,
            'execution_context':{'planner':None,'agent_group':None,'agent_paw':None,'requirements':['Separate execution authorization and preflight.']},
            'limitations':['OFFLINE MOCK; no live model, execution or detection verification.']}}


def mixed_retrieval():
    return {'abilities':[{'record':get_record(i),'score':1.0} for i in [PROCESS,POST]],'adversaries':[],
            'behavior_candidates':{'B1':[PROCESS],'B2':[POST]}}


class MixedWorkflowTests(unittest.TestCase):
    def test_known_required_context_over_budget_stops_before_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            config=Config();config.runs=Path(tmp)/'runs';bundle=load_bundle(GUI/'review/survey-v2-8722')
            state=new_state(config,MIXED,GUI/'review/survey-v2-8722','keyword',policy=policy_for(planning_target(bundle),['endpoint','web'],4))
            state['request']=fixture_request(state)
            state['retrieval']=catalog_handles(mixed_retrieval())
            env=dict(state['input_envelope'],_fact_registry=state['fact_registry'])
            state['compatibility_report']=assess_candidates(state['retrieval'],env,state['request'])
            context,_=select_context(env,MIXED,['endpoint','web'],assessments=state['compatibility_report'])
            budget=len(canonical(dict(context,observations=[])))+10
            model=Mock();flow=Workflow(config,model)
            def limited(envelope,text,scope,records=None,**kwargs):
                return select_context(envelope,text,scope,records,budget=budget,**kwargs)
            with patch('scenario_agent.workflow.select_context',side_effect=limited): flow.node_build_plan(state)
            self.assertEqual(state['status'],'budget_exceeded');model.generate.assert_not_called()
            self.assertTrue(state['context_selection']['required_but_unselected'])
            self.assertIn('not re-survey',state['error'])

    def test_projected_registry_artifact_tamper_is_rejected_before_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            config=Config();config.runs=Path(tmp)/'runs'
            state=new_state(config,MIXED,GUI/'review/survey-v2-8722','keyword')
            path=config.runs/state['run_folder']/'evidence_registry.json'
            path.write_text('{}')
            model=Mock()
            with self.assertRaises(ValueError): Workflow(config,model).run(state)
            model.generate.assert_not_called()

    def test_real_bundle_mixed_plan_has_requirement_to_step_links_and_deduplicated_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            config=Config();config.runs=Path(tmp)/'runs';bundle=load_bundle(GUI/'review/survey-v2-8722')
            state=new_state(config,MIXED,GUI/'review/survey-v2-8722','keyword',policy=policy_for(planning_target(bundle),['endpoint','web'],4))
            model=MixedMock()
            with patch('scenario_agent.workflow.retrieve',side_effect=lambda *args:mixed_retrieval()):
                result=Workflow(config,model).run(state)
            self.assertEqual(result['status'],'completed',result.get('validation_errors',result.get('error')))
            self.assertEqual(len(result['plan']['metadata']['steps']),2)
            selected=result['selected_context']['observations'];self.assertEqual(len(selected),len({f['id'] for f in selected}))
            self.assertEqual(len([f for f in selected if f['predicate']=='module_access_and_forms']),1)
            self.assertTrue(any(f['id'].startswith('derived-') for f in selected))
            self.assertEqual([s['behavior_requirements'] for s in result['validation_report']['steps']],[['B1'],['B2']])
            self.assertEqual(result['validation_report']['detection_readiness'],'not_verified')
            self.assertFalse(result['execution_authorized'])
            report=result['validation_report'];plan=copy.deepcopy(result['plan'])
            first_fact=report['steps'][0]['supporting_fact_ids'][0]
            # A true endpoint fact cannot be reused to prove this web step's module precondition.
            module=next(c for c in plan['metadata']['steps'][1]['prerequisites'] if 'module_access_and_forms' in c['condition'])
            module['evidence']=first_fact
            env=dict(result['input_envelope'],_fact_registry=result['fact_registry'])
            with self.assertRaises(ValueError): validate_evidence_plan(plan,env,result['compatibility_report'],result['selected_context'])


if __name__=='__main__':unittest.main()
