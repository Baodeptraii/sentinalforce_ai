"""Execute Scenario planning in its own interpreter. No scenario execution."""
import json
import sys
from pathlib import Path


def run_planning(source, folder, resume=False, llm=None, mode='hybrid'):
    source, folder = Path(source), Path(folder)
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from engine import audit_stream
    def audit(state):
        try:
            audit_stream.transition('scenario',{'id':folder.name,'phase':state.get('phase'),'status':state.get('status'),'run_id':state.get('run_id')})
        except (OSError,ValueError):
            write_json(folder/'audit_status.json',{'status':'unavailable'})
    sys.path.insert(0, str(source))
    from scenario_agent.config import Config, write_json
    from scenario_agent.workflow import Workflow, new_state
    from scenario_agent.survey_input import verify_snapshot
    from scenario_agent.errors import error_message

    config = Config(source)
    config.runs = folder / 'runs'
    policy = json.loads((folder / 'policy.json').read_text())
    marker = folder / 'fixed_case.json'
    fixed_case_id = None
    base_cls = Workflow
    if marker.is_file() and not resume:
        from scenario_agent.fixed_cases import FixedWorkflow
        spec = json.loads(marker.read_text())
        fixed_case_id = spec.get('case_id')
        base_cls = FixedWorkflow
    elif marker.is_file() and resume:
        write_json(folder / 'result.json', {'status': 'error',
            'error': 'Fixed-case jobs are deterministic; create a new one instead of resuming.',
            'execution_authorized': False})
        return None

    class IntegratedWorkflow(base_cls):
        def step(self, name, state):
            write_json(folder / 'progress.json', {'phase': name, 'status': 'running',
                          'events': state.get('events', []), 'run_id': state['run_id']})
            audit(dict(state,phase=name,status='running'))
            return super().step(name, state)

        def save(self, state):
            super().save(state)
            audit(state)
            write_json(folder / 'progress.json', {k: state.get(k) for k in ('phase', 'status', 'events', 'run_id','token_metrics','retry_not_before','budget_reason')})

        def node_validate_request(self, state):
            super().node_validate_request(state)
            request = state.get('request', {})
            if state.get('next') == 'retrieve':
                if (not set(request.get('scope', [])).issubset(policy['planning_scope'])
                        or (request.get('max_tests') is not None and (type(request['max_tests']) is not int
                        or not 1 <= request['max_tests'] <= policy['max_steps']))):
                    state.update(status='invalid_request', next='END',
                                 validation_errors=['Parsed request exceeds the selected planning scope or step limit.'])

    workflow = IntegratedWorkflow(config, fixed_case_id) if base_cls is not Workflow else IntegratedWorkflow(config, llm)
    try:
        has_snapshot = (folder/'input/input_manifest.json').is_file()
        if has_snapshot:
            envelope, _ = verify_snapshot(folder/'input')
            if envelope['policy'] != policy: raise ValueError('Job policy differs from immutable input')
        if resume:
            request = json.loads((folder / 'resume.json').read_text())
            state = workflow.resume(request['run_id'], request.get('clarification') or None)
        else:
            request = json.loads((folder / 'request.json').read_text())
            if has_snapshot:
                if request['text'] != envelope['request']['text']: raise ValueError('Job request differs from immutable input')
                state = new_state(config, request['text'], folder/'input/survey', mode, policy=policy)
            else:
                text = request['text'] + '\n\nPhạm vi lập kế hoạch: ' + ', '.join(policy['planning_scope'])
                text += '. Tối đa ' + str(policy['max_steps']) + ' bước. Chỉ lập kế hoạch (plan_only); không thực thi.'
                state = new_state(config, text, folder / 'planning_target.json', mode)
            context_path = folder/'regeneration_context.json'
            if context_path.is_file() and base_cls is Workflow:
                state['text'] = json.loads(context_path.read_text())['effective_request_text']
            state = workflow.run(state)
        keys = ('run_id', 'run_folder', 'status', 'phase', 'error', 'error_code', 'retry_not_before', 'resume_phase',
                'questions', 'blockers', 'validation_errors', 'coverage_summary', 'uncovered_behaviors', 'novelty', 'events', 'evidence_quality', 'grounding_diagnostics','token_metrics','budget_reason','budget_details','provider_details')
        result = {k: state[k] for k in keys if k in state}
        result['effective_request_text'] = state['text']
        result['analyzed_behaviors'] = state.get('behavior_analysis', {}).get('behaviors', [])
        if state.get('fact_registry'):
            result['context_expansion'] = {'source_facts': state['fact_registry']['source_fact_count'], 'derived_facts': state['fact_registry']['derived_fact_count'],
                                           'selected_facts':len(state.get('selected_context',{}).get('observations',[])),
                                           'required_but_unselected':state.get('context_selection',{}).get('required_but_unselected',[])}
        result.update(mode='plan_only', execution_authorized=False, adapter_version=policy['version'])
        run_directory = workflow.run_directory(state)
        for name in ('evidence_registry.json', 'context_selection.json', 'compatibility_report.json', 'validation_report.json', 'step_evidence.json', 'grounding_diagnostics.json', 'behavior_analysis.json', 'behavior_coverage.json','token_metrics.json'):
            path = run_directory/name
            fresh = {'grounding_diagnostics.json':state.get('grounding_diagnostics'),
                     'behavior_analysis.json':state.get('behavior_analysis'),
                     'behavior_coverage.json':state.get('retrieval', {}).get('behavior_coverage'),
                     'compatibility_report.json':state.get('compatibility_report')}
            if name in fresh and not fresh[name]: continue
            if path.is_file(): (folder/name).write_bytes(path.read_bytes())
        if state['status'] == 'completed':
            output = Path(state['output']).resolve()
            if config.runs.resolve() not in output.parents: raise ValueError('Output outside job storage')
            plan = state['plan']
            if len(plan['atomic_ordering']) > policy['max_steps']: raise ValueError('Plan exceeds selected step limit')
            (folder / 'scenario_plan.yml').write_bytes(output.read_bytes())
            result.update(steps=len(plan['atomic_ordering']), readiness=plan['metadata']['readiness'], blockers=plan['metadata']['blockers'])
            if state.get('validation_report'):
                report = state['validation_report']
                result.update(execution_readiness=report['execution_readiness'], detection_readiness=report['detection_readiness'],
                              evidence_validation='schema_hash_pointer_and_typed_predicates',
                              step_reasons=[{'step': x['step_index'], 'ability_id': x['ability_id'], 'facts': x['supporting_fact_ids'],
                                             'compatibility': x['compatibility']} for x in report['steps']])
        write_json(folder / 'result.json', result)
        return state
    except Exception as exc:
        audit({'phase':'planning','status':'error'})
        write_json(folder / 'result.json', {'status': 'error', 'error': error_message(exc), 'execution_authorized': False})
        if llm is not None: raise


def main():
    run_planning(*sys.argv[1:3], resume='--resume' in sys.argv)


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--inspect-plan':
        source, path = Path(sys.argv[2]), Path(sys.argv[3])
        sys.path.insert(0,str(source))
        import yaml
        from scenario_agent.models import validate_contract
        value=yaml.safe_load(path.read_text(encoding='utf-8'))
        validate_contract(source,'plan',value)
        print(json.dumps({k:value[k] for k in ('id','name','description','atomic_ordering')},ensure_ascii=False))
    else: main()
