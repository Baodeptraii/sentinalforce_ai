import copy
import json
import uuid
import sys
import time
import threading
import re
from pathlib import Path
import yaml
from .errors import error_message, ServiceUnavailable
from .token_budget import BudgetWait, run_lock
from datetime import datetime, timezone, timedelta
from .config import sha256, write_json
from .llm import Gemini, QuotaExceeded, PARSE_PROMPT, PLAN_PROMPT
from .models import read_schema, plan_generation_schema
from .rag import retrieve
from .validation import validate_request, validate_plan
from .run_storage import now_iso, folder_name, ensure_directory, save_state, load_run, name_from_behaviors
from .behaviors import (ANALYSIS_PROMPT, GROUND_PROMPT, parse_generation_schema, validate_analysis,
                        grounding_payload, grounding_schema, validate_grounding, check_plan_coverage, planning_view)
from .catalog import connect, ability, adversary
from .survey_input import (load_bundle, planning_target, policy_for, snapshot, verify_snapshot, ADAPTER, canonical, sha)
from .target_evidence import (select_context, assess_candidates, filter_retrieval, records_in,
                              validate_evidence_plan, catalog_handles, INSTRUCTION)

NODES = ('parse', 'validate_request', 'retrieve', 'ground_behaviors', 'build_plan', 'validate_plan', 'finalize')

def redact(value):
    """Drop likely secret values; reference identifiers remain usable."""
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if any(s in k.lower() for s in ('password', 'api_key', 'access_token', 'cookie')) and not k.endswith('_ref') else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value

def new_state(config, text, target_path, mode='hybrid', policy=None):
    target_path = Path(target_path).absolute()
    bundle = load_bundle(target_path) if target_path.is_dir() or target_path.suffix.lower() == '.zip' else None
    target = planning_target(bundle) if bundle else redact(json.loads(target_path.read_text(encoding='utf-8')))
    if bundle:
        policy = policy or policy_for(target, bundle['survey_context']['scope'], 4)
        target.setdefault('capabilities', {})['execution_scope'] = {'allowed_surfaces': policy['planning_scope'],
            'allowed_targets': [target['address']], 'mode': 'plan_only', 'execution_authorized': False}
    if not isinstance(target.get('id'), str) or not target['id'].strip():
        raise ValueError('Target must provide a nonblank id')
    if not text.strip():
        raise ValueError('User text must not be empty')
    run_id = str(uuid.uuid4())
    created_at = now_iso()
    state = {'run_id': run_id, 'created_at': created_at,
            'run_folder': folder_name(text, run_id, created_at),
            'request_id': 'REQ-' + str(uuid.uuid4()),
            'plan_id': str(uuid.uuid4()), 'text': text, 'target': target,
            'target_path': str(target_path), 'target_sha256': sha256(target_path) if not bundle else None,
            'catalog_sha256': sha256(config.catalog), 'contracts_sha256': config.contract_hash(),
            'model': config.model, 'embedding_model': config.embedding_model,
            'mode': mode, 'phase': 'parse', 'next': 'parse', 'status': 'running',
            'parse_attempts': 0, 'plan_attempts': 0, 'ground_attempts': 0, 'pipeline_version': 2, 'events': []}
    if bundle:
        directory = ensure_directory(config.runs, state)
        snapshot(bundle, directory/'input', {'text': text}, policy)
        attach_snapshot(state, directory/'input')
    else:
        state['evidence_quality'] = {'mode': 'profile_only', 'limitation': 'Legacy profile has no evidence registry; verify all prerequisites separately.'}
    return state


def adapter_hash():
    base = Path(__file__).parent
    from .survey_input import SCHEMAS
    files = [base/name for name in ('survey_input.py', 'target_evidence.py', 'workflow.py', 'validation.py', 'models.py', 'requirement_registry.py', 'behaviors.py', 'rag.py', 'intent_evidence.py')] + sorted(SCHEMAS.glob('*.json'))
    return sha(canonical({p.name: sha256(p) for p in files}))


def attach_snapshot(state, root, relative='input'):
    envelope, target = verify_snapshot(root)
    from .requirement_registry import build_registry
    fact_registry = build_registry(envelope, root=Path(root)/'survey')
    write_json(Path(root).parent/'evidence_registry.json', fact_registry)
    state.update(fact_registry=fact_registry, fact_registry_sha256=sha(canonical(fact_registry)))
    state.update(input_snapshot=relative, input_manifest_sha256=sha256(Path(root)/'input_manifest.json'),
                 adapter_version=ADAPTER, adapter_sha256=adapter_hash(), input_envelope=envelope,
                 target=target, target_path=relative+'/planning_target.json', target_sha256=sha256(Path(root)/'planning_target.json'),
                 evidence_quality=envelope['evidence_quality'], pipeline_version=3)


def runtime_envelope(state):
    if not state.get('input_snapshot'): return None
    return dict(state['input_envelope'], _fact_registry=state['fact_registry'])


def model_target(state):
    if not state.get('input_snapshot'): return state['target']
    target = state['target']
    return {k: target[k] for k in ('id', 'address', 'os')} | {'capabilities': target.get('capabilities', {}),
            'inventory': 'Full evidence retained in input snapshot; capability legacy flags are not observed readiness.'}

class Workflow:
    def __init__(self, config, llm=None):
        self.config, self._llm = config, llm

    @property
    def llm(self):
        if self._llm is None:
            self._llm = Gemini(self.config)
        return self._llm

    def check_fingerprints(self, state):
        target_path = state['target_path']
        if state.get('input_snapshot'):
            compatible_path=Path(__file__).with_name('transport_compatible_adapters.json')
            compatible=json.loads(compatible_path.read_text()) if compatible_path.is_file() else []
            if state.get('adapter_version') != ADAPTER or (state.get('adapter_sha256') != adapter_hash() and state.get('adapter_sha256') not in compatible):
                raise ValueError('Input adapter changed; create a new job from the saved request')
            if state['input_snapshot'] != 'input': raise ValueError('Unsafe checkpoint input location')
            root = self.run_directory(state) / state['input_snapshot']
            envelope, target = verify_snapshot(root, state['input_manifest_sha256'])
            if state['target'] != target or state['input_envelope'] != envelope:
                raise ValueError('Checkpoint differs from pinned input snapshot')
            target_path = root / 'planning_target.json'
            if sha(canonical(state['fact_registry'])) != state.get('fact_registry_sha256'):
                raise ValueError('Checkpoint fact registry changed')
            if json.loads((root.parent/'evidence_registry.json').read_text()) != state['fact_registry']:
                raise ValueError('Pinned evidence registry artifact changed')
            if state.get('context_selection'):
                if state['context_selection']['selection_sha256'] != sha(canonical(state['selected_context'])):
                    raise ValueError('Pinned context selection changed')
        expected = {'catalog_sha256': sha256(self.config.catalog), 'contracts_sha256': self.config.contract_hash(),
                    'target_sha256': sha256(target_path), 'model': self.config.model,
                    'embedding_model': self.config.embedding_model}
        if any(state[k] != v for k, v in expected.items()):
            raise ValueError('Inputs/config changed since checkpoint; start a new run')

    def save(self, state):
        save_state(self.config.runs, state)

    def run_directory(self, state):
        return ensure_directory(self.config.runs, state)

    def step(self, name, state):
        state = copy.deepcopy(state)
        self.check_fingerprints(state)
        state['phase'] = name
        state['status'] = 'running'
        started = time.monotonic()
        if getattr(self.config, 'gemini_progress', False):
            print(f'[Scenario Agent] {name}: started', file=sys.stderr, flush=True)
        for key in ('error', 'error_code', 'error_status', 'retry_not_before'):
            state.pop(key, None)
        try:
            if name in ('parse','ground_behaviors','build_plan'):
                client=self.llm
                if callable(getattr(type(client),'bind_budget',None)):client.bind_budget(state['run_id'],self.run_directory(state)/'token_metrics.json')
            getattr(self, 'node_' + name)(state)
        except BudgetWait as error:
            state.update(status='waiting_budget' if error.retry_at else 'budget_exceeded',next='END',resume_phase=name,
                         error=str(error),budget_reason=error.reason,budget_details=error.details,
                         retry_not_before=datetime.fromtimestamp(error.retry_at,timezone.utc).isoformat() if error.retry_at else None)
        except ServiceUnavailable as error:
            state.update(status='waiting_service', next='END', resume_phase=name,
                         error=error_message(error), error_code=error.code, error_status=error.status,
                         provider_details=error.details,
                         retry_not_before=(datetime.now(timezone.utc) + timedelta(seconds=error.retry_after if error.retry_after is not None else 60)).isoformat())
        except QuotaExceeded as error:
            state.update(status='waiting_quota', next='END', resume_phase=name,error=error_message(error),error_code=429,error_status=error.status,provider_details=error.details,
                         retry_not_before=(datetime.now(timezone.utc)+timedelta(seconds=error.retry_after if error.retry_after is not None else 60)).isoformat())
        except Exception as error:
            state.update(status='error', next='END', resume_phase=name,
                         error=error_message(error),
                         error_code=getattr(error, 'code', None),
                         error_status=getattr(error, 'status', None))
        metrics_path=self.run_directory(state)/'token_metrics.json'
        if metrics_path.is_file():state['token_metrics']=json.loads(metrics_path.read_text())
        state['events'].append({'node': name, 'status': state['status'], 'next': state['next']})
        if getattr(self.config, 'gemini_progress', False):
            print(f'[Scenario Agent] {name}: {state["status"]}; next={state["next"]} ({time.monotonic() - started:.1f}s)', file=sys.stderr, flush=True)
        self.save(state)
        return state

    def evidence_payload(self, s, focus=None):
        if not s.get('input_snapshot'): return {}
        records=records_in(s.get('retrieval', {}))
        assessments=s.get('compatibility_report')
        if focus is not None:
            ids={item[0] for item in focus}
            records={k:v for k,v in records.items() if k in ids}
            if assessments:
                assessments=dict(assessments,candidates=[r for r in assessments['candidates'] if (r['ability_id'],r['executor']['platform'],r['executor']['name']) in focus])
        selected, report = select_context(runtime_envelope(s), s['text'], s['input_envelope']['policy']['planning_scope'],
                                          records, assessments=assessments)
        s.update(selected_context=selected, context_selection=report)
        destination=self.run_directory(s)/'context_selection.json'
        if destination.is_file():
            previous=json.loads(destination.read_text())
            if previous!=report:write_json(self.run_directory(s)/'context_selection_history'/(sha(canonical(previous))+'.json'),previous)
        write_json(destination, report)
        return {'survey_context': selected, 'server_policy': s['input_envelope']['policy'],
                'context_selection': report, 'compatibility_report': assessments}

    def node_parse(self, s):
        # A clarification invalidates all downstream conclusions from the old intent.
        for key in ('retrieval', 'coverage_summary', 'uncovered_behaviors', 'ground_errors', 'grounding_diagnostics', 'compatibility_report', 'selected_context', 'context_selection'):
            s.pop(key, None)
        s['ground_attempts'] = 0
        evidence = self.evidence_payload(s)
        references = []
        with connect(self.config.catalog) as db:
            for identifier in set(re.findall(r'[a-fA-F0-9]{8}-[a-fA-F0-9-]{27,}', s['text'])):
                try:
                    chain = adversary(db, identifier)
                    references.append({'id':chain['id'],'name':chain['name'],
                                       'steps':[{'id':a['canonical_id'],'name':a['ability']['name']} for a in chain['abilities']]})
                except LookupError:
                    pass
        response = self.llm.generate(PARSE_PROMPT + '\n' + ANALYSIS_PROMPT + ('\n'+INSTRUCTION if evidence else ''), {
            'app_context': {'id': s['request_id'], 'target_id': s['target']['id'], 'mode': 'plan_only', 'text': s['text']},
            'text': s['text'], 'target': model_target(s), 'catalog_reference_context': references, **evidence,
            'repair_errors': s.get('validation_errors', [])},
            parse_generation_schema(read_schema(self.config.root, 'request')))
        s['raw_request_response'] = copy.deepcopy(response)
        s['request'] = copy.deepcopy(response)
        s['behavior_analysis'] = s['request'].pop('internal_behavior_analysis', None)
        s['parse_attempts'] += 1
        s['next'] = 'validate_request'

    def node_validate_request(self, s):
        try:
            r = s['request']
            if r['id'] != s['request_id'] or r['text'] != s['text']:
                raise ValueError('App id/text changed')
            if s.get('input_snapshot'):
                policy = s['input_envelope']['policy']
                if (not set(r.get('scope', [])).issubset(policy['planning_scope']) or r.get('mode') != 'plan_only'
                    or (r.get('max_tests') is not None and (type(r['max_tests']) is not int or not 1 <= r['max_tests'] <= policy['max_steps']))):
                    raise ValueError('Parsed request exceeds pinned scope/step policy')
            questions = validate_request(self.config, r, s['target'])
            if not questions:
                s['behavior_analysis'] = validate_analysis(s.get('behavior_analysis'), s['text'])
                if not s['behavior_analysis']['behaviors']:
                    questions.append('Bạn muốn kiểm thử những hành vi cụ thể nào?')
        except Exception as error:
            s['validation_errors'] = [str(error)[:2000]]
            s['next'] = 'parse' if s['parse_attempts'] < 2 else 'END'
            if s['next'] == 'END':
                s['status'] = 'invalid_request'
            return
        write_json(self.run_directory(s) / 'user_request.json', r)
        s['validation_errors'] = []
        s.pop('questions', None)
        if questions:
            s.update(status='needs_information', questions=questions, next='END', resume_phase='parse')
        else:
            name_from_behaviors(self.config.runs, s)
            write_json(self.run_directory(s) / 'behavior_analysis.json', s['behavior_analysis'])
            s['next'] = 'retrieve'

    def node_retrieve(self, s):
        analysis = s.get('behavior_analysis')
        if not analysis or not analysis.get('behaviors'):
            raise ValueError('Missing behavior analysis; start a new run')
        request = dict(s['request'], _behavior_queries=analysis['behaviors'])
        s['retrieval'] = retrieve(self.config, request, s['target'], s['mode'])
        if s.get('input_snapshot'):
            s['retrieval'] = catalog_handles(s['retrieval'])
            s['compatibility_report'] = assess_candidates(s['retrieval'], runtime_envelope(s), s['request'])
            write_json(self.run_directory(s)/'compatibility_report.json', s['compatibility_report'])
            s['retrieval'] = filter_retrieval(s['retrieval'], s['compatibility_report'])
            self.evidence_payload(s)
        write_json(self.run_directory(s) / 'retrieval.json', s['retrieval'])
        if not s['retrieval']['abilities'] and not s['retrieval']['adversaries']:
            s.update(status='insufficient_coverage' if s.get('input_snapshot') else 'no_candidates', next='END',
                     uncovered_behaviors=[b['description'] for b in analysis['behaviors']], resume_phase='retrieve')
            if s.get('compatibility_report'):
                s['blockers'] = sorted({reason for row in s['compatibility_report']['candidates'] for reason in row['reasons']})
                s['questions'] = ['No source-compatible ability covers the request; review rejected candidates or supply a catalog source supporting the observed target.']
        else:
            s['next'] = 'ground_behaviors'

    def node_ground_behaviors(self, s):
        payload = grounding_payload(s['behavior_analysis'], s['retrieval'], s['target'])
        payload['user_text'] = s['text']
        focus={(c['ability_id'],c['platform'],c['executor']) for group in payload['behaviors'] for c in group['candidates']}
        payload.update(self.evidence_payload(s,focus=focus))
        response = self.llm.generate(GROUND_PROMPT + ('\n'+INSTRUCTION if s.get('input_snapshot') else ''), payload | {'repair_errors': s.get('ground_errors', [])},
                                     grounding_schema(s['behavior_analysis']))
        s['ground_attempts'] = s.get('ground_attempts', 0) + 1
        s['raw_grounding_response'] = copy.deepcopy(response)
        try:
            coverage = validate_grounding(response, s['behavior_analysis'], s['retrieval'], s['target'])
        except Exception as error:
            s['ground_errors'] = [str(error)[:2000]]
            coverage = getattr(error, 'partial_coverage', None)
            rows = coverage['coverage'] if coverage else []
            supported = {r['behavior_id'] for r in rows if r['matches']}
            s['coverage_summary'] = {'required': len(s['behavior_analysis']['behaviors']), 'supported': len(supported)}
            s['grounding_diagnostics'] = {'status': 'invalid_grounding', 'errors': s['ground_errors'],
                'rejected_matches': coverage.get('rejected_matches', []) if coverage else [],
                'coverage': rows}
            write_json(self.run_directory(s)/'grounding_diagnostics.json', s['grounding_diagnostics'])
            s['next'] = 'ground_behaviors' if s['ground_attempts'] < 2 else 'END'
            if s['next'] == 'END':
                s.update(status='insufficient_coverage', uncovered_behaviors=[b['description'] for b in s['behavior_analysis']['behaviors'] if b['id'] not in supported])
            return
        s.pop('ground_errors', None)
        s['grounding_diagnostics'] = {'status': 'reviewed', 'rejected_matches': coverage['rejected_matches'], 'coverage': coverage['coverage']}
        write_json(self.run_directory(s)/'grounding_diagnostics.json', s['grounding_diagnostics'])
        s.pop('uncovered_behaviors', None)
        s['retrieval']['behavior_coverage'] = coverage
        if s.get('compatibility_report'):
            s['compatibility_report']['behavior_coverage'] = coverage
            write_json(self.run_directory(s)/'compatibility_report.json', s['compatibility_report'])
        missing = [row['behavior_id'] for row in coverage['coverage'] if not row['matches']]
        unmodeled = coverage.get('unmodeled_requirements', [])
        if any(not quote.strip() or quote not in s['text'] for quote in unmodeled):
            raise ValueError('Unmodeled requirement quote is not present in the user request')
        s['coverage_summary'] = {'required': len(coverage['coverage']), 'supported': len(coverage['coverage']) - len(missing)}
        write_json(self.run_directory(s) / 'behavior_coverage.json', coverage)
        write_json(self.run_directory(s) / 'retrieval.json', s['retrieval'])
        if missing or unmodeled:
            s.update(status='insufficient_coverage', next='END', uncovered_behaviors=[
                b['description'] for b in s['behavior_analysis']['behaviors'] if b['id'] in missing] + unmodeled)
        else:
            s['next'] = 'build_plan'

    def node_build_plan(self, s):
        context = {'id': s['plan_id'], 'request_id': s['request_id'], 'target_id': s['target']['id']}
        planning_retrieval = planning_view(s['retrieval'])
        coverage=s['retrieval'].get('behavior_coverage')
        focus={(m['ability_id'],m['platform'],m['executor']) for row in coverage['coverage'] for m in row['matches']} if coverage else None
        evidence = self.evidence_payload(s,focus=focus)
        if evidence and s['context_selection']['required_but_unselected']:
            s.update(status='budget_exceeded', next='END', resume_phase='build_plan',budget_reason='required_facts_context_limit',
                     error='Known required facts exceed context budget; narrow request or adjust the server context budget, not re-survey.')
            return
        instruction = PLAN_PROMPT if not evidence else '''Create a ScenarioPlan matching the response schema, not an executable CALDERA operation. Use app_context identifiers verbatim; omit root objective. Keep metadata schema_version=1.0, mode=plan_only and role=test. Names, techniques, executor privilege and provenance must match catalog. Use only requested behavior matches from retrieval.behavior_coverage. Provide baseline, health checks, source-grounded cleanup review and behavior success criteria; do not claim probes or HTTP 200 prove success. Keep readiness=needs_information and list all compatibility blockers. Parameters must equal the selected executor assessment bindings. Include survey_checks verbatim, plus unknown execution preflight checks. Evidence means historical facts only. Selection sources must reference retrieved records.''' + '\n' + INSTRUCTION
        s['plan'] = self.llm.generate(instruction, {
            'app_context': context,
            'request': s['request'], 'target': model_target(s), 'retrieval': planning_retrieval, **evidence,
            'repair_errors': s.get('validation_errors', []),
            'previous_plan': s.get('plan') if s.get('validation_errors') else None},
            plan_generation_schema(read_schema(self.config.root, 'plan'), context, planning_retrieval, evidence_backed=bool(evidence)))
        if isinstance(getattr(self.llm, 'last_wire_response', None), dict):
            s['raw_generation_response'] = copy.deepcopy(self.llm.last_wire_response)
            s['generation_source_references'] = copy.deepcopy(self.llm.last_source_map)
        s['plan_attempts'] += 1
        s['raw_plan'] = copy.deepcopy(s['plan'])
        s['next'] = 'validate_plan'

    def node_validate_plan(self, s):
        if 'raw_plan' not in s:
            s['raw_plan'] = copy.deepcopy(s['plan'])
        s['plan_normalizations'] = []
        try:
            s['plan'] = validate_plan(self.config, s['plan'], s['request'], s['target'], s['retrieval'], s['plan_id'], s['plan_normalizations'], evidence_registry=runtime_envelope(s), evidence_report=s.get('compatibility_report'), selected_context=s.get('selected_context'))
            if s.get('input_snapshot'):
                s['validation_report'] = validate_evidence_plan(s['plan'], runtime_envelope(s), s['compatibility_report'], s['selected_context'])
                write_json(self.run_directory(s)/'validation_report.json', s['validation_report'])
                write_json(self.run_directory(s)/'step_evidence.json', s['validation_report'])
        except Exception as error:
            s['validation_errors'] = [str(error)[:2000]]
            write_json(self.run_directory(s)/'validation_report.json', {'plan_valid': False, 'errors': s['validation_errors']})
            s['next'] = 'build_plan' if s['plan_attempts'] < 2 else 'END'
            if s['next'] == 'END':
                s['status'] = 'invalid_plan'
            return
        s['validation_errors'] = []
        s['next'] = 'finalize'

    def node_finalize(self, s):
        if s.get('input_snapshot'):
            validate_evidence_plan(s['plan'], runtime_envelope(s), s['compatibility_report'], s['selected_context'])
            reference = 'Survey adapter '+ADAPTER+'; see step_evidence.json and input/input_manifest.json for snapshot evidence and readiness.'
            if reference not in s['plan']['metadata']['limitations']: s['plan']['metadata']['limitations'].append(reference)
        check_plan_coverage(s['plan'], s['retrieval'].get('behavior_coverage'))
        for key in ('uncovered_behaviors', 'questions', 'resume_phase', 'ground_errors'):
            s.pop(key, None)
        # Exact sequence comparison is independent of a model's 'compose' label.
        matches = []
        unresolved = 0
        with connect(self.config.catalog) as db:
            variants = db.execute('SELECT a.adversary_id, v.normalized_json FROM adversary_variants v JOIN adversaries a ON a.record_id=v.adversary_record_id').fetchall()
            for row in variants:
                try:
                    ordering = [ability(db, ref)['canonical_id'] for ref in json.loads(row['normalized_json'])['atomic_ordering']]
                except LookupError:
                    unresolved += 1
                    continue
                if ordering == s['plan']['atomic_ordering']:
                    matches.append(row['adversary_id'])
        s['novelty'] = {'matches_existing_adversary_ids': sorted(set(matches)),
                        'new_ordering_among_resolved_variants': not bool(matches),
                        'checked_variants': len(variants), 'unresolved_variants': unresolved}
        write_json(self.run_directory(s) / 'scenario_uniqueness.json', s['novelty'])
        destination = self.run_directory(s) / 'scenario_plan.yml'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(yaml.safe_dump(s['plan'], allow_unicode=True, sort_keys=False), encoding='utf-8')
        s.update(status='completed', next='END', output=str(destination), execution_authorized=False)

    def graph(self):
        from langgraph.graph import StateGraph, START, END
        graph = StateGraph(dict)
        for name in NODES:
            graph.add_node(name, lambda s, name=name: self.step(name, s))
        routes = {name: name for name in NODES} | {'END': END}
        graph.add_conditional_edges(START, lambda s: s['next'], routes)
        for name in NODES:
            graph.add_conditional_edges(name, lambda s: s['next'], routes)
        return graph.compile()

    def run(self, state):
        if getattr(self,'_run_lock_owner',None)==threading.get_ident():return self._run_unlocked(state)
        with run_lock(self.config.runs,state['run_id']):return self._run_unlocked(state)

    def _run_unlocked(self, state):
        self.check_fingerprints(state)
        self.save(state)
        try:
            graph = self.graph()
        except ModuleNotFoundError:
            state.update(status='error', resume_phase=state['next'], error='LangGraph dependency missing')
            self.save(state)
            raise
        return graph.invoke(state, config={'recursion_limit': 32})

    def resume(self, run_id, clarification=None):
        with run_lock(self.config.runs,run_id):
            self._run_lock_owner=threading.get_ident()
            try:return self._resume_unlocked(run_id,clarification)
            finally:self._run_lock_owner=None

    def _resume_unlocked(self, run_id, clarification=None):
        state, _ = load_run(self.config.runs, run_id)
        self.check_fingerprints(state)
        if state.get('input_snapshot') and state.get('adapter_sha256')!=adapter_hash():
            state['transport_migration']={'from_adapter_sha256':state.get('adapter_sha256'),'to_adapter_sha256':adapter_hash(),'reason':'phase context/budget; pinned inputs and semantic validators unchanged; only failed phase reselects context'}
        if state['status'] == 'needs_information':
            if not clarification:
                raise ValueError('Provide --clarification text to answer the pending questions')
            state['text'] += '\nBổ sung của người dùng: ' + clarification
            state.update(parse_attempts=0, plan_attempts=0, next='parse')
        elif state['status'] == 'insufficient_coverage':
            if clarification:
                state['text'] += '\nBổ sung của người dùng: ' + clarification
                state.update(parse_attempts=0, plan_attempts=0, ground_attempts=0, next='parse')
            else:
                from .intent_evidence import INTENT_VERSION
                stale = state.get('behavior_analysis') and state.get('retrieval', {}).get('behavior_retrieval_version') != INTENT_VERSION
                state.update(ground_attempts=0, next='retrieve' if stale else 'ground_behaviors')
        elif state['status'] in ('waiting_service','waiting_quota','waiting_budget','budget_exceeded'):
            if state.get('retry_not_before') and datetime.now(timezone.utc) < datetime.fromisoformat(state['retry_not_before'].replace('Z','+00:00')):
                return state
            state['next'] = state['resume_phase']
        elif state['status'] == 'error':
            state['next'] = state['resume_phase']
        elif state['status'] == 'invalid_plan' and state.get('plan'):
            # Re-check a saved draft after a validator fix, without requesting
            # another model response. The existing repair budget still applies.
            state['next'] = 'validate_plan'
        else:
            raise ValueError('This run cannot resume; start a new run')
        if state.get('pipeline_version') not in (2, 3):
            # Old checkpoints have no command-grounded intent coverage. Preserve
            # identity, but run the new analysis before they can be completed.
            state.update(next='parse', pipeline_version=2, parse_attempts=0, plan_attempts=0, ground_attempts=0)
        return self.run(state)
