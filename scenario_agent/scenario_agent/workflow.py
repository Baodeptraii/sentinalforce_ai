import copy
import json
import uuid
from pathlib import Path
import yaml
from .config import sha256, write_json
from .llm import Gemini, QuotaExceeded, PARSE_PROMPT, PLAN_PROMPT
from .models import read_schema
from .rag import retrieve
from .validation import validate_request, validate_plan

NODES = ('parse', 'validate_request', 'retrieve', 'build_plan', 'validate_plan', 'finalize')

def redact(value):
    """Drop likely secret values; reference identifiers remain usable."""
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if any(s in k.lower() for s in ('password', 'api_key', 'access_token', 'cookie')) and not k.endswith('_ref') else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value

def new_state(config, text, target_path, mode='hybrid'):
    target_path = Path(target_path).resolve()
    target = redact(json.loads(target_path.read_text(encoding='utf-8')))
    if not isinstance(target.get('id'), str) or not target['id'].strip():
        raise ValueError('Target must provide a nonblank id')
    if not text.strip():
        raise ValueError('User text must not be empty')
    return {'run_id': str(uuid.uuid4()), 'request_id': 'REQ-' + str(uuid.uuid4()),
            'plan_id': str(uuid.uuid4()), 'text': text, 'target': target,
            'target_path': str(target_path), 'target_sha256': sha256(target_path),
            'catalog_sha256': sha256(config.catalog), 'contracts_sha256': config.contract_hash(),
            'model': config.model, 'embedding_model': config.embedding_model,
            'mode': mode, 'phase': 'parse', 'next': 'parse', 'status': 'running',
            'parse_attempts': 0, 'plan_attempts': 0, 'events': []}

class Workflow:
    def __init__(self, config, llm=None):
        self.config, self._llm = config, llm

    @property
    def llm(self):
        if self._llm is None:
            self._llm = Gemini(self.config)
        return self._llm

    def check_fingerprints(self, state):
        expected = {'catalog_sha256': sha256(self.config.catalog), 'contracts_sha256': self.config.contract_hash(),
                    'target_sha256': sha256(state['target_path']), 'model': self.config.model,
                    'embedding_model': self.config.embedding_model}
        if any(state[k] != v for k, v in expected.items()):
            raise ValueError('Inputs/config changed since checkpoint; start a new run')

    def save(self, state):
        write_json(self.config.runs / state['run_id'] / 'state.json', state)

    def step(self, name, state):
        state = copy.deepcopy(state)
        self.check_fingerprints(state)
        state['phase'] = name
        state['status'] = 'running'
        try:
            getattr(self, 'node_' + name)(state)
        except QuotaExceeded:
            state.update(status='waiting_quota', next='END', resume_phase=name,
                         error='Gemini 429: resume later; no automatic retry loop')
        except Exception as error:
            state.update(status='error', next='END', resume_phase=name,
                         error=f'{type(error).__name__}: processing failed; check dependency/configuration and validation artifacts')
        state['events'].append({'node': name, 'status': state['status'], 'next': state['next']})
        self.save(state)
        return state

    def node_parse(self, s):
        s['parse_attempts'] += 1
        s['request'] = self.llm.generate(PARSE_PROMPT, {
            'app_context': {'id': s['request_id'], 'target_id': s['target']['id'], 'mode': 'plan_only', 'text': s['text']},
            'text': s['text'], 'target': s['target'], 'repair_errors': s.get('validation_errors', [])},
            read_schema(self.config.root, 'request'))
        s['next'] = 'validate_request'

    def node_validate_request(self, s):
        try:
            r = s['request']
            if r['id'] != s['request_id'] or r['text'] != s['text']:
                raise ValueError('App id/text changed')
            questions = validate_request(self.config, r, s['target'])
        except Exception as error:
            s['validation_errors'] = [str(error)[:2000]]
            s['next'] = 'parse' if s['parse_attempts'] < 2 else 'END'
            if s['next'] == 'END':
                s['status'] = 'invalid_request'
            return
        write_json(self.config.runs / s['run_id'] / 'user_request.json', r)
        s['validation_errors'] = []
        if questions:
            s.update(status='needs_information', questions=questions, next='END', resume_phase='parse')
        else:
            s['next'] = 'retrieve'

    def node_retrieve(self, s):
        s['retrieval'] = retrieve(self.config, s['request'], s['target'], s['mode'])
        write_json(self.config.runs / s['run_id'] / 'retrieval.json', s['retrieval'])
        if not s['retrieval']['abilities'] and not s['retrieval']['adversaries']:
            s.update(status='no_candidates', next='END')
        else:
            s['next'] = 'build_plan'

    def node_build_plan(self, s):
        s['plan_attempts'] += 1
        s['plan'] = self.llm.generate(PLAN_PROMPT, {
            'app_context': {'id': s['plan_id'], 'request_id': s['request_id'], 'target_id': s['target']['id']},
            'request': s['request'], 'target': s['target'], 'retrieval': s['retrieval'],
            'repair_errors': s.get('validation_errors', [])}, read_schema(self.config.root, 'plan'))
        s['next'] = 'validate_plan'

    def node_validate_plan(self, s):
        try:
            s['plan'] = validate_plan(self.config, s['plan'], s['request'], s['target'], s['retrieval'], s['plan_id'])
        except Exception as error:
            s['validation_errors'] = [str(error)[:2000]]
            s['next'] = 'build_plan' if s['plan_attempts'] < 2 else 'END'
            if s['next'] == 'END':
                s['status'] = 'invalid_plan'
            return
        s['validation_errors'] = []
        s['next'] = 'finalize'

    def node_finalize(self, s):
        destination = self.config.runs / s['run_id'] / 'scenario_plan.yml'
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
        # Run IDs cannot traverse out of the run directory.
        uuid.UUID(run_id)
        state = json.loads((self.config.runs / run_id / 'state.json').read_text())
        self.check_fingerprints(state)
        if state['status'] == 'needs_information':
            if not clarification:
                raise ValueError('Provide --clarification text to answer the pending questions')
            state['text'] += '\nBổ sung của người dùng: ' + clarification
            state.update(parse_attempts=0, plan_attempts=0, next='parse')
        elif state['status'] in ('waiting_quota', 'error'):
            state['next'] = state['resume_phase']
        else:
            raise ValueError('This run cannot resume; start a new run')
        return self.run(state)
