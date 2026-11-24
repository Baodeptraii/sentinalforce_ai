import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from .config import Config

def error_message(error):
    cause = error
    seen = set()
    while id(cause) not in seen:
        seen.add(id(cause))
        nested = cause.__cause__ or (None if cause.__suppress_context__ else cause.__context__)
        if nested is None:
            break
        cause = nested
    if isinstance(cause, ModuleNotFoundError) and cause.name:
        return f'Missing dependency: {cause.name}. Install project dependencies; see README.md.'
    if isinstance(cause, FileNotFoundError):
        return 'Required local input/index is missing. Run doctor and prepare-corpus/build-index.'
    message = f'{type(cause).__name__}: {str(cause)[:1000]}'
    for name in ('GEMINI_API_KEY', 'GOOGLE_API_KEY'):
        key = os.getenv(name)
        if key:
            message = message.replace(key, '[REDACTED]')
    return message

def doctor(config):
    modules = ['pydantic', 'yaml', 'jsonschema', 'dotenv', 'numpy', 'langgraph', 'google.genai', 'sentence_transformers', 'faiss']
    dependencies = {}
    for name in modules:
        try:
            dependencies[name] = importlib.util.find_spec(name) is not None
        except ModuleNotFoundError:
            dependencies[name] = False
    return {'python': sys.version.split()[0], 'dependencies': dependencies,
            'dependency_check': 'Module presence only; runtime imports may still fail due to incompatible dependencies.',
            'catalog_exists': config.catalog.is_file(), 'model': config.model,
            'embedding_model': config.embedding_model,
            'api_key_configured': bool(os.getenv('GEMINI_API_KEY')),
            'free_tier_confirmed_by_user': config.free_confirmed,
            'billing_tier_verified_by_code': False,
            'corpus_exists': (config.index / 'corpus_manifest.json').is_file(),
            'faiss_index_exists': (config.index / 'index_manifest.json').is_file(),
            'execution_supported': False}

def main():
    parser = argparse.ArgumentParser(description='SOC Scenario Agent — planning only')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor')
    sub.add_parser('prepare-corpus')
    sub.add_parser('build-index')
    sub.add_parser('check-index')
    for name in ('retrieve', 'run'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--text', required=True)
        cmd.add_argument('--target', type=Path, default=Path('input/target_profile.json'))
        cmd.add_argument('--mode', choices=('hybrid', 'keyword'), default='hybrid')
    cmd = sub.add_parser('resume')
    cmd.add_argument('run_id')
    cmd.add_argument('--clarification')
    cmd = sub.add_parser('check-schema')
    cmd.add_argument('kind', choices=('request', 'plan'))
    cmd.add_argument('file', type=Path)
    args = parser.parse_args()
    config = Config()
    try:
        if args.command == 'doctor':
            result = doctor(config)
        elif args.command == 'prepare-corpus':
            from .rag import prepare
            result = prepare(config)
        elif args.command == 'build-index':
            from .rag import build_index
            result = build_index(config)
        elif args.command == 'check-index':
            from .rag import check_index
            result = check_index(config)
        elif args.command == 'check-schema':
            import yaml
            from .models import validate_contract
            validate_contract(config.root, args.kind, yaml.safe_load(args.file.read_text(encoding='utf-8')))
            result = {'schema_valid': True, 'business_validated': False}
        elif args.command == 'retrieve':
            from .rag import retrieve
            target = json.loads(args.target.read_text(encoding='utf-8'))
            result = retrieve(config, {'text': args.text, 'objective': None, 'requested_techniques': [], 'max_tests': None}, target, args.mode)
            # Retrieval CLI is a diagnostic, not normalization of a free-text request.
        else:
            from .workflow import Workflow, new_state
            workflow = Workflow(config)
            state = workflow.resume(args.run_id, args.clarification) if args.command == 'resume' else workflow.run(new_state(config, args.text, args.target, args.mode))
            result = {k: state[k] for k in ('run_id', 'status', 'output', 'error', 'questions', 'execution_authorized') if k in state}
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if state['status'] in ('completed', 'needs_information', 'waiting_quota', 'no_candidates') else 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        message = error_message(error)
        print(json.dumps({'status': 'error', 'message': message}, ensure_ascii=False), file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
