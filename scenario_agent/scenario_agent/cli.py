import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from .config import Config

from .errors import error_message

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
            'gemini_timeout_seconds': config.gemini_timeout_ms / 1000,
            'parse_thinking_level': config.gemini_parse_thinking_level,
            'progress_enabled': config.gemini_progress,
            'gemini_max_attempts': config.gemini_max_attempts,
            'gemini_retry_delay_seconds': config.gemini_retry_delay,
            'corpus_exists': (config.index / 'corpus_manifest.json').is_file(),
            'faiss_index_exists': (config.index / 'index_manifest.json').is_file(),
            'execution_supported': False}

def main():
    parser = argparse.ArgumentParser(description='SOC Scenario Agent — planning only')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor')
    inspection = sub.add_parser('inspect-survey', help='Validate Survey v2 offline, without calling a model')
    inspection.add_argument('bundle', type=Path)
    sub.add_parser('prepare-corpus')
    sub.add_parser('build-index')
    sub.add_parser('check-index')
    for name in ('retrieve', 'run'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--text', required=True)
        cmd.add_argument('--target', type=Path, default=Path('input/target_profile.json'))
        cmd.add_argument('--scope', nargs='+', choices=('endpoint', 'web'))
        cmd.add_argument('--max-steps', type=int, default=4)
        cmd.add_argument('--mode', choices=('hybrid', 'keyword'), default='hybrid')
    cmd = sub.add_parser('resume')
    cmd.add_argument('run_id', help='Full UUID or readable run folder name')
    cmd.add_argument('--clarification')
    cmd = sub.add_parser('rename-run', help='Migrate a legacy run folder without calling Gemini')
    cmd.add_argument('run_id', help='Full UUID or current folder name')
    cmd.add_argument('--refresh-goal', action='store_true', help='Use saved behavior analysis to clarify the folder goal')
    cmd = sub.add_parser('check-schema')
    cmd.add_argument('kind', choices=('request', 'plan'))
    cmd.add_argument('file', type=Path)
    args = parser.parse_args()
    config = Config()
    try:
        if args.command == 'inspect-survey':
            from .survey_input import load_bundle
            value = load_bundle(args.bundle)
            result = {'schema_version': value['schema_version'], 'evidence_quality': value['evidence_quality'],
                      'survey_run_id': value['survey_context']['survey_run_id'], 'live_model_called': False}
        elif args.command == 'doctor':
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
        elif args.command == 'rename-run':
            from .run_storage import rename_run
            result = rename_run(config.runs, args.run_id, refresh_goal=args.refresh_goal)
        elif args.command == 'retrieve':
            from .rag import retrieve
            from .survey_input import load_bundle, planning_target
            bundle = load_bundle(args.target) if args.target.is_dir() or args.target.suffix.lower() == '.zip' else None
            target = planning_target(bundle) if bundle else json.loads(args.target.read_text(encoding='utf-8'))
            result = retrieve(config, {'text': args.text, 'objective': None, 'requested_techniques': [], 'max_tests': None}, target, args.mode)
            if bundle:
                from .survey_input import policy_for
                from .target_evidence import assess_candidates, filter_retrieval, select_context, catalog_handles, records_in
                envelope = {k:v for k,v in bundle.items() if k != '_contents'}
                envelope['policy'] = policy_for(target, args.scope or bundle['survey_context']['scope'], args.max_steps)
                if not set(envelope['policy']['planning_scope']).issubset(bundle['survey_context']['scope']):
                    raise ValueError('Diagnostic scope exceeds Survey scope')
                from .requirement_registry import build_registry
                envelope['_fact_registry'] = build_registry(envelope, contents=bundle['_contents'])
                result = catalog_handles(result)
                assessment = assess_candidates(result, envelope, {'text': args.text})
                selected, selection = select_context(envelope, args.text, envelope['policy']['planning_scope'], records_in(result))
                result = {'retrieval': filter_retrieval(result, assessment), 'compatibility_report': assessment,
                          'selected_context': selected, 'context_selection': selection}
            # Retrieval CLI is a diagnostic, not normalization of a free-text request.
        else:
            from .workflow import Workflow, new_state
            workflow = Workflow(config)
            if args.command == 'resume':
                state = workflow.resume(args.run_id, args.clarification)
            else:
                policy = None
                if args.target.is_dir() or args.target.suffix.lower() == '.zip':
                    from .survey_input import load_bundle, planning_target, policy_for
                    bundle = load_bundle(args.target)
                    policy = policy_for(planning_target(bundle), args.scope or bundle['survey_context']['scope'], args.max_steps)
                state = workflow.run(new_state(config, args.text, args.target, args.mode, policy=policy))
            result = {k: state[k] for k in ('run_id', 'run_folder', 'status', 'output', 'error', 'error_code', 'error_status', 'retry_not_before', 'resume_phase', 'questions', 'validation_errors', 'plan_normalizations', 'coverage_summary', 'uncovered_behaviors', 'novelty', 'execution_authorized') if k in state}
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if state['status'] in ('completed', 'needs_information', 'waiting_quota', 'waiting_service', 'no_candidates', 'insufficient_coverage') else 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        message = error_message(error)
        print(json.dumps({'status': 'error', 'message': message}, ensure_ascii=False), file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
