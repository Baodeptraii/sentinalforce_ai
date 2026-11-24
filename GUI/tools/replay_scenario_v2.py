#!/usr/bin/env python3
"""Offline replay using real Survey/catalog, explicit mock generation and no live model.

Run with Scenario's .venv/bin/python, not the Survey interpreter.
"""
import argparse
import json
import sys
from pathlib import Path
from unittest.mock import patch

GUI = Path(__file__).resolve().parents[1]
RUNTIME = Path('scenario_agent')
sys.path[:0] = [str(RUNTIME), str(RUNTIME/'tests'), str(GUI)]
from test_survey_input_v2 import MockGeneration, catalog_fixture, TEXT
from engine import scenario_bridge as bridge
from engine.scenario_worker import run_planning
from engine.survey import load_config
from scenario_agent.config import write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path, help='New directory for a reviewable offline GUI job')
    parser.add_argument('--real-keyword-retrieval', action='store_true', help='Use unchanged local keyword retrieval instead of the catalog fixture')
    args = parser.parse_args()
    if args.destination.exists(): raise ValueError('Destination already exists')
    args.destination.mkdir(parents=True)
    mode = 'actual_keyword_retrieval' if args.real_keyword_retrieval else 'catalog_backed_retrieval_fixture'
    with patch.object(bridge, 'OUTPUTS', args.destination), patch.object(bridge, 'ACTIVE', None), patch.object(bridge.threading, 'Thread'):
        job = bridge.start({'survey_run_id': '8722ef963d82403fb445ed9c0f8e9f05', 'text': TEXT, 'scope': ['web'], 'max_steps': 4},
                           dict(load_config(), scenario_root=str(RUNTIME)))
        folder = args.destination/job['id']
        mock = MockGeneration()
        with patch('scenario_agent.workflow.Gemini', side_effect=AssertionError('Live model prohibited in replay')):
            if args.real_keyword_retrieval:
                state = run_planning(RUNTIME, folder, llm=mock, mode='keyword')
            else:
                with patch('scenario_agent.workflow.retrieve', side_effect=lambda *a:catalog_fixture()):
                    state = run_planning(RUNTIME, folder, llm=mock, mode='keyword')
        saved = bridge.read(folder/'job.json'); saved['status'] = state['status']; write_json(folder/'job.json', saved)
        result = bridge.read(folder/'result.json')
        result['evaluation'] = {'generation': 'mock_LLM', 'retrieval': mode, 'live_model_calls': 0, 'scenario_executed': False}
        write_json(folder/'result.json', result)
        api = bridge.public(job['id'])
        write_json(folder/'offline_replay.json', {'mock_llm': True, 'retrieval': mode, 'live_model_calls': 0, 'scenario_executed': False,
                   'status': state['status'], 'api_source': api['input_source'], 'model_calls_mocked': len(mock.payloads),
                   'input_facts': state['evidence_quality']['observations'], 'steps': api['result'].get('steps'),
                   'execution_authorized': False, 'validation_errors': state.get('validation_errors', [])})
        print(json.dumps({'job': str(folder), 'status': state['status'], 'retrieval': mode, 'mock_llm': True}))
        return 0 if state['status'] == 'completed' else 1


if __name__ == '__main__': raise SystemExit(main())
