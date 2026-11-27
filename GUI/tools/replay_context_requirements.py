#!/usr/bin/env python3
"""Offline mixed endpoint/web replay: real Survey/catalog, mocked model and retrieval fixture.

Run using /home/soc/build_scenario_agent/.venv/bin/python. Never executes source commands.
"""
import argparse
import json
import sys
from pathlib import Path
from unittest.mock import patch
GUI=Path(__file__).resolve().parents[1]
RUNTIME=Path('/home/soc/build_scenario_agent')
sys.path[:0]=[str(RUNTIME),str(RUNTIME/'tests'),str(GUI)]
from test_context_requirements import MixedMock, mixed_retrieval, MIXED
from engine import scenario_bridge as bridge
from engine.scenario_worker import run_planning
from engine.survey import load_config
from scenario_agent.config import write_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    args=parser.parse_args()
    if args.destination.exists(): raise ValueError('Destination already exists; preserve historical replay')
    args.destination.mkdir(parents=True)
    with patch.object(bridge,'OUTPUTS',args.destination),patch.object(bridge,'ACTIVE',None),patch.object(bridge.threading,'Thread'):
        job=bridge.start({'survey_run_id':'8722ef963d82403fb445ed9c0f8e9f05','text':MIXED,'scope':['endpoint','web'],'max_steps':4},
                         dict(load_config(),scenario_root=str(RUNTIME)))
        folder=args.destination/job['id'];model=MixedMock()
        with patch('scenario_agent.workflow.Gemini',side_effect=AssertionError('Live model prohibited')), \
             patch('scenario_agent.workflow.retrieve',side_effect=lambda *args:mixed_retrieval()):
            state=run_planning(RUNTIME,folder,llm=model,mode='keyword')
        saved=bridge.read(folder/'job.json');saved['status']=state['status'];write_json(folder/'job.json',saved)
        result=bridge.read(folder/'result.json')
        evaluation={'generation':'mock_LLM','retrieval':'real_catalog_backed_fixture','live_model_calls':0,'scenario_executed':False}
        result['evaluation']=evaluation;write_json(folder/'result.json',result)
        public=bridge.public(job['id'])
        write_json(folder/'offline_replay.json',dict(evaluation,status=state['status'],steps=public['result'].get('steps'),
                   source_facts=state['fact_registry']['source_fact_count'],derived_facts=state['fact_registry']['derived_fact_count'],
                   selected_facts=len(state['selected_context']['observations']),input_snapshot_pinned=True,
                   execution_authorized=False,api_source=public['input_source']))
        print(json.dumps({'job':str(folder),'status':state['status'],'evaluation':evaluation},ensure_ascii=False))
        return 0 if state['status']=='completed' else 1


if __name__=='__main__': raise SystemExit(main())
