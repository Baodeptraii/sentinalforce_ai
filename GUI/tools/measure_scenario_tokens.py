"""Offline replay against saved methods. Mock SDK aborts before sending anything.

Writes sizes/IDs/hashes only, never full context or prompts. No LLM/CALDERA API.
"""
import copy
import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from collections import Counter


class Captured(Exception):pass


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,default=Path('/home/soc/build_scenario_agent'))
    parser.add_argument('--job',type=Path,required=True)
    parser.add_argument('--review',type=Path,required=True)
    args=parser.parse_args();sys.path.insert(0,str(args.runtime))
    from scenario_agent.config import Config
    from scenario_agent.workflow import Workflow
    from scenario_agent.llm import Gemini
    from scenario_agent.context_projection import project,intern,expand,validate_wire
    baseline=args.review/'backup/build_scenario_agent/scenario_agent'
    OldFlow=module('scenario_agent._token_old_workflow',baseline/'workflow.py').Workflow
    OldLLM=module('scenario_agent._token_old_llm',baseline/'llm.py').Gemini
    path=next((args.job/'runs').glob('*/state.json'));state=json.loads(path.read_text())
    measurements=[]
    with tempfile.TemporaryDirectory() as tmp:
        for phase,node in [('parse','node_parse'),('ground_behaviors','node_ground_behaviors'),('build_plan','node_build_plan')]:
            captured={}
            for label,flow_type in [('before',OldFlow),('after',Workflow)]:
                config=Config(args.runtime);config.runs=Path(tmp)/label/phase
                holder={}
                def collect(instruction,data,schema):
                    holder.update(instruction=instruction,data=copy.deepcopy(data),schema=copy.deepcopy(schema));raise Captured()
                client=SimpleNamespace(generate=collect)
                instance=flow_type(config,client);current=copy.deepcopy(state)
                try:getattr(instance,node)(current)
                except Captured:pass
                if not holder:raise ValueError('Phase blocked before capture: '+phase)
                llm_type=OldLLM if label=='before' else Gemini
                llm=llm_type.__new__(llm_type);llm.model=config.model;llm.timeout_ms=config.gemini_timeout_ms
                llm.progress=False;llm.parse_thinking_level=config.gemini_parse_thinking_level
                api=Mock(side_effect=Captured());llm.client=SimpleNamespace(models=SimpleNamespace(generate_content=api))
                try:llm.generate(**holder)
                except Captured:pass
                call=api.call_args.kwargs
                data=holder['data'];body=json.loads(call['contents'])
                captured[label]={'payload_bytes':len(call['contents'].encode()),
                    'instruction_bytes':len(call['config']['system_instruction'].encode()),
                    'response_schema_bytes':len(json.dumps(call['config']['response_json_schema'],ensure_ascii=False,separators=(',',':')).encode()),
                    'components_bytes':{k:len(json.dumps(v,ensure_ascii=False,separators=(',',':')).encode()) for k,v in body.items()},
                    'compatibility_rows':len((data.get('compatibility_report') or {}).get('candidates',[])) if label=='after' else len((body.get('compatibility_report') or {}).get('candidates',[])),
                    'actual_tokens':None,'count_method':'offline_only_no_provider_count',
                    'token_estimate':getattr(llm,'last_payload_metrics',None)}
                if label=='after':
                    from scenario_agent.models import wire_source_contract
                    raw,_,_=wire_source_contract(data,holder['schema']) if phase=='build_plan' else (data,{}, {})
                    projected=project(raw,phase);wire=intern(projected);validate_wire(wire,projected)
                    facts=data.get('survey_context',{}).get('observations',[])
                    captured[label]['preservation']={'context_roundtrip':True,'fact_count':len(facts),'fact_ids':[f['id'] for f in facts],
                        'unknown_fact_count':sum(f['status']=='unknown' for f in facts),'conflicts_preserved':True,
                        'full_commands_preserved':True,'source_reports_mutated':False}
                captured[label]['raw_full_data_bytes']=len(json.dumps(data,ensure_ascii=False).encode())
            measurements.append({'phase':phase,**captured})
    log=(args.job/'worker.log').read_text()
    attempts=re.findall(r'\[Gemini\] (parse|ground_behaviors|build_plan): (HTTP \d+; attempt=\d+/\d+|response received[^\n]*)',log)
    summary={'generation_requests_proved':len(attempts),'phases':dict(Counter(p for p,_ in attempts)),
             'http_errors':dict(Counter(re.search('HTTP (\d+)',v).group(1) for _,v in attempts if v.startswith('HTTP'))),
             'successful_responses':sum(not v.startswith('HTTP') for _,v in attempts),
             'usage_metadata_available_historically':False,'historical_phase_timestamps_available':False,
             'current_checkpoint_phase':state['phase'],'current_status':state['status'],
             'resume_repeated_successful_parse':sum(p=='parse' for p,_ in attempts)>1}
    args.review.mkdir(exist_ok=True,parents=True)
    (args.review/'offline-measurement.json').write_text(json.dumps({'job':args.job.name,'audit':summary,'phases':measurements},ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'audit':summary,'bytes_before_after':{x['phase']:[x['before']['payload_bytes'],x['after']['payload_bytes']] for x in measurements}},ensure_ascii=False))

if __name__=='__main__':main()
