"""Offline diagnostic replay: immutable job/catalog, no model or command execution.

Run with the Scenario runtime interpreter. A successful evidence check does not
certify the full ability's scope, prerequisites, maliciousness, or telemetry.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path('scenario_agent'))
    parser.add_argument('--job',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    job=args.job.resolve();output=args.output.resolve()
    if output==job or job in output.parents:parser.error('Output must be outside the recorded job')
    sys.path.insert(0,str(args.source.resolve()))
    from scenario_agent.config import Config
    from scenario_agent.rag import retrieve
    from scenario_agent.behaviors import validate_grounding, validate_analysis
    from scenario_agent.intent_evidence import process_requirement
    paths=list((job/'runs').glob('*/state.json'))
    if len(paths)!=1:parser.error('Expected one recorded runtime state')
    state=json.loads(paths[0].read_text())
    request=json.loads((job/'request.json').read_text())
    analysis=state['behavior_analysis']
    # Evaluate recorded model responses, without asking a provider to regenerate.
    recorded=validate_grounding(state['raw_grounding_response'],analysis,state['retrieval'],state['target'])
    retrieval=retrieve(Config(args.source),dict(state['request'],_behavior_queries=analysis['behaviors']),state['target'],'keyword')
    original=[b for b in analysis['behaviors'] if b['source_quote'] in request['text'] and process_requirement(b)]
    if len(original)!=1:parser.error('Expected one explicit parent-child behavior in original request')
    behavior={k:v for k,v in original[0].items() if k!='id'}
    original_analysis=validate_analysis({'ordered':False,'behaviors':[behavior]},request['text'])
    source_id=original[0]['id']
    evidence=retrieval['intent_candidates'][source_id]
    report={'mode':'offline_command_evidence_only','model_called':False,'commands_executed':False,
        'recorded_job':job.name,'original_request':request['text'],'effective_request':state['text'],
        'recorded_analysis':analysis,'recorded_summary_before_fix':state.get('coverage_summary'),
        'recorded_response_revalidated':{'required':len(recorded['coverage']),
            'supported':sum(bool(r['matches']) for r in recorded['coverage']),
            'uncovered_behavior_ids':[r['behavior_id'] for r in recorded['coverage'] if not r['matches']]},
        'new_parent_child_candidates':evidence,
        'limitation':'Literal source relationship only; not a generated plan, proof of maliciousness, full-source scope approval, or detection result.'}
    # Explicitly labelled fixture, derived from a real source launcher. It tests
    # validation transport, and is never represented as a new model response.
    if evidence:
        candidate=evidence[0]
        record=next(x['record'] for x in retrieval['abilities'] if x['record']['canonical_id']==candidate['ability_id'])
        executor=next(ex for ex in record['ability']['executors'] if ex['name']=='psh' and ex['platform']=='windows')
        fixture={'coverage':[{'behavior_id':'B1','reason':'Offline source-derived test fixture',
            'matches':[{'ability_id':candidate['ability_id'],'platform':executor['platform'],
                'executor':executor['name'],'command_quote':candidate['evidence']['source_fragment']}]}],
            'unmodeled_requirements':[]}
        fixture_retrieval=dict(retrieval,behavior_candidates={'B1':retrieval['behavior_candidates'][source_id]})
        tested=validate_grounding(fixture,original_analysis,fixture_retrieval,state['target'])
        report['original_request_source_fixture']={'required':1,'supported':1,'coverage':tested}
    output.mkdir(parents=True,exist_ok=True)
    (output/'replay_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    (output/'retrieval_replay.json').write_text(json.dumps(retrieval,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('mode','model_called','commands_executed','recorded_response_revalidated')},ensure_ascii=False))

if __name__=='__main__':main()
