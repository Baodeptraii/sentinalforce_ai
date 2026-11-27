"""Explicit controlled-LLM fixtures for regression tests. Never used by agent code."""
import copy
from scenario_agent.behaviors import grounding_payload, validate_grounding, validate_analysis

def with_analysis(request, records):
    result=copy.deepcopy(request)
    result['internal_behavior_analysis']={'ordered':True,'behaviors':[
        {'description':'EVAL FIXTURE: '+r['ability']['name'],'source_quote':request['text'],
         'query_en':r['ability']['name']+' '+r['canonical_id'],'keywords':[r['ability']['name'][:100]]}
        for r in records] or [{'description':'EVAL FIXTURE: generic discovery','source_quote':request['text'],
                              'query_en':'system discovery','keywords':['discovery']} ]}
    return result

def ground_fixture(data):
    result={'coverage':[],'unmodeled_requirements':[]}
    for group in data['behaviors']:
        behavior=group['behavior'];candidates=group['candidates']
        wanted=[c for c in candidates if c['ability_id'] in behavior['query_en']]
        chosen=next((c for c in wanted if c['executor'] in ('psh','cmd','sh')),wanted[0] if wanted else None)
        result['coverage'].append({'behavior_id':behavior['id'],'reason':'EVAL FIXTURE: controlled catalog-command match',
            'matches':[] if chosen is None else [{**{k:chosen[k] for k in ('ability_id','platform','executor')},'command_quote':chosen['command']}]})
    return result

def coverage_fixture(request, records, target):
    analysis=validate_analysis(with_analysis(request,records)['internal_behavior_analysis'],request['text'])
    retrieval={'abilities':[{'record':r} for r in records],'adversaries':[],
               'behavior_candidates':{b['id']:[r['canonical_id'] for r in records] for b in analysis['behaviors']}}
    data=grounding_payload(analysis,retrieval,target)
    result=validate_grounding(ground_fixture(data),analysis,retrieval,target)
    result['method']='controlled_LLM_fixture_with_real_catalog_commands'
    return result
