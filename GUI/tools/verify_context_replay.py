#!/usr/bin/env python3
"""Verify a completed offline replay, including projected facts and requirement/step links."""
import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit
GUI=Path(__file__).resolve().parents[1]
RUNTIME=Path('scenario_agent')
sys.path.insert(0,str(RUNTIME))
import yaml
from jsonschema import Draft202012Validator
from scenario_agent.config import Config,write_json
from scenario_agent.survey_input import verify_snapshot,load_directory,pointer,sha
from scenario_agent.workflow import Workflow,runtime_envelope
from scenario_agent.validation import validate_plan


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('job',type=Path);args=parser.parse_args()
    job=args.job.resolve();config=Config();config.runs=job/'runs'
    result=json.loads((job/'result.json').read_text())
    state=json.loads((config.runs/result['run_folder']/'state.json').read_text())
    assert result['status']=='completed' and state['status']=='completed'
    Workflow(config).check_fingerprints(state)
    verify_snapshot(job/'input')
    schemas=config.root/'input/schema/survey_v2'
    registry=json.loads((job/'evidence_registry.json').read_text())
    assert registry==state['fact_registry']
    assessments=json.loads((job/'compatibility_report.json').read_text())
    checks=[('evidence_registry',registry),('selected_context',state['selected_context']),('scenario_input_envelope',state['input_envelope'])]
    checks += [('requirement_assessment',row) for row in assessments['candidates']]
    for name,value in checks:
        schema=json.loads((schemas/(name+'.schema.json')).read_text());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(value)
    bundle=load_directory(job/'input/survey');contents=bundle['_contents'];docs={name:json.loads(data) for name,data in contents.items()}
    references=0;derived=0
    for fact in registry['observations']:
        for ref in fact['evidence_refs']:
            assert sha(contents[ref['file']])==ref['sha256'];value=pointer(docs[ref['file']],ref['pointer']);references+=1
            if not fact['id'].startswith('derived-'):continue
            if fact['predicate'] in ('process','service'):
                assert all(value[k]==v for k,v in fact['value'].items())
                parent=pointer(docs[ref['file']],ref['pointer'].rsplit('/',2)[0]);assert fact['observed_at']==parent.get('collected_at')
            elif fact['predicate']=='inventory':assert len(value)==fact['value']['returned_records'] and fact['value']['coverage']=='returned_records_only'
            elif fact['predicate']=='web_origin':
                url=urlsplit(value.get('url') or value['requested_url'])
                assert fact['value']['origin']==url.scheme+'://'+url.netloc
                assert fact['value']['application_base_path_known'] is False
            else:raise AssertionError('Unregistered projected fact predicate')
            derived+=1
    plan=yaml.safe_load((job/'scenario_plan.yml').read_text());assert plan==state['plan']
    validate_plan(config,plan,state['request'],state['target'],state['retrieval'],state['plan_id'],evidence_registry=runtime_envelope(state),
                  evidence_report=state['compatibility_report'],selected_context=state['selected_context'])
    artifact={'schema_version':'1.0','job_id':job.name,'standard_schemas':'passed','snapshot_and_checkpoint_hashes':'passed',
              'fact_refs_checked':references,'derived_projections_checked':derived,'steps':len(plan['metadata']['steps']),
              'requirement_to_step_links':'passed','generation':result.get('evaluation',{}).get('generation'),
              'live_model_called':False,'scenario_executed':False,'execution_authorized':False}
    write_json(job/'offline_verification.json',artifact);print(json.dumps(artifact))


if __name__=='__main__':main()
