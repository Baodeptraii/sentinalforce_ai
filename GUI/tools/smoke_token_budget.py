"""Exactly one tiny Gemini generation, synthetic input only, no endpoint/CALDERA.

Requires explicit --allow-one-request. No retry, countTokens, fallback model or
checkpoint resume. The existing configured model/key remain unchanged.
"""
import argparse
import json
import os
import sys
import uuid
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-one-request',action='store_true')
    parser.add_argument('--runtime',type=Path,default=Path('/home/soc/build_scenario_agent'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not args.allow_one_request:parser.error('Explicit --allow-one-request required')
    sys.path.insert(0,str(args.runtime))
    from scenario_agent.config import Config,write_json
    from scenario_agent.llm import Gemini
    from scenario_agent.errors import GeminiAPIError
    from scenario_agent.token_budget import BudgetWait
    config=Config(args.runtime)
    limits={'SOC_LLM_COUNT_MODE':'estimated','SOC_LLM_PARSE_INPUT':'2048','SOC_LLM_PARSE_OUTPUT':'128','SOC_LLM_RUN_REQUESTS':'1'}
    previous={k:os.environ.get(k) for k in limits};os.environ.update(limits)
    args.output.mkdir(parents=True,exist_ok=True)
    report={'model':config.model,'phase':'parse','generation_request_limit':1,'count_tokens_request_limit':0,
            'input_token_allowance_limit':2048,'output_token_limit':128,'input_kind':'synthetic_no_survey_or_endpoint_data',
            'caldera_actions':0,'automatic_retry':False,'checkpoint_resumed':False}
    write_json(args.output/'test-plan.json',report)
    try:
        client=Gemini(config);client.bind_budget('controlled-probe-'+uuid.uuid4().hex,args.output/'token_metrics.json')
        result=client.generate('Return JSON with verdict ok. This is a synthetic protocol/usage test, not a scenario request.',
            {'app_context':{'id':'synthetic-probe','target_id':'synthetic-no-endpoint','mode':'plan_only'},'text':'Synthetic protocol test.'},
            {'type':'object','additionalProperties':False,'required':['verdict'],'properties':{'verdict':{'type':'string','enum':['ok']}}})
        if result!={'verdict':'ok'}:raise ValueError('Unexpected synthetic result')
        report['status']='passed'
    except GeminiAPIError as error:
        report.update(status='provider_error',http_status=error.code,provider_status=error.status,provider_details=error.details)
    except BudgetWait as error:
        report.update(status='budget_blocked_no_generation',reason=error.reason)
    except Exception as error:
        report.update(status='error',error_type=type(error).__name__)
    finally:
        if (args.output/'token_metrics.json').exists():
            metrics=json.loads((args.output/'token_metrics.json').read_text());report.update(requests=metrics['requests'],actual_total_tokens=metrics['actual_total_tokens'],
                unknown_usage_requests=metrics['unknown_usage_requests'],charged_tokens=metrics['charged_tokens'])
        write_json(args.output/'result.json',report)
        for k,v in previous.items():
            if v is None:os.environ.pop(k,None)
            else:os.environ[k]=v
    print(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':main()
