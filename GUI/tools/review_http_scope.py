"""Replay recorded HTTP:80 evidence under current policy; never contacts the lab."""
import copy
import hashlib
import json
from pathlib import Path
import sys
PROJECT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(PROJECT),str(PROJECT/'GUI')]
from engine.survey import build_profile, load_config
from engine.web_scope import allowed_pairs, url_allowed
from engine.web_limitations import limitations
from engine.readiness import assess
from engine.evidence_refs import validate_profile_refs
from engine.contracts import TargetProfile
from final_template.web_profile import aggregate_web


def review(run_id):
    if Path(run_id).name != run_id: raise ValueError('Invalid run id')
    source=PROJECT/'GUI/outputs'/run_id
    dest=PROJECT/'GUI/review'/('http-scope-'+run_id);dest.mkdir(parents=True,exist_ok=True)
    def read(name): return json.loads((source/name).read_text())
    def save(name,data): (dest/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    request=read('survey_request.json'); config=load_config();pairs=allowed_pairs(config,request['target_ip'])
    sources=[];excluded=0;hashes={}
    for path in sorted(source.glob('tool_*_probe_*.json')):
        record=copy.deepcopy(read(path.name));data=record['data']
        if not isinstance(data,dict):continue
        hashes[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        rows=data.get('requests',data.get('services',[]))
        kept=[r for r in rows if url_allowed(r['url'],request['target_ip'],pairs)]
        excluded+=len(rows)-len(kept)
        data.pop('services',None);data['requests']=kept
        data['scope']=[dict(scheme=s,port=p) for s,p in pairs]
        data['ports_checked']=list(dict.fromkeys(p for _,p in pairs))
        data['limitations']=limitations(data.get('authentication'))
        record['review']={'mode':'offline_filtered_replay','source_run':run_id,'note':'Historical evidence subset, not a new survey.'}
        save(path.name,record);sources.append((path.name+'#/data',data))
    evidence=aggregate_web(sources);save('web_evidence.json',evidence)
    profile=build_profile(request,read('01_agent.json'),read('02_endpoint.json'),evidence)
    TargetProfile.model_validate(profile);validate_profile_refs(dest,profile)
    ready=assess(request,profile,evidence,{'probe_web','probe_dvwa'},config=config)
    report=read('report.json');report.update(missing_information=ready['missing_information'],warnings=ready['warnings'],web_readiness=ready['web_readiness'])
    report['review']={'mode':'offline_filtered_replay','source_run':run_id,'excluded_out_of_scope_records':excluded,'source_sha256':hashes,'note':'No requests sent. Timestamps and verified session are historical, not reverified. Original run contained out-of-scope requests; it was not executed using the new policy.'}
    save('target_profile.json',profile);save('report.json',report);save('survey_request.json',request)
    print('Offline review:',dest)
    print('Excluded historical records outside new scope:',excluded)
    print('Warnings:',len(report['warnings']))
    return dest

if __name__=='__main__':review(sys.argv[1])
