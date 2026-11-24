"""Offline review only: never contacts a model, CALDERA or the target."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(PROJECT), str(PROJECT / 'GUI')]
from engine.web_history import load_evidence
from engine.readiness import assess
from engine.survey import build_profile
from engine.contracts import TargetProfile
from engine.evidence_refs import validate_profile_refs


def replay(source, destination):
    source, destination = source.resolve(), destination.resolve()
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError('Review phải ở thư mục riêng, không nằm trong outputs của lượt gốc.')
    required = ['survey_request.json', '01_agent.json', '02_endpoint.json', 'target_profile.json', 'report.json']
    def read(name): return json.loads((source / name).read_text(encoding='utf-8'))
    for name in required:
        if not (source / name).is_file(): raise FileNotFoundError(source / name)
    request, evidence = read('survey_request.json'), load_evidence(source)
    profile = TargetProfile.model_validate(build_profile(request, read('01_agent.json'), read('02_endpoint.json'), evidence)).model_dump(mode='json', exclude_unset=True)
    completed = set()
    for path in source.glob('tool_*.json'):
        record = read(path.name)
        if record.get('status') == 'ok': completed.add(record['tool'])
    if (source / '03_web.json').exists(): completed.add('probe_web')
    if (source / '04_dvwa.json').exists(): completed.add('probe_dvwa')
    ready = assess(request, profile, evidence, completed)
    report = read('report.json')
    report.update(missing_information=ready['missing_information'], web_readiness=ready['web_readiness'], warnings=ready['warnings'])
    if ready['required_missing']: report['status'] = 'partial'
    report['review'] = {'offline': True, 'source_run': source.name, 'timestamps': 'Thời điểm gốc của lượt chạy; đây không phải lần khảo sát mới.'}
    old = read('target_profile.json')
    comparison = {'source_run': source.name, 'source_hashes': {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in required},
        'before_service_count': len(old['services']), 'after_service_count': len(profile['services']),
        'web_origins': [s['url'] for s in evidence['services']], 'applications': evidence['applications'],
        'request_count': len(evidence['requests']), 'unique_observation_count': len(evidence['observations']),
        'duplicate_observations': len(evidence['requests']) - len(evidence['observations']),
        'limitations': ['Bằng chứng cũ không lưu nguyên nhân cụ thể URLError và chuỗi chuyển hướng; giữ legacy_unknown, không suy đoán TLS certificate.', 'Không thực hiện GET, đăng nhập, operation hoặc gọi API LLM.']}
    destination.mkdir(parents=True, exist_ok=True)
    for path in source.glob('*.json'):
        if path.name in ('01_agent.json', '02_endpoint.json', 'survey_request.json', '03_web.json', '04_dvwa.json') or path.name.startswith('tool_'):
            if path.is_symlink(): raise ValueError('Symlink evidence refused')
            shutil.copy2(path, destination / path.name)
    log = source / 'execution.log'
    if log.exists():
        if log.is_symlink(): raise ValueError('Symlink evidence refused')
        shutil.copy2(log, destination / log.name)
    for name, value in [('target_profile.json', profile), ('web_evidence.json', evidence), ('report.json', report), ('comparison.json', comparison)]:
        (destination / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    validate_profile_refs(destination, profile)
    return comparison


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--review-dir', type=Path)
    args = parser.parse_args()
    if Path(args.run_id).name != args.run_id: parser.error('run_id chỉ gồm tên thư mục trong outputs')
    result = replay(PROJECT / 'GUI/outputs' / args.run_id, args.review_dir or PROJECT / 'GUI/review' / ('web-' + args.run_id))
    print(json.dumps({k: v for k, v in result.items() if k not in ('source_hashes', 'applications')}, ensure_ascii=False, indent=2))
