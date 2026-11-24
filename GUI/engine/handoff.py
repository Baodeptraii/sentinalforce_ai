"""Evidence-preserving handoff. The six-field profile stays compatible."""
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone

from .runner import save
from .evidence_refs import validate_profile_refs


def build_handoff(directory, job):
    profile_path = directory / 'target_profile.json'
    if not profile_path.exists(): return None
    profile = json.loads(profile_path.read_text(encoding='utf-8'))
    validate_profile_refs(directory, profile)
    report_path = directory / 'report.json'
    report = json.loads(report_path.read_text(encoding='utf-8')) if report_path.exists() else {}
    evidence = []
    for path in sorted(directory.rglob('*.json')):
        if path.name in ('state.json', 'handoff.json') or path.is_symlink(): continue
        if directory.resolve() not in path.resolve().parents: continue
        evidence.append({'file': path.relative_to(directory).as_posix(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    result = {
        'format': 'survey_handoff_v1', 'run_id': job['id'],
        'target_ip': profile['address'], 'scope': job.get('request', {}),
        'started_at': job.get('created_at'), 'finished_at': job.get('finished_at') or report.get('finished_at'),
        'profile_file': 'target_profile.json', 'report_file': 'report.json' if report_path.exists() else None,
        'status': report.get('status', job.get('status', 'unknown')),
        'readiness': {'planning': 'evidence_available' if report.get('status') in ('completed', 'completed_with_unknowns') else 'partial_evidence',
                      'execution': 'requires_scenario_preflight', 'detection': 'not_evaluated'},
        'freshness': {'policy': 'Re-survey if target, services or session changed; always preflight before execution.',
                      'session_is_observation_only': True, 'credential_or_cookie_included': False},
        'missing_information': report.get('missing_information', []), 'evidence': evidence,
    }
    save(directory / 'handoff.json', result)
    return result


def bundle(directory):
    """Only include attested JSON, never arbitrary credentials/logs or symlinks."""
    if (directory / 'survey_v2' / 'scenario_handoff.json').exists():
        from .survey_output_v2 import bundle_v2
        return bundle_v2(directory / 'survey_v2')
    metadata = json.loads((directory / 'handoff.json').read_text(encoding='utf-8'))
    stream = io.BytesIO()
    total = 0
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('handoff.json', json.dumps(metadata, ensure_ascii=False, indent=2))
        for entry in metadata['evidence']:
            path = directory / entry['file']
            if path.is_symlink() or directory.resolve() not in path.resolve().parents:
                raise ValueError('Evidence path escapes run directory')
            total += path.stat().st_size
            if total > 32_000_000: raise ValueError('Evidence bundle exceeds 32 MB; inspect files locally')
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != entry['sha256']:
                raise ValueError('Evidence changed since handoff was built')
            archive.writestr(entry['file'], data)
    return stream.getvalue()
