"""Stable downloads and evidence-backed UI state; never runs lab actions."""
from .web_history import load_evidence, public_inspection
from .readiness import assess

import ipaddress
import json
import re
from datetime import datetime, timezone


def read_json(path, default=None):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default


def download_name(job, directory):
    try:
        address = ipaddress.ip_address((job.get('request') or {}).get('target_ip') or (job.get('profile') or {}).get('address')).compressed
        address = address.replace('.', '-').replace(':', '-')
    except (ValueError, TypeError):
        address = 'unknown'
    report = job.get('report') or read_json(directory / 'report.json', {})
    stamp = None
    for value in [report.get('finished_at'), job.get('finished_at'), job.get('created_at')]:
        try:
            stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=timezone.utc)
            break
        except (AttributeError, ValueError):
            continue
    if stamp is None:
        # Stable filesystem timestamp for legacy runs without recorded timestamps.
        stamp = datetime.fromtimestamp((directory / 'target_profile.json').stat().st_mtime, timezone.utc)
    identifier = re.sub('[^a-zA-Z0-9]', '', str(job.get('id', directory.name)))[:32]
    return 'target_profile_%s_%s_%s.json' % (address, stamp.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ'), identifier)


def hydrate(job, directory):
    job['handoff'] = read_json(directory / 'handoff.json')
    job['metrics'] = read_json(directory / 'metrics.json')
    report = read_json(directory / 'report.json', job.get('report', {})) or {}
    job['report'] = report
    if job.get('status') != 'running' and report.get('status') in ('partial', 'completed', 'completed_with_unknowns', 'failed'):
        job['status'] = report['status']
    job['mode'] = report.get('mode', job.get('mode', 'scripts'))
    job['model'] = report.get('model', job.get('model', ''))
    job['warnings'] = list(dict.fromkeys(report.get('warnings', job.get('warnings', []))))
    job['files'] = sorted(str(p.relative_to(directory)) for p in directory.rglob('*')
                          if p.is_file() and p.suffix in ('.json', '.log') and p.name != 'state.json')
    if not job.get('events'):
        events = []
        if (directory / 'preflight.json').exists():
            events.append({'time': None, 'stage': 'preflight', 'text': 'Có kết quả kiểm tra điều kiện trong preflight.json'})
        trace = read_json(directory / 'ai_trace.json', [])
        for event in trace:
            kind = event.get('event')
            if kind == 'tool_request':
                text = 'Model chọn tool: ' + event.get('call', {}).get('function', {}).get('name', '?')
            elif kind == 'tool_result': text = 'Tool %s trả kết quả: %s' % (event.get('tool'), event.get('result', {}).get('status'))
            elif kind == 'llm_error': text = event.get('message', 'Lỗi LLM')
            elif kind == 'model_request': text = 'Gửi yêu cầu model · lượt %s' % event.get('turn')
            elif kind == 'stop': text = 'Dừng: ' + event.get('reason', 'unknown')
            else: continue
            events.append({'time': event.get('at'), 'stage': kind, 'text': text})
        if report:
            events.append({'time': report.get('finished_at'), 'stage': 'stopped', 'text': 'Báo cáo: ' + report.get('status', 'unknown')})
        job['events'] = events
    if not report.get('failure') and report.get('stop_reason') == 'llm_error':
        errors = [e for e in read_json(directory / 'ai_trace.json', []) if e.get('event') == 'llm_error']
        if errors:
            report['failure'] = {'stage': 'model', 'turn': report.get('steps'), 'message': errors[-1].get('message', 'Lỗi LLM')}
    if job.get('profile') and job.get('request'):
        evidence = load_evidence(directory)
        job['web_inspection'] = public_inspection(evidence)
        if not report.get('web_readiness'):
            completed = {'probe_web', 'probe_dvwa'} if evidence['requests'] else set()
            view = assess(job['request'], job['profile'], evidence, completed)
            job['web_readiness'] = view['web_readiness']
            job['missing_information'] = view['missing_information']
        else:
            job['web_readiness'] = report['web_readiness']
            job['missing_information'] = report.get('missing_information', [])
    if (directory / 'target_profile.json').exists():
        job['download_name'] = download_name(job, directory)
    return job
