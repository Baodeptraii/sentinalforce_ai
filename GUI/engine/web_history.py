"""Read-only replay of web evidence, including explicitly incomplete legacy logs."""
import json
import re
from final_template.web_profile import aggregate_web


def load_evidence(directory):
    normalized = directory / 'web_evidence.json'
    if normalized.exists():
        return json.loads(normalized.read_text(encoding='utf-8'))
    sources = []
    for path in sorted(directory.glob('tool_*_probe_*.json')):
        record = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(record.get('data'), dict): sources.append((path.name + '#/data', record['data']))
    if not sources:
        for name in ('03_web.json', '04_dvwa.json'):
            path = directory / name
            if path.exists(): sources.append((name, json.loads(path.read_text(encoding='utf-8'))))
    # Old probes stored only the exception class in logs, without the actual reason.
    log = directory / 'execution.log'
    if log.exists():
        rows = []
        for line, text in enumerate(log.read_text(encoding='utf-8').splitlines()):
            match = re.search(r'Chưa đọc được (https?://\S+) \(URLError\)', text)
            if match:
                rows.append({'url': match.group(1), 'http_status': None, 'log_line': line + 1,
                             'error': {'kind': 'legacy_unknown', 'message': 'Bản ghi cũ chỉ có URLError; không lưu nguyên nhân chi tiết hoặc chuỗi chuyển hướng.'}})
        if rows: sources.append(('execution.log', {'services': rows}))
    return aggregate_web(sources)


def public_inspection(evidence):
    # Whitelist fields: no stored HTML/headers/cookies should reach UI accidentally.
    return {'request_count': len(evidence['requests']), 'observation_count': len(evidence['observations']),
            'observations': [{k: row.get(k) for k in ('url', 'http_status', 'server_banner', 'title', 'error', 'sources', 'requested_urls', 'redirect_chains', 'tls_verified')}
                             for row in evidence['observations']]}
