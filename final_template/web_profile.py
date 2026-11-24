"""Pure web evidence normalization shared by producer and legacy profile reader."""
import copy
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def safe_text(value, limit=500):
    text = str(value)
    text = re.sub(r'(?i)(bearer\s+)[^\s,]+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)((?:password|token|api_key|cookie|phpsessid)\s*[:=]\s*)[^\s;,]+', r'\1[REDACTED]', text)
    text = re.sub(r'AIza[\w-]+|sk-[\w-]{8,}', '[REDACTED]', text)
    text = re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@', r'\1[REDACTED]@', text)
    return ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)[:limit]


def canonical_url(value):
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Expected HTTP(S) URL')
    scheme = parsed.scheme.lower(); host = parsed.hostname.lower()
    host = '[' + host + ']' if ':' in host else host
    port = parsed.port
    netloc = host if port is None or port == (443 if scheme == 'https' else 80) else host + ':' + str(port)
    query = [(k, '[REDACTED]' if re.search(r'(?i)pass|token|secret|session|cookie|auth|api.?key|credential', k) else v)
             for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((scheme, netloc, parsed.path or '/', urlencode(query), ''))


def origin(url):
    parsed = urlsplit(canonical_url(url))
    return urlunsplit((parsed.scheme, parsed.netloc, '/', '', ''))


def valid_response(row):
    code = row.get('http_status')
    return not row.get('error') and type(code) is int and 200 <= code <= 599 and code != 400


def application(row):
    """A path or a 403 alone never identifies an application."""
    code = row.get('http_status')
    if row.get('error') or type(code) is not int or not 200 <= code < 300:
        return None
    title = row.get('title') or ''
    hint = row.get('application_hint')
    name = 'DVWA' if hint == 'DVWA' or re.search(r'(?i)\bDVWA\b|damn vulnerable web application', title) else 'XAMPP' if re.search(r'(?i)welcome to xampp', title) or hint == 'XAMPP' else None
    if not name: return None
    parsed = urlsplit(row['url'])
    match = re.search(r'(?i)/(dvwa|dashboard)(?:/|$)', parsed.path)
    base = parsed.path[:match.end()].rstrip('/') + '/' if match else parsed.path.rsplit('/', 1)[0] + '/'
    return name, urlunsplit((parsed.scheme, parsed.netloc, base, '', ''))


def aggregate_web(sources, evidence_file='web_evidence.json'):
    """Preserve every request, deduplicate observations and group positive services."""
    records = []; observations = []; lookup = {}; origins = {}; apps = {}
    for filename, data in sources:
        legacy = 'requests' not in data
        for index, entry in enumerate(data.get('requests', data.get('services', []))):
            row = copy.deepcopy(entry)
            try: row['url'] = canonical_url(row['url'])
            except (ValueError, KeyError, TypeError): continue
            try: row['requested_url'] = canonical_url(row['requested_url']) if row.get('requested_url') else None
            except (ValueError, TypeError): row['requested_url'] = None
            source_file, _, prefix = filename.partition('#')
            row['source'] = {'file': source_file, 'index': index, 'pointer': prefix + ('/services/' if legacy else '/requests/') + str(index)}
            row['redirect_chain'] = row.get('redirect_chain') if not legacy else None
            row['error'] = row.get('error')
            row['tls_verified'] = row.get('tls_verified')  # Missing in legacy evidence, never infer it.
            records.append(row)
            key = (row['url'], row.get('http_status'), json.dumps(row['error'], sort_keys=True))
            if key not in lookup:
                lookup[key] = len(observations)
                observations.append({k: row.get(k) for k in ['url', 'http_status', 'server_banner', 'title', 'application_hint', 'error', 'tls_verified']})
                observations[-1].update(sources=[], requested_urls=[], redirect_chains=[])
                if not observations[-1]['server_banner']: observations[-1]['server_banner'] = row.get('server')
            observation = observations[lookup[key]]
            observation['sources'].append(row['source'])
            if row['requested_url'] and row['requested_url'] not in observation['requested_urls']: observation['requested_urls'].append(row['requested_url'])
            if row['redirect_chain'] is not None and row['redirect_chain'] not in observation['redirect_chains']: observation['redirect_chains'].append(row['redirect_chain'])
    for index, row in enumerate(observations):
        if not valid_response(row): continue
        base = origin(row['url']); origins.setdefault(base, []).append(index)
        identified = application(row)
        if identified: apps.setdefault(identified, []).append(index)
    groups = []; origin_evidence = []; app_evidence = []
    for base, indices in origins.items():
        oi = len(origin_evidence); origin_evidence.append({'url': base, 'observations': indices})
        group = {'kind': 'web', 'name': urlsplit(base).scheme.upper(), 'url': base, 'status': 'observed',
                 'evidence_ref': evidence_file + '#/origins/' + str(oi), 'applications': []}
        for (name, app_base), app_indices in apps.items():
            if origin(app_base) != base: continue
            ai = len(app_evidence); app_evidence.append({'name': name, 'base_url': app_base, 'observations': app_indices})
            group['applications'].append({'name': name, 'base_url': app_base, 'application_identified': True,
                'session_ready': None, 'current_security_level': None, 'version': None,
                'evidence_ref': evidence_file + '#/applications/' + str(ai)})
        groups.append(group)
    authentication = []
    for filename, data in sources:
        auth = data.get('authentication')
        if not isinstance(auth, dict): continue
        authentication.append(dict(auth, source=filename))
        for group in groups:
            for app in group['applications']:
                if app['name'] == 'DVWA' and app['base_url'] == auth.get('base_url') and auth.get('session_ready') is True:
                    app['session_ready'] = True
                    app['current_security_level'] = auth.get('current_security_level')
                    source_file, _, prefix = filename.partition('#')
                    app['authentication_ref'] = source_file + '#' + prefix + '/authentication'
                    if 'modules' in auth:
                        app['modules_ref'] = source_file + '#' + prefix + '/authentication/modules'
    result = {'source_status': [{'file': filename, 'budget_exhausted': data.get('budget_exhausted', False), 'ports_planned': data.get('ports_planned'), 'ports_checked': data.get('ports_checked')} for filename, data in sources],
            'authentication': authentication, 'format': 'web_evidence_v2', 'requests': records, 'observations': observations,
            'origins': origin_evidence, 'applications': app_evidence, 'services': groups}
    if any('scope' in data for _, data in sources):
        result['scope'] = [dict(scheme=s, port=p) for s, p in dict.fromkeys((entry['scheme'], entry['port']) for _, data in sources for entry in data.get('scope', []))]
    return result


def legacy_web_services(services):
    candidates = [s for s in services if s.get('kind') != 'web' and s.get('url') and type(s.get('http_status')) is int]
    if not candidates: return copy.deepcopy(services)
    groups = aggregate_web([('legacy_profile', {'services': candidates})])['services']
    for group in groups:
        group['evidence_ref'] = '#/services'
        for app in group['applications']: app['evidence_ref'] = '#/services'
    return [copy.deepcopy(s) for s in services if s not in candidates] + groups


def llm_web_summary(data):
    evidence = aggregate_web([('tool_evidence', data)])
    rows = evidence['observations']
    result = {'status': data.get('status', 'unknown'), 'request_count': len(evidence['requests']),
              'unique_observation_count': len(rows), 'observations': [], 'omitted_count': max(0, len(rows) - 24)}
    for row in rows[:24]:
        parsed = urlsplit(row['url'])
        result['observations'].append({'url': row['url'], 'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'http_status': row['http_status'], 'application_hint': row['application_hint'],
            'error_kind': row['error'].get('kind') if row['error'] else None, 'tls_verified': row['tls_verified']})
    if isinstance(data.get('authentication'), dict):
        result['authentication'] = {k: data['authentication'].get(k) for k in ('status', 'session_ready', 'current_security_level', 'error_kind')}
        if 'modules' in data['authentication']:
            result['authentication']['module_count'] = len(data['authentication']['modules'])
            result['authentication']['module_paths'] = [m['path'] for m in data['authentication']['modules']]
    return result
