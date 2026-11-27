"""Survey tools and deterministic orchestration, ready to expose as AI tools later."""
import copy
import re
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import queue
import threading
import sys
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .runner import API, save
from .lifecycle import Cancelled, check_cancel
from .network_io import read_limited
from .web_scope import allowed_pairs, url_allowed
from .web_limitations import limitations
from .evidence_refs import validate_profile_refs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from final_template.contracts import validate_document
from final_template.web_profile import aggregate_web, canonical_url, safe_text


def now():
    return datetime.now(timezone.utc).isoformat()


def load_config():
    path = Path(os.environ.get('SURVEY_CONFIG_FILE', str(ROOT / 'config.json'))).expanduser().resolve()
    data = json.loads((path if path.exists() else ROOT / 'config.example.json').read_text(encoding='utf-8'))
    data['caldera_url'] = os.environ.get('CALDERA_URL', data['caldera_url']).rstrip('/')
    data['key_file'] = os.environ.get('CALDERA_KEY_FILE', data['key_file'])
    data.setdefault('orchestration_mode', 'scripts')
    if data['orchestration_mode'] not in ('ai', 'scripts'):
        raise ValueError('orchestration_mode phải là ai hoặc scripts.')
    return data


def api_for(config):
    key = os.environ.get('CALDERA_KEY')
    if not key:
        try:
            key = Path(config['key_file']).expanduser().read_text().strip()
        except OSError:
            raise ValueError('Chưa có API key. Đặt CALDERA_KEY hoặc cấu hình key_file trên máy chạy GUI.') from None
    if not key:
        raise ValueError('API key đang trống.')
    return API(config['caldera_url'], key)


def normalize_request(data, config):
    try:
        ip = ipaddress.ip_address(str(data.get('target_ip', '')).strip())
    except ValueError:
        raise ValueError('Nhập địa chỉ IPv4 hợp lệ, ví dụ 192.168.73.137.') from None
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise ValueError('Chỉ hỗ trợ IPv4 của endpoint trong mạng lab được cấu hình.')
    if not any(ip in ipaddress.ip_network(n) for n in config['allowed_networks']):
        raise ValueError('IP nằm ngoài allowed_networks. Cập nhật cấu hình mạng lab trước khi khảo sát.')
    scope = data.get('survey_scope')
    if not isinstance(scope, list) or not scope or any(s not in ('endpoint', 'web') for s in scope):
        raise ValueError('Chọn Endpoint, Dịch vụ web hoặc Cả hai.')
    web_checks = data.get('web_checks', ['dvwa'] if 'web' in scope else [])
    if not isinstance(web_checks, list) or any(x != 'dvwa' for x in web_checks):
        raise ValueError('web_checks chỉ hỗ trợ dvwa trong phiên bản này.')
    if web_checks and 'web' not in scope:
        raise ValueError('Chỉ chọn DVWA khi phạm vi có dịch vụ web.')
    return {'target_ip': str(ip), 'survey_scope': sorted(set(scope)), 'web_checks': sorted(set(web_checks))}


def fresh(agent, config):
    try:
        stamp = datetime.fromisoformat(agent['last_seen'].replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - stamp.replace(tzinfo=stamp.tzinfo or timezone.utc)).total_seconds()
        return -60 <= age <= config['agent_max_age_seconds']
    except (KeyError, TypeError, ValueError):
        return False


def preflight(data, config):
    result = {'ready': False, 'checks': [], 'agent': None, 'request': None}
    def check(name, state, detail):
        result['checks'].append({'name': name, 'state': state, 'detail': detail})
    try:
        request = normalize_request(data, config)
        result['request'] = request
        check('Phạm vi mạng', 'pass', request['target_ip'] + ' thuộc mạng được phép.')
    except ValueError as exc:
        check('Phạm vi mạng', 'fail', str(exc)); return result
    if config.get('orchestration_mode') == 'ai':
        try:
            if sys.version_info < (3, 11):
                raise ValueError('Chế độ AI cần Python 3.11+; dùng môi trường GUI riêng.')
            from . import contracts
            from langgraph.graph import StateGraph
            from .llm import settings
            llm = settings(config)
            check('Cấu hình AI', 'pass', 'Đã cấu hình model %s; khả năng gọi API được xác minh khi chạy.' % llm['model'])
        except (ImportError, ValueError) as exc:
            check('Cấu hình AI', 'fail', str(exc) if isinstance(exc, ValueError) else 'Thiếu dependency AI. Chạy uv sync --frozen trong GUI.'); return result
    try:
        api = api_for(config)
        api.deadline = time.monotonic() + 30
        agents = api.call('agents')
        if not isinstance(agents, list) or not all(isinstance(a, dict) for a in agents):
            raise ValueError('CALDERA agents API trả về dữ liệu không đúng định dạng.')
        check('CALDERA API', 'pass', 'Kết nối và xác thực API thành công.')
    except ValueError as exc:
        check('CALDERA API', 'fail', str(exc)); return result
    except HTTPError as exc:
        check('CALDERA API', 'fail', 'API trả HTTP %s. Kiểm tra API key và URL.' % exc.code); return result
    except (OSError, ValueError, TypeError):
        check('CALDERA API', 'fail', 'Không đọc được API. Kiểm tra CALDERA đang chạy và kết nối từ máy GUI.'); return result
    candidates = [a for a in agents if request['target_ip'] in (a.get('host_ip_addrs') or []) and fresh(a, config)]
    if len(candidates) != 1:
        detail = 'Không có Sandcat liên lạc trong %s giây gần đây khớp IP này.' % config['agent_max_age_seconds'] if not candidates else 'Có nhiều Sandcat online trùng IP. Dừng agent thừa trước khi chạy.'
        check('Sandcat đúng mục tiêu', 'fail', detail); return result
    a = candidates[0]
    result['agent'] = {k: a.get(k) for k in ('paw', 'host', 'platform', 'group', 'trusted', 'last_seen', 'executors', 'privilege', 'host_ip_addrs')}
    check('Sandcat đúng mục tiêu', 'pass', '%s · %s' % (a.get('host'), a['paw']))
    supported = a.get('platform') == 'windows' and a.get('trusted') and 'psh' in (a.get('executors') or [])
    check('Công cụ khảo sát', 'pass' if supported else 'fail', 'Windows + PowerShell sẵn sàng.' if supported else 'Bản hiện tại cần Windows, Sandcat trusted và executor psh.')
    component = 'planner'
    try:
        planners = api.call('planners')
        component = 'source'
        sources = api.call('sources')
        component = 'operation'
        operations = api.call('operations')
        component = 'dữ liệu planner/source/operation'
        busy = any(op.get('state') not in ('finished', 'out_of_time') and any(x.get('paw') == a['paw'] for x in op.get('host_group', [])) for op in operations)
        ok = any(x['name'] == 'atomic' for x in planners) and any(x['name'] == 'basic' for x in sources)
        check('Operation khảo sát', 'pass' if ok and not busy else 'fail', 'Planner và source sẵn sàng, endpoint không bận.' if ok and not busy else 'Thiếu planner atomic/source basic hoặc endpoint thuộc operation chưa kết thúc.')
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        reason = 'phản hồi vượt giới hạn kích thước' if isinstance(exc, ValueError) and str(exc) == 'CALDERA response exceeds limit' else type(exc).__name__
        check('Operation khảo sát', 'fail', 'Không đọc được %s (%s).' % (component, reason))
    check('Quyền thực thi', 'pass' if a.get('privilege') == 'Elevated' else 'warn', 'Quyền hiện tại: %s. Trường không đọc được sẽ được giữ chưa xác minh.' % a.get('privilege', 'unknown'))
    result['ready'] = not any(x['state'] == 'fail' for x in result['checks'])
    return result


class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self.title = ''; self.in_title = False
    def handle_starttag(self, tag, attrs):
        if tag == 'title': self.in_title = True
        if tag == 'a':
            href = dict(attrs).get('href')
            if href: self.links.append(href)
    def handle_endtag(self, tag):
        if tag == 'title': self.in_title = False
    def handle_data(self, text):
        if self.in_title: self.title += text


class RedirectScopeError(URLError):
    pass


def classify_url_error(exc):
    reason = exc.reason if isinstance(exc, URLError) else exc
    text = str(reason).lower()
    if isinstance(exc, RedirectScopeError): kind = 'out_of_scope_redirect'
    elif isinstance(reason, ssl.SSLCertVerificationError):
        kind = 'hostname_mismatch' if getattr(reason, 'verify_code', None) in (62, 64) or any(x in text for x in ['hostname mismatch', 'ip address mismatch', 'not valid for']) else 'tls_certificate'
    elif isinstance(reason, socket.gaierror): kind = 'dns'
    elif isinstance(reason, (TimeoutError, socket.timeout)) or 'timed out' in text: kind = 'timeout'
    elif isinstance(reason, ConnectionRefusedError) or getattr(reason, 'errno', None) in (61, 111, 10061): kind = 'refused'
    elif isinstance(reason, ssl.SSLError): kind = 'tls_error'
    elif 'redirect' in text: kind = 'redirect_error'
    else: kind = 'other'
    return {'kind': kind, 'message': safe_text(reason)}


class SameHostRedirect(HTTPRedirectHandler):
    max_redirections = 4
    max_repeats = 2

    def __init__(self, ip, port, allowed_ports=None, pairs=None):
        self.ip, self.port = ip.lower(), port
        self.allowed_ports = set(allowed_ports or [port])
        self.pairs = pairs if pairs is not None else [(scheme, p) for p in self.allowed_ports for scheme in ('http', 'https')]
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        try:
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            allowed = url_allowed(newurl, self.ip, self.pairs)
        except ValueError:
            allowed = False
        try: destination = canonical_url(newurl)
        except (ValueError, TypeError): destination = '[invalid URL]'
        entry = {'from': canonical_url(req.full_url), 'to': destination, 'http_status': code, 'blocked': not allowed}
        self.chain.append(entry)
        if not allowed:
            raise RedirectScopeError('Chuyển hướng ngoài mục tiêu hoặc cổng được phép đã bị chặn')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def probe_web(ip, endpoint, config, log, deadline=None):
    discovered = [int(x['LocalPort']) for x in endpoint.get('data', {}).get('listeners', []) if x.get('LocalPort')]
    pairs = allowed_pairs(config, ip)
    ports = list(dict.fromkeys(port for _, port in pairs if 'web_candidate_ports' not in config or port in config['web_candidate_ports']))[:config['max_web_ports']]
    deadline = deadline if deadline is not None else time.monotonic() + 60
    ca_file = config.get('web_ca_file')
    if ca_file:
        ca_file = Path(ca_file).expanduser()
        if not ca_file.is_absolute(): raise ValueError('web_ca_file phải là đường dẫn CA tuyệt đối hoặc ~/...')
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    records = []
    for port in ports:
        if time.monotonic() >= deadline: break
        for scheme in [s for s in (('https', 'http') if port in (443, 8443) else ('http', 'https')) if (s, port) in pairs]:
            root = '%s://%s:%d/' % (scheme, ip, port)
            queue = [canonical_url(urljoin(root, path)) for path in config.get('web_paths', ['/'])
                     if isinstance(path, str) and path.startswith('/') and not path.startswith('//') and not urlsplit(path).query and not urlsplit(path).fragment]
            seen = set(); attempts = 0; responded = False
            redirect = SameHostRedirect(ip, port, ports, pairs)
            opener = build_opener(ProxyHandler({}), redirect, HTTPSHandler(context=context))
            while queue and attempts < config['max_web_pages'] and time.monotonic() < deadline:
                url = queue.pop(0)
                if url in seen or not url_allowed(url, ip, pairs): continue
                seen.add(url); attempts += 1; redirect.chain = []
                record = {'requested_url': url, 'url': url, 'http_status': None, 'server_banner': None,
                          'title': None, 'application_hint': None, 'tls_verified': None, 'error': None,
                          'redirect_chain': [], 'checked_at': now()}
                try:
                    request = Request(url, headers={'User-Agent': 'DATN-Survey/2.0'})
                    try:
                        response = opener.open(request, timeout=max(.1, min(4, deadline - time.monotonic())))
                    except HTTPError as exc:
                        if 300 <= exc.code < 400: raise URLError('redirect_failed') from None
                        response = exc
                    with response:
                        raw_body = read_limited(response, 262144, deadline)
                        record['body_truncated'] = len(raw_body) > 262144
                        body = raw_body[:262144].decode('utf-8', 'replace')
                        parser = Page(); parser.feed(body)
                        final_url = canonical_url(response.geturl()); seen.add(final_url)
                        parsed = urlsplit(final_url)
                        # Guard even custom/malformed opener responses, not just redirect callbacks.
                        final_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                        if not url_allowed(final_url, ip, pairs): raise RedirectScopeError('Final URL ngoài phạm vi')
                        record.update(url=final_url, http_status=response.code,
                            server_banner=safe_text(response.headers.get('Server', ''), 200) or None,
                            title=safe_text(parser.title.strip(), 160),
                            tls_verified=True if parsed.scheme == 'https' else None)
                        title = parser.title.lower()
                        if re.search(r'\bdvwa\b|damn vulnerable web application', title) or 'damn vulnerable web application' in body.lower(): record['application_hint'] = 'DVWA'
                        elif 'welcome to xampp' in title: record['application_hint'] = 'XAMPP'
                        responded = responded or response.code != 400
                        log('HTTP %s · %s' % (response.code, final_url))
                        for link in parser.links:
                            try:
                                dest = urlsplit(urljoin(final_url, link))
                                link_port = dest.port or (443 if dest.scheme == 'https' else 80)
                            except ValueError:
                                continue
                            if url_allowed(dest.geturl(), ip, pairs) and not dest.query and not dest.fragment and not dest.username and dest.path.endswith('/'):
                                candidate = canonical_url(dest.geturl())
                                if candidate not in seen and len(queue) < config['max_web_pages']: queue.append(candidate)
                except (OSError, ValueError) as exc:
                    record['error'] = classify_url_error(exc)
                    log('Probe lỗi %s · %s · %s' % (record['error']['kind'], url, record['error']['message']))
                record['redirect_chain'] = copy.deepcopy(redirect.chain)
                records.append(record)
                if record['error'] and record['error']['kind'] in ('dns', 'timeout', 'refused', 'tls_certificate', 'hostname_mismatch', 'tls_error'):
                    break  # Same-origin transport failed; avoid repeating identical connection errors per path.
            # Each explicitly allowed protocol is checked independently.
    return {'format': 'web_probe_v2', 'collected_at': now(), 'target_ip': ip,
            'status': 'observed' if any(r['http_status'] is not None for r in records) else 'unknown',
            'scope': [{'scheme': s, 'port': p} for s, p in pairs], 'requests': records, 'ports_planned': ports,
            'ports_checked': sorted({urlsplit(r['requested_url']).port or (443 if urlsplit(r['requested_url']).scheme == 'https' else 80) for r in records}),
            'request_count': len(records), 'budget_exhausted': time.monotonic() >= deadline,
            'limitations': limitations()}


def build_profile(request, agent, endpoint, web):
    scope = request['survey_scope']; d = endpoint['data']; services = []
    if 'endpoint' in scope:
        services = [{'name': x['display_name'], 'service_name': x['name'], 'state': x['state'], 'status': 'observed'} for x in d.get('services', [])]
        if d.get('listeners'):
            services.append({'name': 'TCP listeners', 'kind': 'endpoint', 'status': 'observed', 'listeners': d['listeners'], 'processes': d.get('processes', []), 'evidence_ref': '02_endpoint.json#/data/listeners'})
        services.append({'name': 'Sandcat', 'paw': agent['paw'], 'privilege': agent.get('privilege'), 'status': 'observed'})
    normalized_web = web if web and web.get('format') == 'web_evidence_v2' else aggregate_web([('03_web.json', web)]) if web else aggregate_web([])
    if 'web' in scope:
        services.extend(normalized_web['services'])
    profile = {'id': 'target-' + request['target_ip'].replace('.', '-'),
            'os': {'name': d.get('os_name'), 'version': d.get('os_version'), 'architecture': d.get('architecture'), 'hostname': d.get('hostname'), 'status': 'observed'},
            'address': request['target_ip'], 'services': services,
            'capabilities': {'sandcat_online': True, 'powershell_ready': True, 'admin_ready': d['is_elevated'], 'web_runner_ready': True if 'web' in scope else None,
                             'web_reachable': True if normalized_web['services'] else None, 'dvwa_session_ready': None},
            'telemetry': {'process_events': None, 'network_events': None, 'web_access_logs': None, 'wazuh_ingestion': None}}
    if 'web' in scope:
        profile['capabilities']['dvwa_session_ready'] = True if any(a.get('session_ready') is True for service in normalized_web['services'] for a in service.get('applications', []) if a['name'] == 'DVWA') else None
        profile['capabilities']['application_identified'] = True if normalized_web['applications'] else None
    return validate_document(profile, 'target_profile')


def collect_endpoint(request, agent, config, directory, log):
    cmd = [sys.executable, '-u', str(ROOT / 'engine/runner.py'), 'run', '--paw', agent['paw'], '--expected-ip', request['target_ip'],
           '--expected-host', agent['host'], '--url', config['caldera_url'], '--key-file', str(Path(config['key_file']).expanduser()),
           '--timeout', str(config['operation_timeout_seconds']), '--output-dir', str(directory / 'caldera')]
    cmd.extend(['--max-age', str(config['agent_max_age_seconds'])])
    # No shell and no password in argv. Runner's own timeout pauses its operation and restores group.
    check_cancel(directory)
    cmd.extend(['--cancel-file', str(directory / 'cancel.requested')])
    messages = queue.Queue()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
    def read_output():
        for line in proc.stdout: messages.put(line.strip())
    reader = threading.Thread(target=read_output, daemon=True); reader.start()
    stop_at = time.monotonic() + config['operation_timeout_seconds'] + 25
    stopping = False
    try:
        while proc.poll() is None:
            if (directory / 'cancel.requested').exists() and not stopping:
                proc.terminate(); stopping = True; stop_at = min(stop_at, time.monotonic() + 25)
            if time.monotonic() >= stop_at:
                if not stopping:
                    proc.terminate(); stopping = True; stop_at = time.monotonic() + 25
                else:
                    proc.kill()
                    save(directory / 'recovery_required.json', {'reason': 'Runner exceeded cleanup deadline', 'inspect': 'caldera/summary.json', 'automatic_retry_allowed': False})
                    raise TimeoutError('Runner stopped by watchdog; inspect CALDERA cleanup journal before retrying.')
            try: log(messages.get(timeout=.2))
            except queue.Empty: pass
        reader.join(timeout=1)
        while not messages.empty(): log(messages.get_nowait())
        check_cancel(directory)
        if proc.returncode != 0:
            raise RuntimeError('Khảo sát endpoint thất bại. Xem nhật ký và bằng chứng CALDERA của lượt này.')
    finally:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=25)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        proc.stdout.close()
    endpoint = json.loads((directory / 'caldera/endpoint-info.json').read_text(encoding='utf-8'))
    save(directory / '02_endpoint.json', endpoint)
    return endpoint


def execute(request, config, directory, update, log):
    check_cancel(directory)
    request = normalize_request(request, config)
    save(directory / 'survey_request.json', request)
    update('preflight', None, 'Kiểm tra lại điều kiện cần')
    checks = preflight(request, config)
    save(directory / 'preflight.json', checks)
    if not checks['ready']:
        raise RuntimeError('Điều kiện cần đã thay đổi. ' + ' '.join(x['detail'] for x in checks['checks'] if x['state'] == 'fail'))
    agent = checks['agent']; save(directory / '01_agent.json', agent)
    if config.get('orchestration_mode') == 'ai':
        from .agent import run_agent
        return run_agent(request, agent, config, directory, update, log)
    if config.get('orchestration_mode', 'scripts') != 'scripts':
        raise ValueError('orchestration_mode phải là ai hoặc scripts.')
    update('tool_running', None, 'Sandcat đang khảo sát máy mục tiêu')
    endpoint = collect_endpoint(request, agent, config, directory, log)
    update('tool_result', None, 'Đã thu bằng chứng endpoint')
    from .readiness import assess
    sources = []; completed = set()
    if 'web' in request['survey_scope']:
        for tool, filename, paths in [('probe_web', '03_web.json', config.get('web_paths', ['/']))] + ([('probe_dvwa', '04_dvwa.json', config.get('dvwa_paths', ['/dvwa/', '/dvwa/login.php']))] if 'dvwa' in request.get('web_checks', []) else []):
            check_cancel(directory)
            update('tool_running', None, 'Khảo sát web: ' + tool)
            raw = probe_web(request['target_ip'], endpoint, dict(config, web_paths=paths), log)
            if tool == 'probe_dvwa':
                from .dvwa_session import verify_session
                raw['authentication'] = verify_session(request['target_ip'], config)
            raw['limitations'] = limitations(raw.get('authentication'))
            save(directory / filename, raw); sources.append((filename, raw)); completed.add(tool)
            update('tool_result', None, 'Đã ghi bằng chứng: ' + tool)
    web = aggregate_web(sources)
    save(directory / 'web_evidence.json', web)
    update('profile', None, 'Chuẩn hóa kết quả và xuất JSON')
    profile = build_profile(request, agent, endpoint, web)
    from .telemetry import apply as apply_telemetry
    telemetry = apply_telemetry(profile, request, agent, endpoint, config, directory, update, log)
    validate_document(profile, 'target_profile')
    validate_profile_refs(directory, profile)
    save(directory / 'target_profile.json', profile)
    readiness = assess(request, profile, web, completed, config=config, telemetry=telemetry)
    warnings = list(dict.fromkeys(readiness['warnings'] + list(endpoint['data'].get('limitations', []))))
    save(directory / 'report.json', {'status': 'partial' if readiness['required_missing'] else 'completed_with_unknowns', 'mode': 'scripts', 'finished_at': now(), 'scope': request['survey_scope'], 'warnings': warnings, 'missing_information': readiness['missing_information'], 'web_readiness': readiness['web_readiness'], 'detection_result': 'not_evaluated', 'telemetry': telemetry})
    return profile, warnings
