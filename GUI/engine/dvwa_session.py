"""Bounded DVWA login verification. Session secrets stay in memory only."""
import json
import time
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlencode
import re
from urllib.request import build_opener, Request, ProxyHandler, HTTPCookieProcessor, HTTPSHandler
import ssl
from .web_scope import allowed_pairs, url_allowed
from .survey import SameHostRedirect, RedirectScopeError, classify_url_error, now
from .network_io import read_limited


class LoginPage(HTMLParser):
    def __init__(self):
        super().__init__(); self.token = None; self.logout = False; self.selected = None; self.level = None; self.in_security = False; self.links = []; self.forms = []; self.form = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'a' and a.get('href'): self.links.append(a['href'])
        if tag == 'form':
            # Values, tokens, cookies and query strings never leave memory.
            self.form = {'method': a.get('method', 'get').upper(), 'action_path': urlsplit(a.get('action', '')).path[:256], 'inputs': [], 'csrf_present': False}
            self.forms.append(self.form)
        if tag in ('input', 'select', 'textarea') and self.form is not None:
            name = a.get('name', '')[:80]
            if len(self.form['inputs']) < 40:
                self.form['inputs'].append({'name': name, 'type': a.get('type', tag)[:30]})
            if re.search(r'token|csrf', name, re.I): self.form['csrf_present'] = True
        if tag == 'input' and a.get('name') == 'user_token': self.token = a.get('value')
        if tag == 'a' and urlsplit(a.get('href', '')).path.endswith('/logout.php') or tag == 'a' and a.get('href') == 'logout.php': self.logout = True
        if tag == 'select': self.in_security = a.get('name') == 'security'
        if tag == 'option' and self.in_security and 'selected' in a and a.get('value') in ('low','medium','high','impossible'): self.level = a['value']
    def handle_endtag(self, tag):
        if tag == 'select': self.in_security = False
        if tag == 'form': self.form = None


class AuthRedirect(SameHostRedirect):
    def __init__(self, base):
        p = urlsplit(base); super().__init__(p.hostname, p.port or (443 if p.scheme == 'https' else 80)); self.base = base
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urlsplit(newurl)
        allowed = [urlsplit(self.base).path + name for name in ('login.php', 'index.php', 'security.php')]
        if not newurl.startswith(self.base) or destination.username or destination.path not in allowed:
            raise RedirectScopeError('DVWA authentication redirect ngoài base URL đã cấu hình')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def verify_session(ip, config, deadline=None, survey_modules=False):
    registry = config.get('dvwa_auth_by_target')
    options = registry.get(ip, {}) if isinstance(registry, dict) else config.get('dvwa_auth', {})
    result = {'base_url': options.get('base_url'), 'session_ready': None, 'current_security_level': None,
              'checked_at': now(), 'status': 'not_configured', 'checks': []}
    if not options.get('enabled'): return result
    base = options.get('base_url', '')
    p = urlsplit(base)
    if not url_allowed(base, ip, allowed_pairs(config, ip)) or p.hostname != ip or p.scheme not in ('http','https') or p.username or p.query or p.fragment or not p.path.endswith('/'):
        result.update(status='out_of_scope'); return result
    deadline = deadline or time.monotonic() + 20
    try:
        credentials = json.loads(Path(options['credentials_file']).expanduser().read_text())
        if not all(isinstance(credentials.get(k), str) and credentials[k] for k in ('username','password')): raise ValueError()
    except (OSError, ValueError, KeyError):
        result.update(status='credential_unavailable'); return result
    ca = config.get('web_ca_file')
    try:
        context = ssl.create_default_context(cafile=str(Path(ca).expanduser()) if ca else None)
    except (OSError, ValueError):
        result['status'] = 'tls_configuration_error'; return result
    jar = CookieJar()
    opener = build_opener(ProxyHandler({}), AuthRedirect(base), HTTPCookieProcessor(jar), HTTPSHandler(context=context))
    def fetch(path, form=None):
        if time.monotonic() >= deadline: raise TimeoutError('DVWA verification budget exceeded')
        target = urljoin(base,path)
        req = Request(target, data=urlencode(form).encode() if form is not None else None,
                      headers={'User-Agent':'DATN-Survey/2.0'})
        with opener.open(req, timeout=max(.1,min(5,deadline-time.monotonic()))) as response:
            final = response.geturl()
            if not final.startswith(base): raise RedirectScopeError('DVWA final URL ngoài phạm vi')
            raw = read_limited(response, 262144, deadline)
            text = raw[:262144].decode('utf-8','replace')
            page = LoginPage(); page.feed(text)
            result['checks'].append({'path':path,'http_status':response.code,'final_path':urlsplit(final).path,'logout_marker':page.logout,'csrf_present':bool(page.token),'security_level_selected':page.level,'body_truncated':len(raw)>262144})
            return response.code, urlsplit(final).path, page
    try:
        code, _, login = fetch('login.php')
        if code != 200 or not login.token:
            result['status'] = 'login_form_unverified'; return result
        fetch('login.php', {'username':credentials['username'],'password':credentials['password'],'Login':'Login','user_token':login.token})
        code, path, index = fetch('index.php')
        if code != 200 or path != p.path+'index.php' or not index.logout:
            result['status'] = 'authentication_unverified'; return result
        result.update(session_ready=True,status='verified')
        code, path, security = fetch('security.php')
        if code == 200 and path == p.path+'security.php' and security.logout:
            result['current_security_level'] = security.level
        if survey_modules:
            candidates = []
            for href in index.links:
                target = urlsplit(urljoin(base, href))
                prefix = p.path + 'vulnerabilities/'
                # Only exact, discovered module directory links; no action URLs or queries.
                suffix = target.path[len(prefix):] if target.path.startswith(prefix) else ''
                if target.scheme == p.scheme and target.netloc == p.netloc and re.fullmatch(r'[A-Za-z0-9_-]+/', suffix) and not target.query and not target.fragment:
                    relative = 'vulnerabilities/' + suffix
                    if relative not in candidates: candidates.append(relative)
            limit = max(1, min(20, int(config.get('max_dvwa_modules', 12))))
            result['modules'] = []
            result['modules_planned'] = candidates[:limit]
            result['modules_truncated'] = len(candidates) > limit
            for module in candidates[:limit]:
                code, final, page = fetch(module)
                result['modules'].append({'path': module, 'http_status': code, 'authenticated': code == 200 and page.logout and final == p.path + module,
                                          'forms': page.forms[:8], 'forms_truncated': len(page.forms) > 8})
    except (OSError, ValueError) as exc:
        # Avoid echoing provider text which could contain credentials or session material.
        result['status'] = 'modules_check_failed' if 'modules' in result else 'security_check_failed' if result['session_ready'] else 'check_failed'
        result['error_kind'] = classify_url_error(exc)['kind']
        if isinstance(getattr(exc, 'code', None), int): result['http_status'] = exc.code
        cause = getattr(exc, 'reason', exc)
        result['error_type'] = type(cause).__name__
        result['error_errno'] = getattr(cause, 'errno', None)
        if isinstance(cause, PermissionError): result['error_kind'] = 'local_permission_denied'
    finally:
        jar.clear()
    return result
