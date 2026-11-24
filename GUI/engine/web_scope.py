"""Administrator-owned protocol/port allowlist, independent of model discoveries."""
from urllib.parse import urlsplit


def allowed_pairs(config, ip):
    rows = config.get('web_scope_by_target', {}).get(ip, config.get('web_scope'))
    if rows is None:
        rows = [{'scheme': scheme, 'port': port} for port in config.get('web_ports', [80, 443]) for scheme in ('http', 'https')]
    if not isinstance(rows, list): raise ValueError('web_scope phải là danh sách scheme/port')
    pairs = []
    for row in rows:
        scheme, port = row.get('scheme'), row.get('port')
        if scheme not in ('http','https') or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('web_scope không hợp lệ')
        if (scheme,port) not in pairs: pairs.append((scheme,port))
    return pairs


def url_allowed(url, ip, pairs):
    try:
        p = urlsplit(url)
        return p.hostname == ip.lower() and not p.username and not p.password and (p.scheme, p.port or (443 if p.scheme == 'https' else 80)) in pairs
    except (ValueError, TypeError): return False
