"""Check configured DVWA login only; no CALDERA, model or attack operations."""
import json
from .survey import load_config
from .dvwa_session import verify_session
from urllib.parse import urlsplit


def main():
    config = load_config()
    host = urlsplit(config.get('dvwa_auth', {}).get('base_url', '')).hostname
    if not host:
        print('Chưa cấu hình dvwa_auth.base_url.'); return 1
    from .survey import normalize_request
    normalize_request({'target_ip': host, 'survey_scope': ['web'], 'web_checks': ['dvwa']}, config)
    result = verify_session(host, config)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['session_ready'] is True else 1


if __name__ == '__main__':
    raise SystemExit(main())
