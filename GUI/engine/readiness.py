"""Deterministic readiness: completed checks are distinct from target readiness."""

def assess(request, profile, evidence, completed, endpoint_ready=True, failed_tools=(), config=None, telemetry=None):
    missing = []
    def gap(field, status, reason, required=False):
        missing.append(dict(field=field, status=status, reason=reason, required=required))
    web = 'web' in request['survey_scope']
    dvwa = web and 'dvwa' in request.get('web_checks', [])
    if 'endpoint' in request['survey_scope'] and not endpoint_ready:
        gap('endpoint_inventory_unverified', 'check_failed' if 'collect_endpoint' in failed_tools else 'not_checked', 'Tool chưa trả về inventory endpoint hợp lệ.', True)
    if web:
        if any(row.get('budget_exhausted') for row in evidence.get('source_status', [])):
            gap('web_probe_budget', 'check_failed', 'Hết ngân sách thời gian khi khảo sát web; không coi các cổng chưa thử là đã kiểm tra.', True)
        for tool in ['probe_web'] + (['probe_dvwa'] if dvwa else []):
            if tool not in completed:
                gap(tool + '_not_completed', 'check_failed' if tool in failed_tools else 'not_checked', 'Tool chưa thực hiện xong hoặc lỗi; xem bản ghi tool.', True)
        if not evidence['services']:
            gap('web_reachable', 'check_failed' if evidence['observations'] else 'not_checked', 'Chưa có phản hồi xác nhận dịch vụ HTTP(S); xem từng URL và lỗi kết nối.')
        if not evidence['applications']:
            gap('application_identified', 'check_failed' if evidence['observations'] else 'not_checked', 'Chưa có dấu hiệu nhận diện ứng dụng đủ căn cứ; đường dẫn hoặc 403 không đủ.')
        if dvwa:
            if not any(app['name'] == 'DVWA' for app in evidence['applications']):
                gap('dvwa_identity', 'check_failed' if 'probe_dvwa' in completed else 'not_checked', 'Chưa nhận diện DVWA từ phản hồi hợp lệ.')
            apps = [a for service in profile['services'] for a in service.get('applications', []) if a['name'] == 'DVWA']
            auth = evidence.get('authentication', [])
            status = auth[-1].get('status') if auth else 'not_configured'
            if not any(a.get('session_ready') is True for a in apps):
                gap('dvwa_session_ready', 'out_of_scope' if status == 'out_of_scope' else 'credential_required' if status in ('not_configured', 'credential_unavailable') else 'check_failed', 'Chưa xác minh phiên DVWA · ' + status + ((' · ' + auth[-1]['error_kind']) if auth and auth[-1].get('error_kind') else ''))
            if not any(a.get('current_security_level') is not None for a in apps):
                gap('dvwa_security_level', 'out_of_scope' if status == 'out_of_scope' else 'not_checked', 'Chưa đọc được security level từ phiên đăng nhập được xác minh.')
            gap('dvwa_version', 'not_checked', 'Dấu hiệu nhận diện và banner không xác minh phiên bản DVWA.')
            if not any('modules' in a for a in auth):
                gap('dvwa_modules', 'not_checked', 'Chưa đọc metadata module/form trong phiên DVWA được xác minh.')
            elif any(a.get('modules_truncated') or a.get('status') != 'verified' for a in auth if 'modules' in a):
                gap('dvwa_modules', 'check_failed', 'Khảo sát module còn thiếu do giới hạn hoặc lỗi; xem modules_planned và checks.')
        else:
            gap('dvwa_session_ready', 'out_of_scope', 'Không chọn khảo sát DVWA.')
    else:
        gap('web', 'out_of_scope', 'Không chọn phạm vi web; không cần khắc phục.')
    for field in profile['telemetry']:
        observed = (telemetry or {}).get('checks', {}).get(field)
        if observed and profile['telemetry'][field] is None:
            gap('telemetry.' + field, observed['status'], observed['reason'])
            continue
        if profile['telemetry'][field] is None:
            gap('telemetry.' + field, 'not_checked' if field != 'web_access_logs' or web else 'out_of_scope',
                'Không kiểm tra tạo/ingest log; service đang chạy không chứng minh telemetry hoạt động.' if field != 'web_access_logs' or web else 'Không chọn phạm vi web.')
    https = [o for o in evidence['observations'] if o['url'].startswith('https:')]
    verified = any(o.get('tls_verified') is True and o.get('http_status') is not None and not o.get('error') for o in https)
    reasons = sorted({o['error']['kind'] for o in https if o.get('error')})
    https_state = {'verified': True if verified else None, 'error_kinds': reasons,
        'reason': 'Có phản hồi HTTPS với xác minh TLS.' if verified else 'Lỗi probe HTTPS: ' + ', '.join(reasons) if reasons else 'Chưa có bằng chứng xác minh TLS.'}
    scope = evidence.get('scope')
    if config is not None:
        from .web_scope import allowed_pairs
        scope = [dict(scheme=s, port=p) for s, p in allowed_pairs(config, request['target_ip'])]
    https_in_scope = web and (scope is None or any(x['scheme'] == 'https' for x in scope))
    if not https_in_scope:
        https_state = {'verified': None, 'status': 'out_of_scope', 'error_kinds': [], 'reason': 'HTTPS ngoài phạm vi khảo sát.'}
        if web: gap('https', 'out_of_scope', https_state['reason'])
    elif not verified:
        gap('https', 'check_failed' if reasons else 'not_checked', https_state['reason'])
    return {'missing_information': missing, 'required_missing': any(m['required'] for m in missing),
            'web_readiness': {'web_reachable': profile['capabilities'].get('web_reachable'),
              'application_identified': True if evidence['applications'] else None,
              'session_ready': profile['capabilities'].get('dvwa_session_ready'), 'https': https_state},
            'warnings': list(dict.fromkeys(m['reason'] for m in missing if m['status'] != 'out_of_scope'))}
