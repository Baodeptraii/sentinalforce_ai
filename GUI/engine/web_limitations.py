"""Describe observed phases without treating public probing as authenticated access."""
def limitations(auth=None):
    rows = ['Probe công khai chỉ GET có giới hạn; banner Server là thông tin tự công bố.',
            'Chưa kiểm tra telemetry hoặc ingestion.', 'Không lưu HTML, cookie, CSRF token hoặc credential.']
    if not auth:
        rows.append('Không thực hiện bước xác thực bổ sung; phiên đăng nhập và security level chưa xác minh.')
    elif auth.get('session_ready') is True:
        rows.append('Đã xác minh đăng nhập tại ' + str(auth.get('checked_at', 'thời điểm khảo sát')) + '; không bảo đảm phiên thực thi sau vẫn đăng nhập được.')
        if auth.get('current_security_level') is not None:
            rows.append('Đã đọc security level từ phiên khảo sát; không thay đổi security level.')
        else: rows.append('Chưa xác minh security level: ' + ('trang security chưa cung cấp mức hợp lệ trong phiên đã xác minh' if auth.get('status') == 'verified' else auth.get('status','unknown')) + (' · '+auth['error_kind'] if auth.get('error_kind') else ''))
    else:
        rows.append('Phiên đăng nhập và security level chưa xác minh: ' + auth.get('status','unknown') + (' · '+auth['error_kind'] if auth.get('error_kind') else ''))
    if auth and auth.get('http_status') is not None: rows.append('Bước xác thực nhận HTTP ' + str(auth['http_status']) + '; không suy ra phiên sẵn sàng từ mã lỗi.')
    return rows
