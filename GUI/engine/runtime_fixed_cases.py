"""Static manifest of the five fixed demo cases.

Mirrors the runtime registry (build_scenario_agent/scenario_agent/fixed_cases.py
CASES) for GUI-side display, classification and execution policy. The runtime
catalog revision hashes for every step are pinned in engine/execution_context.py
FIXED_SOURCES; a mismatch there blocks execution instead of silently accepting.
"""
CASE_TITLES = {
    'EP-01': 'EP-01 — Rà quét thông tin máy (discovery)',
    'EP-02': 'EP-02 — Mô phỏng ransom bằng tạo/thêm/sửa/xóa file trong namespace demo',
    'EP-03': 'EP-03 — Mô phỏng beaconing và truyền file giả lập tới receiver nội bộ',
    'WEB-01': 'WEB-01 — DVWA SQL Injection + Reflected XSS (mức low)',
    'WEB-02': 'WEB-02 — DVWA Brute Force giới hạn 5 lần thử',
}
CASE_SCOPE = {
    'EP-01': ['endpoint'],
    'EP-02': ['endpoint'],
    'EP-03': ['endpoint'],
    'WEB-01': ['web'],
    'WEB-02': ['web'],
}
CASE_CHAINS = {
    'EP-01': [
        'f8de05d1741dcc468f772ab0ff4dac72',
        'a6bff7612c9f5dec9c44574181feac26',
        'dca8b042fcdffcc1f5cddcff4122c434',
    ],
    'EP-02': [
        'lab-dir-baseline-000000000001',
        'ransom-file-ops-000000000002',
        'scoped-cleanup-000000000003',
    ],
    'EP-03': [
        'http-beacon-000000000001',
        'file-transfer-000000000002',
    ],
    'WEB-01': [
        'session-bootstrap-000000000001',
        'sqli-union-probe-000000000002',
        'xss-browser-proof-000000000003',
    ],
    'WEB-02': [
        'session-bootstrap-000000000001',
        'brute-force-bounded-000000000002',
    ],
}
# Canonical request texts; identical to the runtime CASES request_text values.
CASE_REQUEST_TEXT = {
    'EP-01': ('Trên Windows 192.168.1.150, dùng bộ demo đã kiểm chứng để liệt kê tiến trình, '
              'dịch vụ và thông tin hệ điều hành, đúng 3 bước, không thay đổi hệ thống.'),
    'EP-02': ('Mô phỏng hành vi ransom trên thư mục demo C:\\SOC-Lab\\EP02\\demo của máy 192.168.1.150: '
              'tạo thư mục và file mẫu, thêm/sửa/đổi tên file, ghi ransom note giả lập rõ nhãn TRAINING, '
              'xác minh hash trước/sau và dọn dẹp đúng phạm vi demo; không mã hóa dữ liệu thật.'),
    'EP-03': ('Từ máy 192.168.1.150 gửi đúng 5 heartbeat HTTP cách nhau 3 giây tới receiver nội bộ '
              '192.168.1.164:18765, sau đó truyền một file văn bản giả lập dưới 64 KiB từ '
              'C:\\SOC-Lab\\EP03\\demo; xác minh receipt và hash hai đầu.'),
    'WEB-01': ('Kiểm thử SQL Injection và reflected XSS giới hạn trên DVWA 192.168.1.150:8080 mức low: '
               'phiên hợp lệ có CSRF, probe union SQLi kiểm chứng theo dữ liệu mẫu, và XSS marker vô hại '
               'được chứng minh thực thi trong trình duyệt thật.'),
    'WEB-02': ('Trên DVWA 192.168.1.150:8080, thử tối đa 5 lần trên tài khoản lab được cấp trong module '
               'brute force với xác minh từng lần thử, phiên demo hợp lệ trước đó.'),
}
