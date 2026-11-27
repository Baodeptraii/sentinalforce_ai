"""Fixed demo-case registry and deterministic planner. No LLM in any node.

The five demo cases (EP-01, EP-02, EP-03, WEB-01, WEB-02) are hand-written and
pinned by catalog revision hash plus GUI adapter pins. When a request maps to
one of them, this module constructs the same artifact chain the LLM workflow
produces (user request, behavior analysis, retrieval, grounding coverage,
plan) deterministically, then runs the unchanged validators (validate_request,
validate_grounding, validate_plan, validate_evidence_plan) so the output is a
first-class ScenarioPlan. Nothing here rewrites executor commands: the chain,
order and content come only from the catalog records referenced below.
"""
import copy
import json
from pathlib import Path

from .config import write_json
from .catalog import connect, ability as catalog_ability
from .behaviors import validate_analysis, validate_grounding
from .target_evidence import assess_candidates, catalog_handles, filter_retrieval
from .workflow import Workflow, runtime_envelope

# Ground-quote markers select the exact command line cited as grounding
# evidence; each marker must match exactly one line of the pinned command.
GROUND_MARKERS = {
    'f8de05d1741dcc468f772ab0ff4dac72': 'tasklist',
    'a6bff7612c9f5dec9c44574181feac26': 'Get-Service',
    'dca8b042fcdffcc1f5cddcff4122c434': 'systeminfo',
    'session-bootstrap-000000000001': 'seclev_submit=Submit&user_token=',
    'lab-dir-baseline-000000000001': 'manifest.txt',
    'ransom-file-ops-000000000002': 'Rename-Item',
    'scoped-cleanup-000000000003': 'Remove-Item -LiteralPath $ns -Recurse -Force',
    'http-beacon-000000000001': 'http://192.168.1.164:18765/beacon',
    'file-transfer-000000000002': 'EP03_EXFIL_ERROR',
    'sqli-union-probe-000000000002': 'vulnerabilities/sqli/?id=%27',
    'xss-browser-proof-000000000003': '& $helper -BaseUrl',
    'brute-force-bounded-000000000002': 'deliberately-wrong-',
}

CASES = {
    'EP-01': {
        'title': 'Kiểm kê tiến trình, dịch vụ và thông tin hệ điều hành trên endpoint Windows',
        'description': 'Kế hoạch ba bước thu thập thông tin cơ bản của endpoint: liệt kê tiến trình đang chạy, liệt kê dịch vụ và đọc thông tin hệ điều hành. Toàn bộ bước chỉ đọc, không thay đổi trạng thái hệ thống.',
        'tags': ['discovery', 'endpoint'],
        'scope': ['endpoint'],
        'chain': [
            'f8de05d1741dcc468f772ab0ff4dac72',
            'a6bff7612c9f5dec9c44574181feac26',
            'dca8b042fcdffcc1f5cddcff4122c434',
        ],
        'request_text': ('Trên Windows 192.168.1.150, dùng bộ demo đã kiểm chứng để liệt kê tiến trình, '
                         'dịch vụ và thông tin hệ điều hành, đúng 3 bước, không thay đổi hệ thống.'),
        'objective': 'Liệt kê tiến trình, dịch vụ và thông tin hệ điều hành của máy lab, không thay đổi hệ thống',
        'behaviors': [
            {'ability_id': 'f8de05d1741dcc468f772ab0ff4dac72', 'quote': 'liệt kê tiến trình',
             'query_en': 'enumerate running processes on Windows endpoint', 'keywords': ['process', 'tasklist'],
             'executor': ['windows', 'cmd']},
            {'ability_id': 'a6bff7612c9f5dec9c44574181feac26', 'quote': 'dịch vụ',
             'query_en': 'enumerate installed services on Windows endpoint', 'keywords': ['service'],
             'executor': ['windows', 'cmd']},
            {'ability_id': 'dca8b042fcdffcc1f5cddcff4122c434', 'quote': 'thông tin hệ điều hành',
             'query_en': 'collect operating system information', 'keywords': ['systeminfo'],
             'executor': ['windows', 'cmd']},
        ],
        'reasons': {
            'f8de05d1741dcc468f772ab0ff4dac72': 'tasklist trực tiếp đáp ứng hành vi liệt kê tiến trình được yêu cầu.',
            'a6bff7612c9f5dec9c44574181feac26': 'Get-Service trực tiếp đáp ứng hành vi liệt kê dịch vụ được yêu cầu.',
            'dca8b042fcdffcc1f5cddcff4122c434': 'systeminfo thu thập thông tin hệ điều hành đúng phạm vi được yêu cầu.',
        },
        'verification': {
            'f8de05d1741dcc468f772ab0ff4dac72': ['Output chứa danh sách tiến trình kiểu tasklist (tên ảnh, PID).'],
            'a6bff7612c9f5dec9c44574181feac26': ['Output chứa danh sách dịch vụ với trạng thái RUNNING/STOPPED.'],
            'dca8b042fcdffcc1f5cddcff4122c434': ['Output chứa các trường hệ điều hành (Host Name, OS Name, OS Version).'],
        },
        'telemetry': {
            'f8de05d1741dcc468f772ab0ff4dac72': [('Sysmon', 'Sysmon event 1 process creation cho tasklist.exe')],
            'a6bff7612c9f5dec9c44574181feac26': [('Sysmon', 'Sysmon event 1 process creation cho powershell.exe')],
            'dca8b042fcdffcc1f5cddcff4122c434': [('Sysmon', 'Sysmon event 1 process creation cho systeminfo.exe')],
        },
        'selection_reason': 'Yêu cầu nêu ba hành vi rà quét thông tin cơ bản; catalog có ba nguồn tương ứng một-một (tasklist, Get-Service, systeminfo) với executor cmd trên Windows đã được Survey xác nhận, nên chọn ghép đúng ba nguồn này theo thứ tự yêu cầu.',
        'goal': 'Kiểm kê tiến trình, dịch vụ và thông tin hệ điều hành trên máy lab đúng 3 bước, chỉ đọc',
    },
    'EP-02': {
        'title': 'Mô phỏng hành vi ransomware trên thư mục lab (không mã hóa dữ liệu thật)',
        'description': 'Ba bước mô phỏng dấu vết ransomware trong một thư mục lab riêng: tạo thư mục và file mẫu kèm baseline hash, thực hiện chuỗi thao tác thêm/sửa/đổi tên kèm ransom note nhãn TRAINING, rồi xác minh và dọn dẹp đúng phạm vi thư mục. Không có bước mã hóa dữ liệu thật.',
        'tags': ['impact', 'simulation', 'endpoint'],
        'scope': ['endpoint'],
        'chain': [
            'lab-dir-baseline-000000000001',
            'ransom-file-ops-000000000002',
            'scoped-cleanup-000000000003',
        ],
        'request_text': ('Mô phỏng hành vi ransom trên thư mục demo C:\\SOC-Lab\\EP02\\demo của máy 192.168.1.150: '
                         'tạo thư mục và file mẫu, thêm/sửa/đổi tên file, ghi ransom note giả lập rõ nhãn TRAINING, '
                         'xác minh hash trước/sau và dọn dẹp đúng phạm vi demo; không mã hóa dữ liệu thật.'),
        'objective': 'Mô phỏng dấu vết thay đổi dữ liệu kiểu ransom trong namespace demo, không mã hóa dữ liệu thật',
        'behaviors': [
            {'ability_id': 'lab-dir-baseline-000000000001', 'quote': 'tạo thư mục và file mẫu',
             'query_en': 'create demo namespace manifest and sample files with hashes',
             'keywords': ['namespace', 'manifest']},
            {'ability_id': 'ransom-file-ops-000000000002', 'quote': 'thêm/sửa/đổi tên file',
             'query_en': 'append rename and ransom note simulation on demo files',
             'keywords': ['rename']},
            {'ability_id': 'scoped-cleanup-000000000003', 'quote': 'dọn dẹp đúng phạm vi demo',
             'query_en': 'scoped cleanup of the demo namespace after simulation',
             'keywords': ['remove']},
        ],
        'reasons': {
            'lab-dir-baseline-000000000001': 'Tạo thư mục lab và file mẫu kèm SHA256 làm baseline đối chiếu cho các bước sau.',
            'ransom-file-ops-000000000002': 'Thực hiện thêm/sửa/đổi tên file và ghi ransom note giả lập trong thư mục lab, tương ứng hành vi thao tác dữ liệu được yêu cầu.',
            'scoped-cleanup-000000000003': 'Xóa đúng thư mục lab của phiên và xác nhận không còn hiện diện, khép lại phạm vi mô phỏng.',
        },
        'verification': {
            'lab-dir-baseline-000000000001': ['Output in EP02_SETUP_OK kèm SHA256 baseline của các file mẫu.'],
            'ransom-file-ops-000000000002': ['Output in EP02_MUTATE_OK; hash a_master.txt khác baseline; b_renamed.txt hiện diện; README_READ_ME.txt mang nhãn SIMULATED.'],
            'scoped-cleanup-000000000003': ['Output in EP02_CLEANUP_OK namespace_removed; thư mục demo không còn hiện diện.'],
        },
        'telemetry': {
            'lab-dir-baseline-000000000001': [('Sysmon', 'Sysmon event 11 file create trong C:\\SOC-Lab\\EP02')],
            'ransom-file-ops-000000000002': [('Sysmon', 'Sysmon event 11/2/1 cho rename và ghi nội dung trong namespace demo')],
            'scoped-cleanup-000000000003': [('Sysmon', 'Sysmon event 23 file delete cho C:\\SOC-Lab\\EP02\\demo')],
        },
        'selection_reason': 'Yêu cầu mô phỏng thay đổi dữ liệu kiểu ransom trong phạm vi thư mục demo; chọn ghép ba nguồn được xem xét riêng: tạo baseline, mô phỏng thay đổi dữ liệu (T1565.001) và dọn dẹp có phạm vi, mỗi nguồn có marker kiểm chứng riêng để đối chiếu kết quả.',
        'goal': 'Mô phỏng hành vi ransom bằng thay đổi file trong namespace demo, có baseline và cleanup',
    },
    'EP-03': {
        'title': 'Mô phỏng beaconing và truyền dữ liệu về máy thu nội bộ',
        'description': 'Hai bước mô phỏng hành vi C2/exfiltration: gửi đúng 5 heartbeat HTTP cách nhau 3 giây tới listener nội bộ 192.168.1.164:18765, sau đó truyền một file văn bản giả lập dưới 64 KiB kèm SHA256 và đối chiếu receipt hai đầu.',
        'tags': ['command-and-control', 'exfiltration', 'endpoint'],
        'scope': ['endpoint'],
        'chain': [
            'http-beacon-000000000001',
            'file-transfer-000000000002',
        ],
        'request_text': ('Từ máy 192.168.1.150 gửi đúng 5 heartbeat HTTP cách nhau 3 giây tới receiver nội bộ '
                         '192.168.1.164:18765, sau đó truyền một file văn bản giả lập dưới 64 KiB từ '
                         'C:\\SOC-Lab\\EP03\\demo; xác minh receipt và hash hai đầu.'),
        'objective': 'Mô phỏng beaconing và truyền file giả lập tới receiver nội bộ được duyệt, có receipt/hash',
        'behaviors': [
            {'ability_id': 'http-beacon-000000000001', 'quote': 'gửi đúng 5 heartbeat HTTP cách nhau 3 giây',
             'query_en': 'bounded http beacon heartbeats to internal lab receiver',
             'keywords': ['beacon']},
            {'ability_id': 'file-transfer-000000000002', 'quote': 'truyền một file văn bản giả lập dưới 64 KiB',
             'query_en': 'transfer small synthetic file to internal receiver with hash',
             'keywords': ['exfil']},
        ],
        'reasons': {
            'http-beacon-000000000001': 'Gửi heartbeat HTTP định kỳ đúng 5 lần với khoảng nghỉ 3 giây, mô phỏng hành vi beacon C2 có giới hạn rõ ràng.',
            'file-transfer-000000000002': 'Truyền file giả lập kèm SHA256 tới listener nội bộ để đối chiếu receipt, mô phỏng exfiltration có bằng chứng hai đầu.',
        },
        'verification': {
            'http-beacon-000000000001': ['Output in EP03_BEACON_SUMMARY accepted=5 of 5; receiver ghi đủ 5 receipt beacon của phiên.'],
            'file-transfer-000000000002': ['Output in EP03_EXFIL_SENT với SHA256; receipt phía receiver ghi cùng SHA256 và kích thước.'],
        },
        'telemetry': {
            'http-beacon-000000000001': [('Sysmon', 'Sysmon event 3 network connect tới 192.168.1.164:18765')],
            'file-transfer-000000000002': [('Sysmon', 'Sysmon event 3 network connect kèm ghi file trong namespace demo')],
        },
        'selection_reason': 'Yêu cầu mô phỏng beaconing và truyền dữ liệu về receiver nội bộ được duyệt; chọn ghép hai nguồn: beacon HTTP định kỳ có giới hạn cứng (T1071.001) và truyền file kèm hash đối chiếu (T1041), với requirement kiểm tra receiver riêng lúc thực thi.',
        'goal': 'Mô phỏng beaconing và exfil giả lập tới receiver nội bộ với bằng chứng hai đầu',
    },
    'WEB-01': {
        'title': 'Kiểm chứng SQL Injection và Reflected XSS trên DVWA (mức low)',
        'description': 'Ba bước kiểm chứng hai lỗ hổng web kinh điển trên DVWA mức low: thiết lập phiên hợp lệ có CSRF, probe union SQLi có baseline đối chứng và đếm dòng bị lộ, rồi kiểm chứng reflected XSS bằng marker JavaScript vô hại phải thực thi thật trong trình duyệt headless — phản chiếu HTTP không được tính là bằng chứng.',
        'tags': ['initial-access', 'web', 'dvwa'],
        'scope': ['web'],
        'chain': [
            'session-bootstrap-000000000001',
            'sqli-union-probe-000000000002',
            'xss-browser-proof-000000000003',
        ],
        'request_text': ('Kiểm thử SQL Injection và reflected XSS giới hạn trên DVWA 192.168.1.150:8080 mức low: '
                         'phiên hợp lệ có CSRF, probe union SQLi kiểm chứng theo dữ liệu mẫu, và XSS marker vô hại '
                         'được chứng minh thực thi trong trình duyệt thật.'),
        'objective': 'Kiểm chứng SQL injection và reflected XSS trên DVWA low bằng predicate xác định, không sửa/xóa dữ liệu',
        'behaviors': [
            {'ability_id': 'session-bootstrap-000000000001', 'quote': 'phiên hợp lệ có CSRF',
             'query_en': 'dvwa session bootstrap with csrf token and security low',
             'keywords': ['csrf', 'session']},
            {'ability_id': 'sqli-union-probe-000000000002', 'quote': 'probe union SQLi kiểm chứng theo dữ liệu mẫu',
             'query_en': 'union sql injection probe with verified sample accounts',
             'keywords': ['sqli', 'union']},
            {'ability_id': 'xss-browser-proof-000000000003', 'quote': 'XSS marker vô hại được chứng minh thực thi trong trình duyệt thật',
             'query_en': 'reflected xss harmless marker proven executing in real browser',
             'keywords': ['xss', 'payload']},
        ],
        'reasons': {
            'session-bootstrap-000000000001': 'Thiết lập phiên DVWA hợp lệ với CSRF token và security low làm điều kiện cho các phép thử phía sau.',
            'sqli-union-probe-000000000002': 'Probe union SQLi có baseline đối chứng; chỉ tính đạt khi số dòng phản hồi tăng rõ rệt so với baseline.',
            'xss-browser-proof-000000000003': 'Marker vô hại phải được chứng minh thực thi thật trong trình duyệt headless; phản chiếu HTTP chỉ được ghi nhận, không tính là bằng chứng.',
        },
        'verification': {
            'session-bootstrap-000000000001': ['Output in DVWA_SESSION_OK login_verified security=low.'],
            'sqli-union-probe-000000000002': ['Output in WEB01_SQLI_OK union_rows_exposed với ít nhất 3 tài khoản mẫu DVWA trong phản hồi probe.'],
            'xss-browser-proof-000000000003': ['Output in WEB01_XSS_OK marker_executed_in_browser; http_reflection_recorded chỉ được ghi nhận, không tính là bằng chứng thực thi.'],
        },
        'telemetry': {
            'session-bootstrap-000000000001': [('Apache access log', 'POST /dvwa/login.php và /dvwa/security.php')],
            'sqli-union-probe-000000000002': [('Apache access log', 'GET /dvwa/vulnerabilities/sqli/ với query probe')],
            'xss-browser-proof-000000000003': [('Apache access log', 'GET /dvwa/vulnerabilities/xss_r/ với payload marker')],
        },
        'selection_reason': 'Yêu cầu kiểm chứng SQLi và XSS trên DVWA mức low; chọn ghép ba nguồn: session bootstrap xử lý CSRF (T1078), union SQLi có đối chứng (T1190) và kiểm chứng XSS qua trình duyệt thật (T1059.007) để tách biệt phản chiếu HTML và thực thi JavaScript.',
        'goal': 'Kiểm chứng SQLi và XSS trên DVWA low bằng predicate, tách biệt HTTP reflection và thực thi JavaScript',
    },
    'WEB-02': {
        'title': 'Kiểm thử brute force giới hạn trên DVWA',
        'description': 'Hai bước kiểm thử vét cân đăng nhập trên module brute force của DVWA: thiết lập phiên hợp lệ trước, sau đó tối đa 5 lần thử trên tài khoản lab (4 giá trị sai, 1 giá trị đúng) với verdict riêng cho từng lần thử.',
        'tags': ['credential-access', 'web', 'dvwa'],
        'scope': ['web'],
        'chain': [
            'session-bootstrap-000000000001',
            'brute-force-bounded-000000000002',
        ],
        'request_text': ('Trên DVWA 192.168.1.150:8080, thử tối đa 5 lần trên tài khoản lab được cấp trong module '
                         'brute force với xác minh từng lần thử, phiên demo hợp lệ trước đó.'),
        'objective': 'Brute force giới hạn đúng 5 lần thử trên module brute force của DVWA với xác minh từng lần',
        'behaviors': [
            {'ability_id': 'session-bootstrap-000000000001', 'quote': 'phiên demo hợp lệ trước đó',
             'query_en': 'dvwa session bootstrap with csrf token and security low',
             'keywords': ['csrf', 'session']},
            {'ability_id': 'brute-force-bounded-000000000002', 'quote': 'thử tối đa 5 lần',
             'query_en': 'bounded brute force attempts with per attempt verification',
             'keywords': ['brute', 'wrong']},
        ],
        'reasons': {
            'session-bootstrap-000000000001': 'Thiết lập phiên DVWA hợp lệ trước khi thực hiện các lần thử đăng nhập.',
            'brute-force-bounded-000000000002': 'Chạy tối đa 5 lần thử với giới hạn cứng trong nguồn, mỗi lần xác minh bằng marker riêng để phân biệt sai/đúng.',
        },
        'verification': {
            'session-bootstrap-000000000001': ['Output in DVWA_SESSION_OK login_verified security=low.'],
            'brute-force-bounded-000000000002': ['Output liệt kê từng ATTEMPT với guessed_correctly; kết thúc WEB02_BRUTE_OK attempts<=5 hard_bound=5.'],
        },
        'telemetry': {
            'session-bootstrap-000000000001': [('Apache access log', 'POST /dvwa/login.php và /dvwa/security.php')],
            'brute-force-bounded-000000000002': [('Apache access log', 'GET /dvwa/vulnerabilities/brute/ lặp tối đa 5 lần')],
        },
        'selection_reason': 'Yêu cầu brute force giới hạn trên DVWA; chọn ghép hai nguồn: session bootstrap có CSRF (T1078) và probe brute force giới hạn cứng 5 lần thử với xác minh từng lần (T1110.001).',
        'goal': 'Brute force giới hạn 5 lần thử với xác minh từng lần trên module brute force DVWA',
    },
}

CASE_ORDER = ['EP-01', 'EP-02', 'EP-03', 'WEB-01', 'WEB-02']


def case_ids():
    return list(CASE_ORDER)


def case_summary(case_id):
    case = CASES[case_id]
    return {'case_id': case_id, 'title': case['title'], 'scope': list(case['scope']),
            'steps': list(case['chain']), 'request_text': case['request_text'],
            'objective': case['objective']}


def _ground_quote(command, marker):
    lines = [line.strip() for line in command.splitlines() if marker in line]
    if len(lines) != 1:
        raise ValueError('Ground marker must select exactly one command line: ' + marker)
    return lines[0]


def constraints():
    return {
        'baseline_required': True, 'cleanup_required': True, 'rollback_required': True,
        'health_check_required': None, 'avoid_service_disruption': True,
        'service_changes_require_separate_approval': True, 'variants_require_approval': True,
        'setup_cleanup_count_toward_max_tests': False, 'exploitation_success_required': True,
        'detection_evaluation_requested': None, 'additional_constraints': [],
    }


class FixedWorkflow(Workflow):
    """Deterministic pipeline for one fixed case; validators stay unchanged."""

    def __init__(self, config, case_id):
        super().__init__(config, llm=None)
        if case_id not in CASES:
            raise ValueError('Unknown fixed case: ' + str(case_id))
        self.case_id = case_id
        self.case = CASES[case_id]
        self._records = None

    def _load_records(self):
        if self._records is None:
            with connect(self.config.catalog) as db:
                self._records = [catalog_ability(db, ref) for ref in self.case['chain']]
        return self._records

    def _behavior_map(self):
        return {b['ability_id']: b for b in self.case['behaviors']}

    def _spec_for(self, behavior):
        # validate_analysis assigns IDs B1.. by position; order is preserved.
        index = int(behavior['id'][1:]) - 1
        return self.case['behaviors'][index]

    def step(self, name, state):
        # Same bookkeeping as the base step, never constructing an LLM client.
        import time
        import copy as _copy
        state = _copy.deepcopy(state)
        self.check_fingerprints(state)
        state['phase'] = name
        state['status'] = 'running'
        started = time.monotonic()
        for key in ('error', 'error_code', 'error_status', 'retry_not_before'):
            state.pop(key, None)
        try:
            getattr(self, 'node_' + name)(state)
        except Exception as error:
            state.update(status='error', next='END', resume_phase=name,
                         error=str(error)[:2000],
                         error_code=getattr(error, 'code', None),
                         error_status=getattr(error, 'status', None))
        state['events'].append({'node': name, 'status': state['status'], 'next': state['next'],
                                'duration_seconds': round(time.monotonic() - started, 3),
                                'fixed_case': self.case_id})
        self.save(state)
        return state

    def run(self, state):
        # Deterministic chain; langgraph is not required for fixed cases.
        self.check_fingerprints(state)
        self.save(state)
        for _ in range(12):
            if state.get('next') in (None, 'END'):
                break
            state = self.step(state['next'], state)
        return state

    def node_parse(self, s):
        for key in ('retrieval', 'coverage_summary', 'uncovered_behaviors', 'ground_errors',
                    'grounding_diagnostics', 'compatibility_report', 'selected_context', 'context_selection'):
            s.pop(key, None)
        s['ground_attempts'] = 0
        self.evidence_payload(s)
        case = self.case
        s['request'] = {
            'id': s['request_id'], 'text': s['text'], 'target_id': s['target']['id'],
            'objective': case['objective'], 'requested_techniques': [],
            'scope': list(case['scope']), 'max_tests': len(case['chain']), 'mode': 'plan_only',
            'constraints': constraints(), 'clarifications_needed': [],
        }
        s['behavior_analysis'] = {
            'ordered': True,
            'behaviors': [{'description': b['query_en'], 'source_quote': b['quote'],
                           'query_en': b['query_en'], 'keywords': list(b['keywords'])}
                          for b in case['behaviors']],
        }
        s['parse_attempts'] += 1
        s['next'] = 'validate_request'

    def node_retrieve(self, s):
        records = self._load_records()
        by_id = {r['canonical_id']: r for r in records}
        candidates = {}
        for b in s['behavior_analysis']['behaviors']:
            spec = self._spec_for(b)
            candidates[b['id']] = [spec['ability_id']]
        s['retrieval'] = {'abilities': [{'record': by_id[ref]} for ref in self.case['chain']],
                          'adversaries': [], 'behavior_candidates': candidates}
        if s.get('input_snapshot'):
            s['retrieval'] = catalog_handles(s['retrieval'])
            s['compatibility_report'] = assess_candidates(s['retrieval'], runtime_envelope(s), s['request'])
            write_json(self.run_directory(s) / 'compatibility_report.json', s['compatibility_report'])
            s['retrieval'] = filter_retrieval(s['retrieval'], s['compatibility_report'])
            self.evidence_payload(s)
        write_json(self.run_directory(s) / 'retrieval.json', s['retrieval'])
        if not s['retrieval']['abilities']:
            raise ValueError('Fixed-case sources failed compatibility assessment; re-review the pinned sources')
        s['next'] = 'ground_behaviors'

    def node_ground_behaviors(self, s):
        case = self.case
        analysis = s['behavior_analysis']
        retrieval = s['retrieval']
        records = {r['record']['canonical_id']: r['record'] for r in retrieval['abilities']}
        rows = []
        for b in analysis['behaviors']:
            spec = self._spec_for(b)
            ref = spec['ability_id']
            record = records[ref]
            platform, name = spec.get('executor', ['windows', 'psh'])
            ex = next(e for e in record['ability']['executors']
                      if (e['platform'], e['name']) == (platform, name))
            rows.append({'behavior_id': b['id'],
                         'reason': 'Fixed-case mapping: pinned source revision ' + record['provenance']['revision'][:12],
                         'matches': [{'ability_id': ref, 'platform': ex['platform'], 'executor': ex['name'],
                                      'command_quote': _ground_quote(ex['command'], GROUND_MARKERS[ref])}]})
        response = {'coverage': rows, 'unmodeled_requirements': []}
        coverage = validate_grounding(response, analysis, retrieval, s['target'])
        s['ground_attempts'] = s.get('ground_attempts', 0) + 1
        s['grounding_diagnostics'] = {'status': 'reviewed', 'rejected_matches': coverage['rejected_matches'],
                                      'coverage': coverage['coverage'], 'method': 'fixed_case_deterministic_mapping'}
        write_json(self.run_directory(s) / 'grounding_diagnostics.json', s['grounding_diagnostics'])
        s.pop('uncovered_behaviors', None)
        s['retrieval']['behavior_coverage'] = coverage
        if s.get('compatibility_report'):
            s['compatibility_report']['behavior_coverage'] = coverage
            write_json(self.run_directory(s) / 'compatibility_report.json', s['compatibility_report'])
        s['coverage_summary'] = {'required': len(coverage['coverage']),
                                 'supported': len(coverage['coverage']) - len(
                                     [r for r in coverage['coverage'] if not r['matches']])}
        write_json(self.run_directory(s) / 'behavior_coverage.json', coverage)
        write_json(self.run_directory(s) / 'retrieval.json', s['retrieval'])
        s['next'] = 'build_plan'

    def node_build_plan(self, s):
        case = self.case
        coverage = s['retrieval'].get('behavior_coverage')
        focus = {(m['ability_id'], m['platform'], m['executor']) for row in coverage['coverage'] for m in row['matches']}
        evidence = self.evidence_payload(s, focus=focus)
        if evidence and s['context_selection']['required_but_unselected']:
            s.update(status='budget_exceeded', next='END', resume_phase='build_plan',
                     budget_reason='required_facts_context_limit',
                     error='Known required facts exceed context budget; re-survey with narrower scope.')
            return
        records = {r['record']['canonical_id']: r['record'] for r in s['retrieval']['abilities']}
        assessments = {(r['ability_id'], r['executor']['platform'], r['executor']['name']): r
                       for r in s.get('compatibility_report', {}).get('candidates', [])}
        specs = {sp['ability_id']: sp for sp in case['behaviors']}
        behaviors = {self._spec_for(b)['ability_id']: b for b in s['behavior_analysis']['behaviors']}
        steps = []
        blockers = set()
        for index, ref in enumerate(case['chain'], 1):
            record = records[ref]
            item = record['ability']
            behavior = behaviors[ref]
            platform, name = specs[ref].get('executor', ['windows', 'psh'])
            ex = next(e for e in item['executors'] if (e['platform'], e['name']) == (platform, name))
            assessment = assessments[(ref, ex['platform'], ex['name'])]
            blockers |= set(assessment['blockers'])
            steps.append({
                'step_index': index, 'ability_id': ref, 'name': item['name'], 'role': 'test',
                'technique_ids': [item['technique_id']] if item.get('technique_id') else [],
                'reason': case['reasons'][ref],
                'executor': {'platform': ex['platform'], 'name': ex['name'],
                             'privilege': item.get('privilege') or None},
                'parameters': {k: v['value'] for k, v in assessment['bindings'].items()},
                'prerequisites': copy.deepcopy(assessment['survey_checks']),
                'readiness': 'needs_information',
                'behavior_verification': list(case['verification'][ref] + [behavior['description']]),
                'expected_telemetry': [{'source': source, 'observable': observable, 'availability': 'unknown'}
                                       for source, observable in case['telemetry'][ref]],
                'baseline': ['Baseline hash/trạng thái được ghi trong output của các bước trước khi thay đổi.'],
                'cleanup_and_rollback': ['Phạm vi thay đổi và cách dọn dẹp đã được xem xét trong từng nguồn; các bước chỉ đọc hoặc dùng phiên web không cần rollback; reset ngoài kế hoạch phải theo quy trình lab.'],
                'health_checks': ['Sau chuỗi: xác minh marker từng bước và trạng thái namespace/session demo.'],
                'sources': [copy.deepcopy(record['provenance'])],
            })
        plan = {
            'id': s['plan_id'],
            'name': case['title'],
            'description': case['description'],
            'atomic_ordering': list(case['chain']),
            'tags': list(case['tags']),
            'metadata': {
                'schema_version': '1.0',
                'request_id': s['request_id'],
                'target_id': s['target']['id'],
                'mode': 'plan_only',
                'goal': case['goal'],
                'selection': {
                    'strategy': 'compose_abilities',
                    'reason': case['selection_reason'],
                    'sources': [copy.deepcopy(records[ref]['provenance']) for ref in case['chain']],
                },
                'readiness': 'needs_information',
                'blockers': sorted(blockers),
                'assumptions': [
                    'Môi trường mục tiêu đã được Survey xác nhận trong phiên hiện tại; preflight kiểm tra lại agent, executor và quyền trước khi dispatch.',
                    'Các tài nguyên lab sử dụng (thư mục demo, ứng dụng web, listener nội bộ) đã được chuẩn bị và cấp quyền bởi quản trị lab.',
                ],
                'steps': steps,
                'execution_context': {
                    'planner': 'atomic', 'agent_group': None, 'agent_paw': None,
                    'requirements': ['Preflight xác minh Sandcat trusted/heartbeat, executor và quyền Elevated.',
                                     'Listener nội bộ dùng cho truyền dữ liệu (nếu chuỗi có) được controller khởi động đúng phiên và ghi receipt/hash hai đầu.'],
                },
                'limitations': [
                    'Mô phỏng chỉ tác động trong phạm vi tài nguyên lab đã duyệt; không mã hóa dữ liệu thật, không thu dữ liệu cá nhân.',
                    'Telemetry/detection chỉ được kết luận sau khi thu dữ liệu theo phiên thực thi.',
                ],
            },
        }
        s['plan'] = plan
        s['plan_attempts'] += 1
        s['next'] = 'validate_plan'
