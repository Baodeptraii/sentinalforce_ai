"""Offline tests for the fixed demo-case GUI pieces: classifier, scope checks,
blocker allowlist and the bounded demo receiver. No live lab traffic."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import fixed_case_registry, scenario_execution as execution
from engine.demo_receiver import DemoReceiver
from engine.runtime_fixed_cases import CASE_TITLES


class ClassifierTests(unittest.TestCase):
    def test_maps_each_demo_group(self):
        mapping = {
            'Rà quét thông tin máy 192.168.1.150: liệt kê tiến trình, dịch vụ và thông tin hệ điều hành.': 'EP-01',
            'Mô phỏng ransom bằng cách tạo, sửa, đổi tên và xóa file trong namespace demo, ghi ransom note TRAINING.': 'EP-02',
            'Gửi đúng 5 heartbeat tới receiver nội bộ rồi truyền file giả lập dưới 64 KiB.': 'EP-03',
            'Kiểm thử SQL injection và reflected XSS trên DVWA mức low.': 'WEB-01',
            'Brute force tối đa 5 lần trên module brute force của DVWA.': 'WEB-02',
        }
        for text, case in mapping.items():
            result = fixed_case_registry.classify_case(text)
            self.assertIsNotNone(result, text)
            self.assertEqual(result['case_id'], case, text)
            self.assertEqual(result['matched_by'], 'keyword')

    def test_ambiguous_and_out_of_scope_return_none(self):
        self.assertIsNone(fixed_case_registry.classify_case('dvwa brute force và sql injection cùng lúc'))
        self.assertIsNone(fixed_case_registry.classify_case('cài đặt mail server cho công ty'))
        self.assertIsNone(fixed_case_registry.classify_case(''))

    def test_explicit_selection_validates_case_id(self):
        for case_id in CASE_TITLES:
            self.assertEqual(fixed_case_registry.resolve_case(case_id)['case_id'], case_id)
        with self.assertRaises(ValueError):
            fixed_case_registry.resolve_case('EP-09')


class ScopeCheckTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((Path(__file__).resolve().parents[1] / 'config.json').read_text())
        self.config['demo_receiver'] = {'enabled': True, 'host': '192.168.1.164', 'port': 18765,
                                        'beacon_path': '/demo/beacon', 'exfil_path': '/demo/exfil',
                                        'max_beacon': 8, 'max_exfil': 3, 'max_bytes': 65536}

    def test_receiver_config_shape(self):
        rc = execution.receiver_config(self.config)
        self.assertEqual(rc['origin'], 'http://192.168.1.164:18765')
        self.assertEqual(rc['max_bytes'], 65536)
        self.config['demo_receiver']['enabled'] = False
        self.assertIsNone(execution.receiver_config(self.config))
        self.config['demo_receiver']['host'] = 'not-an-ip'
        self.config['demo_receiver']['enabled'] = True
        self.assertIsNone(execution.receiver_config(self.config))

    def test_ep02_path_escape_blocked(self):
        good = "$ns='C:\\SOC-Lab\\EP02\\demo'\nSet-Content -LiteralPath \"$ns\\a.txt\" -Value 'x'"
        bad = "Set-Content -Path 'C:\\Windows\\Temp\\evil.txt' -Value 'x'"
        self.assertTrue(execution.fixed_command_scope_ok(good, '192.168.1.150', self.config, 'EP-02'))
        self.assertFalse(execution.fixed_command_scope_ok(bad, '192.168.1.150', self.config, 'EP-02'))

    def test_ep03_receiver_and_bounds(self):
        good = ("Invoke-WebRequest -Uri 'http://192.168.1.164:18765/demo/beacon' -Method Post\n"
                "for ($i = 1; $i -le 5; $i++) { Start-Sleep -Seconds 3 }")
        self.assertTrue(execution.fixed_command_scope_ok(good, '192.168.1.150', self.config, 'EP-03'))
        wrong_host = "Invoke-WebRequest -Uri 'http://10.9.9.9:18765/demo/beacon' -Method Post"
        over_bound = "for ($i = 1; $i -le 50; $i++) { Invoke-WebRequest -Uri 'http://192.168.1.164:18765/demo/beacon' }"
        self.assertFalse(execution.fixed_command_scope_ok(wrong_host, '192.168.1.150', self.config, 'EP-03'))
        self.assertFalse(execution.fixed_command_scope_ok(over_bound, '192.168.1.150', self.config, 'EP-03'))

    def test_web_urls_must_target_dvwa(self):
        good = "$base='http://192.168.1.150:8080/dvwa'\ncurl.exe -s \"$base/login.php\""
        external = "curl.exe -s 'http://example.com/dvwa/login.php'"
        wrong_port = "curl.exe -s 'http://192.168.1.150/dvwa/login.php'"
        self.assertTrue(execution.fixed_command_scope_ok(good, '192.168.1.150', self.config, 'WEB-01'))
        self.assertFalse(execution.fixed_command_scope_ok(external, '192.168.1.150', self.config, 'WEB-01'))
        self.assertFalse(execution.fixed_command_scope_ok(wrong_port, '192.168.1.150', self.config, 'WEB-01'))

    def test_no_inline_literal_secret(self):
        inline = "curl.exe --data 'username=admin&password=Hunter42x' 'http://192.168.1.150:8080/dvwa/login.php'"
        variable = "curl.exe --data \"username=$($cred.user)&pwd=$($cred.pwd)\" 'http://192.168.1.150:8080/dvwa/login.php'"
        self.assertFalse(execution.fixed_command_scope_ok(inline, '192.168.1.150', self.config, 'WEB-01'))
        self.assertTrue(execution.fixed_command_scope_ok(variable, '192.168.1.150', self.config, 'WEB-01'))


class BlockerAllowlistTests(unittest.TestCase):
    def test_known_blockers_pass(self):
        common = ['Manual review source effects, baseline, health checks and cleanup/rollback; absence of cleanup commands is not proof none is needed',
                  'Required privilege is unspecified in catalog; manual review',
                  'Revalidate runner identity, executor availability and privilege before execution']
        ep02 = common + ['Required path was not surveyed: C:\\SOC-Lab\\EP02\\demo',
                         'Verify filesystem existence/access and cleanup scope for source path C:\\SOC-Lab\\EP02\\demo']
        ep03 = ep02 + ['Verify demo receiver availability, bounds and receipt capture at execution time']
        self.assertTrue(execution.fixed_blockers_allowed(ep02, 'EP-02'))
        self.assertTrue(execution.fixed_blockers_allowed(ep03, 'EP-03'))

    def test_unknown_blocker_blocks_revalidation(self):
        self.assertFalse(execution.fixed_blockers_allowed(['Một blocker lạ chưa từng review'], 'EP-02'))
        # WEB-specific blockers do not clear endpoint cases.
        web_only = ['Survey session is historical; obtain and verify execution session reference separately']
        self.assertTrue(execution.fixed_blockers_allowed(web_only, 'WEB-01'))
        self.assertFalse(execution.fixed_blockers_allowed(web_only, 'EP-02'))


class ReceiverTests(unittest.TestCase):
    def test_caps_and_receipt_hash(self):
        import hashlib
        import time
        from urllib.request import Request, urlopen
        config = {'demo_receiver': {'enabled': True, 'host': '127.0.0.1', 'port': 18799,
                                    'beacon_path': '/demo/beacon', 'exfil_path': '/demo/exfil',
                                    'max_beacon': 2, 'max_exfil': 1, 'max_bytes': 65536}}
        receiver = DemoReceiver(config, None)
        receiver.start()
        try:
            time.sleep(0.2)
            base = 'http://127.0.0.1:18799'
            def post(path, body, headers=None):
                req = Request(base + path, data=body, method='POST', headers=headers or {})
                with urlopen(req, timeout=3) as resp:
                    return resp.code, json.loads(resp.read())
            accepted = 0
            for i in range(4):
                try:
                    code, payload = post('/demo/beacon', ('run=demo&seq=%d' % i).encode())
                    accepted += 1 if payload.get('received') else 0
                except Exception:
                    pass
            self.assertEqual(accepted, 2)  # hard cap respected
            payload = b'x' * 1024
            sha = hashlib.sha256(payload).hexdigest()
            code, body = post('/demo/exfil', payload, {'X-Demo-Name': 'payload_demo.txt', 'X-Demo-SHA256': sha})
            self.assertEqual((code, body['received'], body['sha256']), (200, True, sha))
            summary = receiver.stop()
            self.assertEqual(summary['accepted'], {'beacon': 2, 'exfil': 1})
            exfil_receipt = next(r for r in summary['receipts'] if r.get('kind') == 'exfil')
            self.assertEqual(exfil_receipt['declared_sha256'], sha)
        finally:
            if receiver.server is not None:
                receiver.stop()


if __name__ == '__main__':
    unittest.main()
