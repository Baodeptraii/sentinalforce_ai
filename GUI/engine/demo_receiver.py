"""Bounded HTTP receiver for the EP-03 demo transfer.

Binds only the configured LAN address, serves exactly two fixed paths, enforces
hard caps (request count, body size) and records a hash receipt for every
accepted request. Synthetic training markers only; nothing is executed and no
user data is collected. Started per execution by the controller and stopped in
its finally block; never exposed on 0.0.0.0.
"""
import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .scenario_execution import receiver_config


def _now():
    return datetime.now(timezone.utc).isoformat()


class DemoReceiver:
    def __init__(self, config, execution_folder):
        rc = receiver_config(config)
        if not rc:
            raise ValueError('demo_receiver chưa cấu hình hoặc tắt')
        self.host, self.port = rc['host'], rc['port']
        self.paths = {rc['beacon_path']: 'beacon', rc['exfil_path']: 'exfil'}
        self.limits = {'beacon': rc['max_beacon'], 'exfil': rc['max_exfil']}
        self.max_beacon_body = 2048
        self.max_exfil_body = rc['max_bytes']
        self.receipts = []
        self.lock = threading.Lock()
        self.server = None
        self.thread = None
        self.started_at = None
        self.stopped_at = None

    class _Handler(BaseHTTPRequestHandler):
        # self.server.outer is the DemoReceiver instance.
        def log_message(self, fmt, *args):
            pass

        def _reject(self, code, reason):
            body = json.dumps({'received': False, 'error': reason}).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            outer = self.server.outer
            kind = outer.paths.get(self.path)
            if not kind:
                return outer._handle_reject(self, 404, 'path_not_allowed')
            try:
                length = int(self.headers.get('Content-Length') or '0')
            except ValueError:
                return outer._handle_reject(self, 400, 'bad_content_length')
            cap = outer.max_beacon_body if kind == 'beacon' else outer.max_exfil_body
            if length <= 0 or length > cap:
                return outer._handle_reject(self, 413, 'size_out_of_bounds')
            body = self.rfile.read(length)
            receipt = outer._accept(kind, body, self.headers)
            if receipt is None:
                return outer._handle_reject(self, 429, 'request_count_exceeded')
            payload = json.dumps({'received': True, 'sha256': receipt['sha256'],
                                  'bytes': receipt['bytes'], 'received_at': receipt['received_at']}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def _handle_reject(self, handler, code, reason):
        with self.lock:
            self.receipts.append({'path': handler.path, 'kind': 'rejected', 'reason': reason,
                                  'received_at': _now()})
        handler._reject(code, reason)

    def _accept(self, kind, body, headers):
        with self.lock:
            count = sum(1 for r in self.receipts if r.get('kind') == kind)
            if count >= self.limits[kind]:
                return None
            name = re.sub(r'[^A-Za-z0-9._-]', '_', str(headers.get('X-Demo-Name', kind + '_payload')))[:64]
            declared = headers.get('X-Demo-SHA256')
            receipt = {'kind': kind, 'name': name, 'bytes': len(body),
                       'sha256': hashlib.sha256(body).hexdigest(),
                       'declared_sha256': declared if declared and re.fullmatch(r'[0-9a-fA-F]{64}', declared) else None,
                       'received_at': _now()}
            if kind == 'beacon':
                try:
                    fields = parse_qs(body.decode('utf-8', 'replace'), keep_blank_values=True)
                    receipt['seq'] = fields.get('seq', [None])[0]
                except ValueError:
                    receipt['seq'] = None
            self.receipts.append(receipt)
            return receipt

    def start(self):
        server = ThreadingHTTPServer((self.host, self.port), self._Handler)
        server.outer = self
        self.server = server
        self.started_at = _now()
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.stopped_at = _now()
            self.server = None
        with self.lock:
            return {'started_at': self.started_at, 'stopped_at': self.stopped_at,
                    'origin': 'http://' + self.host + ':' + str(self.port),
                    'receipts': list(self.receipts),
                    'accepted': {kind: sum(1 for r in self.receipts if r.get('kind') == kind)
                                 for kind in self.limits}}
