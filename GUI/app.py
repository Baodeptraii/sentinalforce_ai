#!/usr/bin/env python3
"""SOC Console. Start with GUI/start.sh after local setup."""
import argparse
import json
import mimetypes
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import re
import secrets
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from engine.survey import ROOT, execute, load_config, normalize_request, now, preflight
from final_template.contracts import normalize_profile
from engine.presentation import hydrate, read_json
from engine.llm import redact
from engine.lifecycle import InstanceLock, Cancelled, pending_recovery, endpoint_activity_path
from engine.runner import save
from engine.handoff import build_handoff, bundle
from engine import scenario_bridge, scenario_actions, scenario_execution, execution_telemetry, audit_stream
from engine.survey_output_v2 import convert as export_survey_v2

OUTPUTS = ROOT / 'outputs'
LOCK = threading.RLock()
JOBS = {}
TOKEN = secrets.token_urlsafe(32)
ACTIVE = None
WORKER = None


def load_jobs():
    """Adapt historical profiles for display without rewriting saved evidence."""
    for file in OUTPUTS.glob('*/state.json'):
        try:
            job = json.loads(file.read_text(encoding='utf-8'))
            if job.get('profile'):
                job['profile'] = normalize_profile(job['profile'])
            job['warnings'] = [w.replace('ART thực thi, ', '') for w in job.get('warnings', [])]
            if job['status'] == 'running':
                job.update(status='interrupted', message='GUI đã dừng giữa lượt. Kiểm tra operation trong CALDERA trước khi chạy lại.')
            if not job.get('profile'):
                raw = read_json(file.parent / 'target_profile.json')
                if raw: job['profile'] = normalize_profile(raw)
            JOBS[job['id']] = hydrate(job, file.parent)
        except (OSError, ValueError, KeyError, TypeError):
            continue


def persist(job):
    path = OUTPUTS / job['id'] / 'state.json'
    previous=read_json(path,{})
    save(path, job)
    try:audit_stream.transition('survey',job,previous)
    except (OSError,ValueError):job['audit_status']='unavailable'


def work(job, config):
    global ACTIVE
    try:
        with InstanceLock(endpoint_activity_path(job['request']['target_ip'])):
            if scenario_execution.pending(job['request']['target_ip']):
                raise ValueError('Endpoint có execution đang chạy/cần phục hồi.')
            return survey_work(job, config)
    except Exception as error:
        with LOCK:
            job.update(status='failed',error=redact(str(error)),message=redact(str(error)),finished_at=now())
            persist(job);ACTIVE=None


def survey_work(job, config):
    global ACTIVE
    directory = OUTPUTS / job['id']
    def update(stage, progress, message):
        with LOCK:
            job.setdefault('events', []).append({'time': now(), 'stage': stage, 'text': message})
            job.update(stage=stage, progress=None, message=message)
            persist(job)
    def log(message):
        if not message: return
        with LOCK:
            item = {'time': now(), 'text': message[:1500]}
            job['logs'].append(item)
            job['logs'] = job['logs'][-300:]
            with (directory / 'execution.log').open('a', encoding='utf-8') as f:
                f.write(item['time'] + ' ' + item['text'] + '\n')
            persist(job)
    try:
        profile, warnings = execute(job['request'], config, directory, update, log)
        with LOCK:
            report = read_json(directory / 'report.json', {})
            status = report.get('status', 'completed_with_unknowns')
            if status not in ('partial', 'completed', 'completed_with_unknowns'): status = 'partial'
            labels = {'partial': 'Kết quả một phần — đã giữ profile và bằng chứng', 'completed': 'Hoàn tất khảo sát',
                      'completed_with_unknowns': 'Hoàn tất — còn thông tin chưa xác minh'}
            job.update(status=status, stage='stopped', progress=None, message=labels[status], profile=profile, warnings=warnings, report=report)
            update('stopped', None, labels[status])
    except Exception as exc:
        with LOCK:
            message = redact(str(exc))
            job.update(status='cancelled' if isinstance(exc, Cancelled) else 'failed', message=message, error=message)
            update('failed', None, message)
        log(message)
    finally:
        with LOCK:
            job['finished_at'] = now()
            try:
                job['handoff'] = build_handoff(directory, job)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                job.setdefault('warnings', []).append('Handoff unavailable: ' + redact(str(exc)))
            try:
                export_survey_v2(directory, directory / 'survey_v2', job)
                job['survey_output_v2'] = 'survey_v2/scenario_handoff.json'
            except (OSError, ValueError, KeyError, TypeError) as exc:
                job.setdefault('warnings', []).append('Survey v2 export unavailable: ' + redact(str(exc)))
            job['files'] = sorted(str(p.relative_to(directory)).replace('\\', '/') for p in directory.rglob('*') if p.is_file() and p.suffix in ('.json', '.log') and p.name != 'state.json')
            persist(job)
            hydrate(job, directory)
            ACTIVE = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Request paths may contain target IPs but never API keys.
        pass

    def send(self, body, status=200, content_type='application/json; charset=utf-8', attachment=None):
        if not isinstance(body, bytes): body = json.dumps(body, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        if attachment: self.send_header('Content-Disposition', 'attachment; filename="%s"' % attachment)
        self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/api/abilities':
            catalog_root = Path(load_config().get('scenario_root', str(ROOT.parent / 'scenario_agent'))).expanduser()
            catalog = catalog_root / 'data/catalog.sqlite'
            try:
                with sqlite3.connect(catalog.as_uri() + '?mode=ro', uri=True) as db:
                    db.row_factory = sqlite3.Row
                    rows = [dict(row) for row in db.execute('SELECT record_id, ability_id, name, description, tactic, technique_id, technique_name, privilege, source_kind, review_status FROM abilities ORDER BY name, record_id')]
                    executors = {}
                    for row in db.execute('SELECT ability_record_id, platform, name FROM executors ORDER BY platform, name'):
                        executors.setdefault(row['ability_record_id'], []).append({'platform': row['platform'], 'name': row['name']})
                    for row in rows:
                        row['executors'] = executors.get(row['record_id'], [])
                return self.send({'items': rows, 'total': len(rows)})
            except (OSError, sqlite3.Error):
                return self.send({'error': 'Không đọc được catalog ability.'}, 503)
        report_match = re.fullmatch(r'/api/executions/([a-f0-9]{32})/telemetry(?:/(report\.json|report\.md))?',path)
        if report_match:
            try:
                report=execution_telemetry.read(report_match[1])
                if report_match[2]:
                    name=report_match[2]
                    payload=execution_telemetry.markdown(report) if name=='report.md' else json.dumps(report,ensure_ascii=False)
                    return self.send(payload.encode(),content_type='text/markdown; charset=utf-8' if name=='report.md' else 'application/json',attachment=name)
                return self.send(report)
            except (ValueError,OSError):return self.send({'error':'Telemetry/report unavailable'},404)
        if path == '/api/telemetry/diagnostic':
            return self.send(read_json(ROOT/'telemetry_diagnostic.json',{'status':'not_checked'}))
        if path == '/api/executions':
            return self.send({'items':scenario_execution.history()})
        execution = re.fullmatch(r'/api/executions/([a-f0-9]{32})(?:/files/([a-z_-]+\.json))?',path)
        if execution:
            try:
                if execution[2]:
                    if execution[2] not in scenario_execution.FILES:raise ValueError('File unavailable.')
                    artifact=scenario_execution.folder(execution[1])/execution[2]
                    if artifact.is_symlink():raise ValueError('File unavailable.')
                    return self.send(artifact.read_bytes(),content_type='application/json',attachment=execution[2])
                return self.send(scenario_execution.read(execution[1]))
            except (ValueError,OSError):return self.send({'error':'Execution/file unavailable'},404)
        if path == '/api/scenario-library':
            try: return self.send(scenario_actions.library())
            except (ValueError, OSError): return self.send({'error':'Không đọc được kho kịch bản.'},503)
        if path == '/api/scenarios':
            return self.send(scenario_bridge.history())
        match = re.fullmatch(r'/api/scenarios/([a-f0-9]{32})(?:/files/([a-zA-Z0-9_./-]+))?', path)
        if match:
            try:
                if match[2]:
                    file = scenario_bridge.checked_download(scenario_bridge.directory(match[1]), match[2])
                    return self.send(file.read_bytes(), content_type='application/octet-stream', attachment=match[2])
                return self.send(scenario_bridge.public(match[1]))
            except (ValueError, OSError):
                return self.send({'error': 'Scenario/file unavailable'}, 404)
        if path == '/api/meta':
            config = load_config()
            return self.send({'token': TOKEN, 'caldera_url': config['caldera_url'], 'allowed_networks': config['allowed_networks'],
                'mode': config.get('orchestration_mode', 'scripts'), 'model': os.environ.get('SURVEY_LLM_MODEL', config.get('llm', {}).get('model', '')),
                'app_root': str(ROOT), 'config_file': os.environ.get('SURVEY_CONFIG_FILE', str(ROOT / 'config.json')), 'active_job': ACTIVE,
                'pending_recovery': pending_recovery(OUTPUTS) if not ACTIVE else []})
        if path == '/api/jobs':
            with LOCK:
                rows = [{k: j.get(k) for k in ('id', 'request', 'created_at', 'status', 'mode', 'model')} for j in sorted(JOBS.values(), key=lambda j: j['created_at'], reverse=True)]
                return self.send(rows)
        match = re.fullmatch(r'/api/jobs/([a-f0-9]{32})', path)
        if match:
            with LOCK:
                job = JOBS.get(match[1])
                return self.send(dict(job,token_metrics=read_json(OUTPUTS/match[1]/'token_metrics.json')) if job else {'error': 'Không tìm thấy lượt khảo sát.'}, 200 if job else 404)
        match = re.fullmatch(r'/api/jobs/([a-f0-9]{32})/bundle', path)
        if match:
            with LOCK:
                job = JOBS.get(match[1])
                if not job or job.get('status') == 'running': return self.send({'error': 'Bundle is not ready.'}, 409)
                try:
                    content = bundle(OUTPUTS / match[1])
                except (OSError, ValueError, KeyError) as exc:
                    return self.send({'error': redact(str(exc))}, 422)
            return self.send(content, content_type='application/zip', attachment='survey_' + match[1] + '.zip')
        match = re.fullmatch(r'/api/jobs/([a-f0-9]{32})/files/(.+)', path)
        if match:
            directory = (OUTPUTS / match[1]).resolve()
            target = (directory / match[2]).resolve()
            if directory not in target.parents or target.suffix not in ('.json', '.log') or not target.is_file() or target.name == 'state.json':
                return self.send({'error': 'Không tìm thấy file.'}, 404)
            if target.name == 'target_profile.json':
                try:
                    metadata = JOBS.get(match[1]) or read_json(directory / 'state.json', {'id': match[1]})
                    job = hydrate(dict(metadata), directory)
                    body = target.read_bytes()
                except (ValueError, TypeError, KeyError):
                    return self.send({'error': 'Target Profile không đúng cấu trúc.'}, 422)
            else:
                body = target.read_bytes()
            return self.send(body, content_type='application/octet-stream', attachment=job['download_name'] if target.name == 'target_profile.json' else target.name)
        files = {'/console.js': 'console.js', '/console.css': 'console.css', '/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css',
                 '/scenario.js': 'scenario.js', '/scenario-execution.js':'scenario-execution.js', '/scenario-core.js': 'scenario-core.js',
                 '/scenario-data.json': 'scenario-data.json', '/flow.js': 'flow.js',
                 '/flow-core.js': 'flow-core.js', '/flow.css': 'flow.css'}
        if path in files:
            file = ROOT / 'static' / files[path]
            return self.send(file.read_bytes(), content_type=(mimetypes.guess_type(file.name)[0] or 'text/plain') + '; charset=utf-8')
        self.send({'error': 'Not found'}, 404)

    def do_POST(self):
        global ACTIVE, WORKER
        if self.headers.get('X-Survey-Token') != TOKEN:
            return self.send({'error': 'Phiên không hợp lệ. Tải lại trang.'}, 403)
        origin = self.headers.get('Origin')
        if origin and urlsplit(origin).netloc != self.headers.get('Host'):
            return self.send({'error': 'Origin không hợp lệ.'}, 403)
        try:
            size = int(self.headers.get('Content-Length', 0))
            limit = 512000 if self.path.startswith('/api/scenarios') else 4096
            if not 0 < size < limit: raise ValueError('Kích thước request không hợp lệ.')
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict): raise ValueError('Request phải là JSON object.')
            config = load_config()
            refresh=re.fullmatch(r'/api/executions/([a-f0-9]{32})/telemetry/refresh',self.path)
            if refresh:return self.send(execution_telemetry.enqueue(refresh[1]),202)
            execution = re.fullmatch(r'/api/executions/([a-f0-9]{32})/(confirm|stop|reconcile)',self.path)
            if execution:
                if execution[2]=='confirm':return self.send(scenario_execution.confirm(execution[1],data,config),202)
                if execution[2]=='stop':return self.send(scenario_execution.stop(execution[1],config),202)
                return self.send(scenario_execution.reconcile(execution[1],config))
            if self.path == '/api/scenarios':
                return self.send(scenario_bridge.start(data, config), 202)
            action = re.fullmatch(r'/api/scenarios/([a-f0-9]{32})/(library|regenerate|cancel|delete|execute)', self.path)
            if action:
                identifier, name = action.groups()
                if name == 'library': return self.send(scenario_actions.add_to_library(identifier, config))
                if name == 'regenerate': return self.send(scenario_bridge.regenerate(identifier, config),202)
                if name == 'cancel': return self.send(scenario_bridge.cancel(identifier),202)
                if name == 'delete': return self.send(scenario_bridge.delete(identifier))
                if name == 'execute':
                    return self.send(scenario_actions.execute(identifier, config, start_on_click=data.get('start_on_click') is True))
            resume = re.fullmatch(r'/api/scenarios/([a-f0-9]{32})/resume', self.path)
            if resume:
                return self.send(scenario_bridge.start(data, config, resume[1]), 202)
            cancellation = re.fullmatch(r'/api/jobs/([a-f0-9]{32})/cancel', self.path)
            if cancellation:
                with LOCK:
                    job = JOBS.get(cancellation[1])
                    if not job or job['status'] != 'running': return self.send({'error': 'No active run.'}, 409)
                    (OUTPUTS / job['id'] / 'cancel.requested').touch()
                    job['message'] = 'Đã yêu cầu dừng. Đang chờ tool kết thúc và hoàn nguyên nhóm CALDERA.'
                    persist(job)
                return self.send({'status': 'cancellation_requested'}, 202)
            if self.path == '/api/preflight':
                return self.send(preflight(data, config))
            if self.path == '/api/jobs':
                request = normalize_request(data, config)
                with LOCK:
                    if scenario_execution.pending(data.get('target_ip')): return self.send({'error':'Endpoint có execution đang chạy/cần phục hồi.'},409)
                    if ACTIVE: return self.send({'error': 'Có một lượt đang chạy. Đợi kết thúc trước khi tạo lượt mới.'}, 409)
                    pending = [row for row in pending_recovery(OUTPUTS) if row['target_ip'] in (None, request['target_ip'])]
                    if pending: return self.send({'error': 'Cleanup CALDERA chưa được xác nhận. Chạy tools/reconcile.py theo SURVEY_UPGRADE.md trước khi thử lại.', 'recovery': pending}, 409)
                    identifier = uuid.uuid4().hex
                    job = {'id': identifier, 'request': request, 'created_at': now(), 'status': 'running', 'stage': 'preflight', 'progress': None,
                           'mode': config.get('orchestration_mode', 'scripts'), 'model': os.environ.get('SURVEY_LLM_MODEL', config.get('llm', {}).get('model', '')),
                           'message': 'Đang chuẩn bị khảo sát', 'events': [], 'logs': [], 'warnings': [], 'files': []}
                    (OUTPUTS / identifier).mkdir(parents=True)
                    JOBS[identifier] = job; ACTIVE = identifier; persist(job)
                    WORKER = threading.Thread(target=work, args=(job, config), daemon=False)
                    WORKER.start()
                return self.send({'id': identifier}, 202)
            return self.send({'error': 'Not found'}, 404)
        except (ValueError, KeyError, OSError) as exc:
            return self.send({'error': str(exc)}, 400)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    OUTPUTS.mkdir(exist_ok=True)
    instance_lock = InstanceLock(Path.home() / '.cache/datn-survey/console.lock')
    instance_lock.__enter__()
    load_jobs()
    scenario_bridge.initialize()
    scenario_execution.initialize()
    execution_telemetry.initialize()
    # Loopback only: access remotely through an SSH forward, not an unauthenticated public bind.
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print('SOC Console: http://127.0.0.1:%d · root=%s · python=%s' % (args.port, ROOT, __import__('sys').executable), flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: print('\nGUI đã dừng. Kiểm tra CALDERA nếu còn operation đang chạy.')
    finally:
        if ACTIVE: (OUTPUTS / ACTIVE / 'cancel.requested').touch()
        if WORKER and WORKER.is_alive(): WORKER.join(timeout=60)
        server.server_close()
        instance_lock.__exit__(None, None, None)


if __name__ == '__main__': main()
