#!/usr/bin/env python3
"""One read-only CALDERA survey. Standard library only, Python >= 3.8.

prepare registers the ability/adversary, status reads agents, run executes once.
No SSH password, CALDERA API key, or AI service is embedded in this script.
"""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request
import uuid
import signal
import tempfile

try:
    from .lifecycle import Cancelled, InstanceLock
    from .network_io import read_limited
except ImportError:
    from lifecycle import Cancelled, InstanceLock
    from network_io import read_limited

BASE = Path(__file__).resolve().parent
ABILITY_ID = '9e1297bd-47cd-455e-a258-bdf570ea0033'
ADVERSARY_ID = '9e1297bd-47cd-455e-a258-bdf570ea0034'


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


class API:
    def __init__(self, url, key):
        self.url, self.key = url.rstrip('/'), key
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise RuntimeError('CALDERA API redirect refused')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.deadline = None
        self.cancel_file = None

    def call(self, path, method='GET', body=None):
        # List callers need identity, state and membership, not historical links
        # or source facts. CALDERA expects repeated include query parameters.
        if path == 'operations' and method == 'GET':
            path += '?include=id&include=name&include=group&include=state&include=host_group'
        if self.cancel_file and Path(self.cancel_file).exists():
            raise Cancelled('Survey cancellation requested')
        remaining = self.deadline - time.monotonic() if self.deadline is not None else 20
        if remaining <= 0: raise TimeoutError('CALDERA request budget exhausted')
        data = None if body is None else json.dumps(body).encode('utf-8')
        req = urllib.request.Request(self.url + '/api/v2/' + path, data=data,
                                     headers={'KEY': self.key, 'Content-Type': 'application/json'},
                                     method=method)
        with self.opener.open(req, timeout=min(20, remaining)) as response:
            raw = read_limited(response, 8_000_000, self.deadline or time.monotonic() + remaining)
            if len(raw) > 8_000_000: raise ValueError("CALDERA response exceeds limit")
            return json.loads(raw) if raw else None


def definitions():
    command = (BASE / 'survey_windows_basic.ps1').read_text(encoding='utf-8')
    ability = {
        'ability_id': ABILITY_ID, 'name': 'Survey GUI - Windows inventory v5',
        'description': 'Read OS, hostname, current identity and elevation; return JSON.',
        'tactic': 'discovery', 'technique_id': 'T1082',
        'technique_name': 'System Information Discovery', 'repeatable': False,
        'executors': [{'name': 'psh', 'platform': 'windows', 'command': command,
                       'timeout': 60, 'cleanup': [], 'payloads': [], 'parsers': []}],
    }
    adversary = {'adversary_id': ADVERSARY_ID, 'name': 'Survey GUI - Inventory and local log metadata v5',
                 'description': 'Exactly one read-only Windows survey ability.',
                 'atomic_ordering': [ABILITY_ID]}
    return ability, adversary


def prepare(api):
    ability, adversary = definitions()
    for endpoint, identifier, wanted in [('abilities', ABILITY_ID, ability),
                                          ('adversaries', ADVERSARY_ID, adversary)]:
        try:
            found = api.call(endpoint + '/' + identifier)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            api.call(endpoint, 'POST', wanted)
            found = api.call(endpoint + '/' + identifier)
        if endpoint == 'abilities':
            executor = next((e for e in found['executors']
                             if e['name'] == 'psh' and e['platform'] == 'windows'), None)
            if executor is None or executor['command'].strip().replace('\n', '').replace('\r', '') != wanted['executors'][0]['command'].strip().replace('\n', '').replace('\r', ''):
                raise RuntimeError('Ability ID exists with different command; refusing overwrite')
        elif found['atomic_ordering'] != [ABILITY_ID]:
            raise RuntimeError('Adversary contains unexpected abilities; refusing execution')
        print(endpoint + ': registered and verified', flush=True)


def agents_summary(api):
    fields = ['paw', 'host', 'platform', 'group', 'trusted', 'last_seen',
              'executors', 'privilege', 'host_ip_addrs']
    return [{k: a.get(k) for k in fields} for a in api.call('agents')]


def validate_agent(agent, args):
    if agent.get('platform') != 'windows' or agent.get('host', '').lower() != args.expected_host.lower():
        raise RuntimeError('Agent platform/hostname does not match authorized endpoint')
    if args.expected_ip not in agent.get('host_ip_addrs', []):
        raise RuntimeError('Agent does not report the expected endpoint IP')
    if not agent.get('trusted') or 'psh' not in agent.get('executors', []):
        raise RuntimeError('Agent must be trusted and support psh')
    seen = datetime.fromisoformat(agent['last_seen'].replace('Z', '+00:00'))
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - seen).total_seconds()
    if not -60 <= age <= args.max_age:
        raise RuntimeError('Agent last_seen is stale or clocks are inconsistent')


def parse_result(response):
    raw = response.get('result')
    if not isinstance(raw, str) or not raw:
        raise RuntimeError('Missing executor result')
    executor = json.loads(base64.b64decode(raw, validate=True).decode('utf-8-sig'))
    if executor.get('exit_code') not in (0, '0', '', None):
        raise RuntimeError('Executor returned nonzero exit_code')
    if executor.get('stderr', '').strip():
        raise RuntimeError('Executor returned stderr; inspect raw evidence')
    survey = json.loads(executor['stdout'].lstrip('\ufeff').strip())
    if survey.get('tool') != 'get_endpoint_info' or survey.get('status') != 'ok':
        raise RuntimeError('Survey did not return ok')
    data = survey.get('data')
    required = ['os_name', 'os_version', 'architecture', 'hostname', 'username',
                'powershell_version', 'collected_at']
    if not isinstance(data, dict) or not all(isinstance(data.get(k), str) and data[k] for k in required):
        raise RuntimeError('Missing or invalid survey data fields')
    if type(data.get('is_elevated')) is not bool:
        raise RuntimeError('is_elevated must be a boolean')
    return executor, survey


def run(api, args):
    if not args.paw:
        raise RuntimeError('run requires --paw from the current agents list')
    deadline = time.monotonic() + args.timeout
    api.deadline = deadline
    api.cancel_file = getattr(args, 'cancel_file', None)
    prepare(api)
    agent = api.call('agents/' + args.paw)
    validate_agent(agent, args)
    operations = api.call('operations')
    for op in operations:
        if op.get('state') not in ('finished', 'out_of_time') and any(
                a.get('paw') == args.paw for a in op.get('host_group', [])):
            raise RuntimeError('Endpoint belongs to another unfinished operation')
    planner = next(p for p in api.call('planners') if p['name'] == 'atomic')
    source = next(s for s in api.call('sources') if s['name'] == 'basic')
    tag = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    output = args.output_dir if args.output_dir else BASE / 'runs' / tag
    output.mkdir(parents=True, exist_ok=True)
    ability, adversary = definitions()
    save(output / 'ability-api.json', ability)
    save(output / 'adversary-api.json', adversary)
    save(output / 'agent-before.json', agent)
    summary = {'status': 'started', 'paw': args.paw, 'expected_host': args.expected_host,
               'expected_ip': args.expected_ip, 'operation_id': None, 'link_id': None,
               'group_restored': False, 'detection_result': 'not_evaluated'}
    group = 'survey-' + tag
    operation_id = None
    terminal = False
    changed = False
    summary.update(original_group=agent['group'], temporary_group=group, cleanup_required=True)
    save(output / 'summary.json', summary)  # Journal intent BEFORE any mutation.
    try:
        changed = True  # The server may apply PATCH even if its response is lost.
        api.call('agents/' + args.paw, 'PATCH', {'group': group})
        members = [a['paw'] for a in api.call('agents') if a.get('group') == group]
        if members != [args.paw]:
            raise RuntimeError('Survey group is not restricted to the selected agent')
        request = {'name': 'Survey Windows ' + tag, 'group': group,
                   'adversary': {'adversary_id': ADVERSARY_ID},
                   'planner': {'id': planner['id']}, 'source': {'id': source['id']},
                   'state': 'running', 'autonomous': 1, 'auto_close': True,
                   'obfuscator': 'plain-text', 'jitter': '2/4', 'use_learning_parsers': False}
        save(output / 'operation-request.json', request)
        operation = api.call('operations', 'POST', request)
        operation_id = operation['id']
        summary['operation_id'] = operation_id
        save(output / 'operation-created.json', operation)
        save(output / 'summary.json', summary)
        print('Operation: ' + operation_id, flush=True)
        while time.monotonic() < deadline:
            operation = api.call('operations/' + operation_id)
            save(output / 'operation-latest.json', operation)
            if {a['paw'] for a in operation.get('host_group', [])} != {args.paw}:
                raise RuntimeError('Unexpected operation target membership')
            links = api.call('operations/' + operation_id + '/links')
            save(output / 'links.json', links)
            if any(l['paw'] != args.paw or l['ability']['ability_id'] != ABILITY_ID for l in links):
                raise RuntimeError('Unexpected link in survey operation')
            completed = [l for l in links if l.get('finish')]
            if completed:
                link = completed[0]
                summary['link_id'] = link['id']
                response = api.call('operations/' + operation_id + '/links/' + link['id'] + '/result')
                save(output / 'link-result.json', response)
                if not response.get('result'):
                    time.sleep(max(0, min(.5, deadline - time.monotonic())))
                    continue
                if link.get('status') != 0:
                    raise RuntimeError('Completed link has nonzero status')
                executor, survey = parse_result(response)
                if survey['target'].lower() != args.expected_host.lower() or survey['data']['hostname'].lower() != args.expected_host.lower():
                    raise RuntimeError('Result hostname mismatch')
                save(output / 'executor-result.json', executor)
                save(output / 'endpoint-info.json', survey)
                if operation.get('state') == 'finished':
                    terminal = True
                    summary['status'] = 'passed'
                    print('Survey passed: ' + str(output / 'endpoint-info.json'), flush=True)
                    break
            if operation.get('state') in ('finished', 'out_of_time'):
                terminal = True
                raise RuntimeError('Operation ended without a verified survey result')
            print('Waiting for Sandcat/result; state=' + operation.get('state', '?'), flush=True)
            time.sleep(max(0, min(.5, deadline - time.monotonic())))
        else:
            raise TimeoutError('Survey timeout; inspect stored evidence before retrying')
    except Exception as exc:
        summary['status'] = 'failed'
        summary['error'] = str(exc)
        raise
    finally:
        # A separate, bounded cleanup window runs even after cancellation/deadline.
        api.deadline = time.monotonic() + 20
        api.cancel_file = None
        if operation_id is None and (output / 'operation-request.json').exists():
            try:
                matches = [op for op in api.call('operations') if op.get('group') == group or op.get('name') == 'Survey Windows ' + tag]
                if len(matches) == 1:
                    operation_id = matches[0]['id']; summary['operation_id'] = operation_id
                else: summary['recovery_required'] = True
            except Exception:
                summary['recovery_required'] = True
        if operation_id and not terminal:
            try:
                api.call('operations/' + operation_id, 'PATCH', {'state': 'paused'})
                summary['operation_paused'] = True
                summary['pause_note'] = 'Pause does not cancel a command already delegated to Sandcat.'
            except Exception as exc:
                summary['pause_error'] = type(exc).__name__
        if changed:
            try:
                current = api.call('agents/' + args.paw)['group']
                if current not in (group, agent['group']):
                    raise RuntimeError('Agent group changed externally; manual recovery required')
                api.call('agents/' + args.paw, 'PATCH', {'group': agent['group']})
                summary['group_restored'] = api.call('agents/' + args.paw)['group'] == agent['group']
            except Exception as exc:
                summary['restore_error'] = type(exc).__name__
        summary['cleanup_required'] = not summary['group_restored'] or bool(summary.get('pause_error') or summary.get('recovery_required'))
        save(output / 'summary.json', summary)
    if not summary['group_restored']:
        raise RuntimeError('Survey completed but agent group was not restored; inspect summary.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'status', 'run'])
    parser.add_argument('--url', default='http://127.0.0.1:8888')
    parser.add_argument('--key-file', type=Path, default=Path.home() / '.config/caldera-survey/api-key')
    parser.add_argument('--paw')
    parser.add_argument('--cancel-file', type=Path)
    parser.add_argument('--expected-host', required=True)
    parser.add_argument('--expected-ip', required=True)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--timeout', type=int, default=240)
    parser.add_argument('--max-age', type=int, default=180)
    args = parser.parse_args()
    key = os.environ.get('CALDERA_KEY') or args.key_file.read_text().strip()
    api = API(args.url, key)
    if args.action == 'prepare':
        prepare(api)
    elif args.action == 'status':
        print(json.dumps(agents_summary(api), indent=2))
    else:
        def terminate(signum, frame):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            raise Cancelled('Runner terminated; attempting cleanup')
        signal.signal(signal.SIGTERM, terminate)
        with InstanceLock(Path.home() / '.cache/datn-survey' / ('endpoint-' + args.expected_ip + '.lock')):
            run(api, args)


if __name__ == '__main__':
    main()
