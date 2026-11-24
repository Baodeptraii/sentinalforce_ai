"""Deterministic optional telemetry checks. LLM text cannot establish evidence."""
import base64
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from .runner import save

FIELDS = ('process_events', 'network_events', 'web_access_logs', 'wazuh_ingestion')


def validate_evidence(profile, evidence):
    if evidence.get('format') != 'telemetry_evidence_v1' or evidence.get('target_ip') != profile['address'] or str(evidence.get('hostname', '')).casefold() != str(profile['os'].get('hostname', '')).casefold():
        raise ValueError('Telemetry evidence target mismatch')
    checked = datetime.fromisoformat(evidence['checked_at'].replace('Z', '+00:00'))
    if checked.tzinfo is None: raise ValueError('Telemetry timestamp lacks timezone')
    for field, value in profile['telemetry'].items():
        if value is None: continue
        if value is not True or evidence.get('values', {}).get(field) is not True:
            raise ValueError('Telemetry value lacks evidence')
        check = evidence.get('checks', {}).get(field, {})
        if check.get('status') != 'observed' or not check.get('evidence'):
            raise ValueError('Telemetry observation missing')
        if not any(recent(sample.get('timestamp') or sample.get('event_time'), checked, 24) for sample in check['evidence']):
            raise ValueError('Telemetry evidence outside observation window')


def manager_sample_matches(sample, field, binding, now):
    if sample.get('agent_id') != binding['agent_id'] or sample.get('agent_name', '').casefold() != binding['hostname'].casefold() or not recent(sample.get('timestamp'), now, 24):
        return False
    if sample.get('source') not in ('alerts/alerts.json', 'archives/archives.json'): return False
    channel = sample.get('channel', '').casefold()
    if field in ('process_events', 'network_events'):
        return channel == 'microsoft-windows-sysmon/operational' and sample.get('event_id') == ('1' if field == 'process_events' else '3')
    if field == 'web_access_logs':
        return sample.get('location', '').replace('\\', '/').casefold() in [p.replace('\\', '/').casefold() for p in binding['web_log_paths']]
    return bool(channel) or sample.get('location', '').replace('\\', '/').casefold() in [p.replace('\\', '/').casefold() for p in binding['web_log_paths']]


def recent(stamp, now, hours):
    try:
        when = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        return when.tzinfo is not None and now - timedelta(hours=hours) <= when <= now + timedelta(seconds=120)
    except (ValueError, TypeError, AttributeError):
        return False


def manager_query(options, binding, window_hours):
    """SSH host key is pinned; fixed read-only scanner; no credential in argv/output."""
    host, user = options['host'], options['username']
    if not re.fullmatch(r'[a-zA-Z0-9.-]+', host) or host.startswith('-') or not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_-]*', user):
        raise ValueError('invalid_manager_endpoint')
    credential = Path(options['credentials_file']).expanduser().resolve()
    known_hosts = Path(options['known_hosts_file']).expanduser().resolve()
    if credential.stat().st_mode & 0o077: raise ValueError('credential_permissions')
    secret = json.loads(credential.read_text())
    spec = {k: binding[k] for k in ('agent_id', 'hostname', 'web_log_paths')}
    spec['window_hours'] = window_hours
    script = Path(__file__).with_name('wazuh_scan.py').read_bytes()
    code = 'import base64;exec(base64.b64decode(' + repr(base64.b64encode(script).decode()) + '))'
    command = 'sudo -S -p "" python3 -c ' + shlex.quote(code) + ' ' + shlex.quote(json.dumps(spec))
    env = dict(os.environ, SSH_ASKPASS=str(Path(__file__).with_name('ssh_askpass.py')),
               SSH_ASKPASS_REQUIRE='force', DISPLAY='survey:0', SURVEY_SSH_CREDENTIAL_FILE=str(credential))
    args = ['ssh', '-T', '-F', '/dev/null', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known_hosts),
            '-o', 'ConnectTimeout=5', '-o', 'NumberOfPasswordPrompts=1', '-o', 'PubkeyAuthentication=no',
            '-o', 'PreferredAuthentications=password', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1',
            user + '@' + host, command]
    # Output goes to a bounded-reader temporary file, not the model or application log.
    with tempfile.TemporaryFile() as output:
        process = subprocess.run(args, input=(secret['password'] + '\n').encode(), stdout=output,
                                 stderr=subprocess.DEVNULL, env=env, start_new_session=True, timeout=20)
        if process.returncode: raise RuntimeError('manager_ssh_or_permission_failed')
        if output.tell() > 65536: raise ValueError('manager_response_too_large')
        output.seek(0)
        return json.loads(output.read())


def collect(request, agent, endpoint, config, directory, update, log):
    now = datetime.now(timezone.utc)
    started = time.monotonic()
    result = {'format': 'telemetry_evidence_v1', 'target_ip': request['target_ip'], 'hostname': agent['host'],
              'checked_at': now.isoformat(), 'window_hours': 24, 'values': dict.fromkeys(FIELDS),
              'checks': {k: {'status': 'not_checked', 'reason': 'Chưa có bằng chứng phù hợp.', 'evidence': []} for k in FIELDS},
              'manager': {'status': 'not_configured'}, 'detection_result': 'not_evaluated'}
    if (directory / 'cancel.requested').exists():
        for check in result['checks'].values(): check.update(status='cancelled', reason='Đã yêu cầu dừng; bỏ qua xác minh telemetry.')
        save(directory / 'telemetry_evidence.json', result)
        return result
    update('telemetry', None, 'Kiểm tra bằng chứng log trên endpoint và Wazuh')
    data = (endpoint or {}).get('data', {})
    if data.get('hostname', '').casefold() == agent['host'].casefold() and recent(data.get('collected_at'), now, 1):
        for field in FIELDS[:3]:
            if field == 'web_access_logs' and 'web' not in request['survey_scope']: continue
            if field != 'web_access_logs' and 'endpoint' not in request['survey_scope']: continue
            observation = data.get('telemetry_observations', {}).get(field, {})
            expected = {'process_events': 'sysmon_event_1', 'network_events': 'sysmon_event_3', 'web_access_logs': 'apache_access_entry'}[field]
            if observation.get('kind') == expected and recent(observation.get('event_time'), now, 24):
                result['values'][field] = True
                result['checks'][field] = {'status': 'observed', 'reason': 'Đọc được bản ghi gần đây trên endpoint; xem riêng trạng thái Wazuh.',
                                           'evidence': [{'source': '02_endpoint.json#/data/telemetry_observations/' + field, **observation}]}
    options = config.get('telemetry', {})
    binding = options.get('targets', {}).get(request['target_ip']) if options.get('enabled') is True else None
    if binding:
        if binding.get('hostname', '').casefold() != agent['host'].casefold():
            result['manager'] = {'status': 'identity_mismatch'}
        else:
            try:
                raw = manager_query(options, binding, 24)
                if raw.get('format') != 'wazuh_observation_v1' or raw.get('agent_id') != binding['agent_id'] or raw.get('hostname', '').casefold() != agent['host'].casefold() or not recent(raw.get('checked_at'), now, 1):
                    raise ValueError('manager_identity_or_time_mismatch')
                result['manager'] = {'status': 'checked', 'observation': raw}
                for field in FIELDS:
                    if field == 'web_access_logs' and 'web' not in request['survey_scope']: continue
                    if field in ('process_events', 'network_events') and 'endpoint' not in request['survey_scope']: continue
                    samples = [s for s in raw.get('samples', []) if s.get('field') == field and manager_sample_matches(s, field, binding, now)]
                    if samples:
                        result['values'][field] = True
                        check = result['checks'][field]
                        check.update(status='observed', reason='Có bản ghi của endpoint tại Wazuh trong cửa sổ 24 giờ; không phải kiểm thử detection.')
                        check['evidence'].extend(samples)
            except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
                # Do not expose remote stderr, credentials or arbitrary exception text.
                result['manager'] = {'status': 'check_failed', 'reason': 'Không đọc được Wazuh: kiểm tra kết nối SSH, host key, quyền đọc và cấu hình riêng.'}
    for field, check in result['checks'].items():
        if (field == 'web_access_logs' and 'web' not in request['survey_scope']) or (field in ('process_events', 'network_events') and 'endpoint' not in request['survey_scope']):
            check.update(status='out_of_scope', reason='Nguồn log ngoài phạm vi đã chọn.')
        elif result['values'][field] is None:
            status = result['manager']['status']
            check.update(status='check_failed' if status in ('check_failed', 'identity_mismatch') else 'not_observed' if status == 'checked' else 'not_checked',
                         reason='Chưa có bản ghi phù hợp trong phần log đã kiểm tra; không kết luận pipeline hỏng.' if status == 'checked' else 'Chưa xác minh được nguồn log; trạng thái Wazuh: ' + status + '.')
    result['duration_seconds'] = round(time.monotonic() - started, 3)
    save(directory / 'telemetry_evidence.json', result)
    log('Telemetry: %s/4 trường có bằng chứng; Wazuh: %s' % (sum(v is True for v in result['values'].values()), result['manager']['status']))
    return result


def apply(profile, request, agent, endpoint, config, directory, update, log):
    evidence = collect(request, agent, endpoint, config, directory, update, log)
    profile['telemetry'] = evidence['values']
    return evidence
