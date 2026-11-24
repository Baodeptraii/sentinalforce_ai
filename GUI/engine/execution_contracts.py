"""Versioned deterministic validation/expectations. Never dispatches or consumes logs."""
import copy
import hashlib
import json
from datetime import datetime, timedelta


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def classification(message):
    # Classification only; never removes a preflight gate.
    return 'unsupported' if any(x in message.lower() for x in (
        'chưa có adapter', 'ngoài tập', 'chưa hỗ trợ', 'không hỗ trợ')) else 'execution_required'


def validation(check):
    checked = check['checked_at']
    artifact = {'schema_version': 'execution_validation_v1', 'checked_at': checked,
        'expires_at': (datetime.fromisoformat(checked.replace('Z', '+00:00')) + timedelta(
            seconds=check['policy']['preview_ttl_seconds'])).isoformat(),
        'plan_sha256': check['plan_sha256'], 'binding_sha256': check['binding_sha256'],
        'target': copy.deepcopy(check['target']), 'survey': copy.deepcopy(check.get('survey')),
        'ready': check['ready'], 'steps': [],
        'issues': [{'category': classification(b), 'message': b} for b in check['blockers']],
        'warnings': [{'category': 'telemetry_optional' if 'telemetry' in w.lower() or 'detection' in w.lower()
                      else 'execution_advisory', 'message': w} for w in check.get('warnings', [])]}
    for s in check['steps']:
        issues = [{'category': classification(b), 'message': b} for b in s['blockers']]
        artifact['steps'].append({'index': s['index'],
            'status': 'unsupported' if any(i['category'] == 'unsupported' for i in issues)
                      else 'needs_information' if issues or not check['ready'] else 'ready',
            'issues': issues, 'source': copy.deepcopy(s['source']),
            'executor': copy.deepcopy(s['executor']),
            'prerequisites': copy.deepcopy(s['prerequisites']),
            'runner_evidence': copy.deepcopy(s.get('runner_evidence'))})
        artifact['steps'][-1]['next_action'] = (
            'Cần adapter có schema/phạm vi và kiểm thử cho nguồn này; không nhập shell thay thế.'
            if any(i['category']=='unsupported' for i in issues) else
            'Đối chiếu từng prerequisite bên dưới; khảo sát lại nếu snapshot hết hạn. Xác nhận không thay thế bằng chứng.'
            if issues or not check['ready'] else 'Có thể xác nhận trong thời hạn validation; runtime sẽ kiểm tra lại.')
    artifact['sha256'] = digest(artifact)
    return artifact


def verify_expected(artifact, record):
    if artifact.get('sha256') != digest({k:v for k,v in artifact.items() if k!='sha256'}):
        raise ValueError('Expected contract hash mismatch')
    if artifact.get('plan_sha256') != record.get('plan_sha256') or artifact.get('execution_id') != record['id']:
        raise ValueError('Expected contract binding mismatch')
    if artifact.get('validation_binding') != record.get('preflight',{}).get('binding_sha256'):
        raise ValueError('Expected validation binding mismatch')


def expected(record, *, historical=False):
    """No observed result/state/exit/alert enters expectation selection."""
    check = record.get('preflight', {})
    steps = []
    for s in check.get('steps', []):
        executor = s.get('executor', {})
        windows = executor.get('platform') == 'windows' and executor.get('name') in ('cmd', 'psh')
        steps.append({'step_id': record['id'] + ':' + str(s['index']), 'index': s['index'],
            'ability_id': s.get('source_ability_id'), 'source': copy.deepcopy(s.get('source')),
            'technique_ids': sorted(set(s.get('technique_ids', []))),
            'executor': copy.deepcopy(executor), 'target': copy.deepcopy(record.get('target')),
            'command_sha256': hashlib.sha256(s.get('command', '').encode()).hexdigest(),
            'execution_expectation': 'completed_with_exit_code_zero',
            'telemetry': {'status': 'defined' if windows else 'not_defined',
                'profile': 'windows_executor_process_launch_v1' if windows else None,
                'alternatives': [{'channel': 'Security', 'event_id': '4688'},
                    {'channel': 'Microsoft-Windows-Sysmon/Operational', 'event_id': '1'}] if windows else [],
                'expected_count': None, 'criterion': 'at_least_one_correlated_process_launch' if windows else None,
                'provenance': 'executor platform/name; process launch only, not command semantics'},
            'alert': {'status': 'not_defined', 'expected_count': None, 'rule_ids': [],
                      'reason': 'No independently validated rule expectation/baseline'},
            'behavior_verifier': 'unsupported'})
    artifact = {'schema_version': 'execution_expected_v1', 'execution_id': record['id'],
        'plan_sha256': record.get('plan_sha256'), 'validation_binding': check.get('binding_sha256'),
        'origin': 'historical_reconstruction_from_preflight' if historical else 'before_execution',
        'steps': steps}
    artifact['sha256'] = digest(artifact)
    return artifact


def fraction(numerator, denominator):
    return {'numerator': numerator, 'denominator': denominator,
            'percent': 100 * numerator / denominator if denominator else None}


def comparison(record, contract, state, events):
    actual = {s['index']: s for s in record.get('steps', [])}
    complete = not state.get('error') and not state.get('truncated') and state.get('status') == 'complete'
    trusted = state.get('identity_policy', {}).get('verified', False)
    rows = []; executed = set(); observed = set(); associated = set(); planned = set()
    for step in contract['steps']:
        result = actual.get(step['index'], {})
        success = result.get('state') == 'completed' and str(result.get('exit_code')) == '0'
        evidence = [e for e in events if e['correlation']['step_index'] == step['index']
                    and trusted and not e['correlation']['ambiguous'] and not e['test_marker']
                    and e['source'].get('component') not in ('execution', 'scenario', 'survey')]
        telemetry = [e for e in evidence if any(all(e['source'].get(k) == v for k, v in alt.items())
                     for alt in step['telemetry']['alternatives'])]
        alerts = {(e['index'], e['document_id']) for e in evidence
                  if str(e.get('index', '')).startswith('wazuh-alerts-') and e['rule']['id']}
        # Alerts-only cannot disprove missing telemetry; positive evidence can establish presence.
        evaluable = success and step['telemetry']['status'] == 'defined' and trusted and (
            bool(telemetry) or (complete and state.get('mode') == 'alerts_and_archives'))
        techniques = set(step['technique_ids']); planned |= techniques
        if success: executed |= techniques
        if telemetry: observed |= techniques
        if alerts: associated |= techniques
        rows.append({'step_id': step['step_id'], 'index': step['index'], 'expected': step,
            'command_status': result.get('state', 'not_run'), 'command_success': success,
            'behavior_status': 'not_verified', 'telemetry_evaluable': evaluable,
            'telemetry_matched': bool(telemetry), 'alert_evaluable': False,
            'alert_status': 'not_defined', 'correlated_alert_count': len(alerts) if trusted else None,
            'evidence_refs': [{'index': e['index'], 'document_id': e['document_id'],
                               'correlation': e['correlation']} for e in evidence],
            'reason': None if evaluable else 'Source, identity, query or expectation insufficient; not a detection verdict'})
    denom = sum(r['telemetry_evaluable'] for r in rows)
    defined = sum(r['expected']['telemetry']['status'] == 'defined' for r in rows)
    return {'schema_version': 'expected_reality_v1', 'expected_sha256': contract['sha256'], 'steps': rows,
        'execution_completion': fraction(sum(r['command_success'] for r in rows), len(rows)),
        'telemetry_coverage': {**fraction(sum(r['telemetry_evaluable'] and r['telemetry_matched'] for r in rows), denom),
            'total_steps_with_expectation': defined, 'not_evaluated': defined - denom,
            'denominator_definition': 'Successful steps with defined expectation and evaluable source/query/identity'},
        'alert_coverage': {**fraction(0, 0), 'not_defined': len(rows)},
        'techniques': {'expected': sorted(planned), 'executed': sorted(executed),
                       'telemetry_supported': sorted(observed), 'alert_associated': sorted(associated)},
        'partial': bool(state.get('truncated') or state.get('error') or not trusted)}
