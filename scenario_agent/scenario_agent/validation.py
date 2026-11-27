"""Semantic invariants beyond JSON Schema. No live verifier exists in v0.1."""
import copy
from .selection import check_adaptation, plain
from .catalog import compatible_executors
from .models import validate_contract
from .behaviors import check_plan_coverage

def normalize_catalog_unknowns(plan, retrieval):
    """Map a catalog's explicitly unspecified privilege to the contract's null.

    Does not infer privilege, change known values or touch catalog/YAML input.
    Preserve the raw model response and return auditable transformations.
    """
    result = copy.deepcopy(plan)
    actions = []
    if not isinstance(result, dict) or not isinstance(result.get('metadata'), dict):
        return result, actions
    steps = result['metadata'].get('steps')
    if not isinstance(steps, list):
        return result, actions
    records = {x['record']['canonical_id']: x['record'] for x in retrieval['abilities']}
    for chain in retrieval['adversaries']:
        records.update({a['canonical_id']: a for a in chain['record']['abilities']})
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or not isinstance(step.get('executor'), dict):
            continue
        record = records.get(step.get('ability_id'))
        if (record and record['ability'].get('privilege') in ('', None)
                and step['executor'].get('privilege') == ''):
            step['executor']['privilege'] = None
            actions.append({'path': f'metadata.steps[{index}].executor.privilege',
                            'from': '', 'to': None,
                            'reason': 'Catalog does not specify privilege; preserve it as unknown.',
                            'ability_id': record['canonical_id']})
    return result, actions

def validate_request(config, request, target):
    validate_contract(config.root, 'request', request)
    if request['target_id'] != target['id']:
        raise ValueError('target_id mismatch')
    questions = list(request['clarifications_needed'])
    if request['objective'] is None:
        questions.append('Bạn muốn đánh giá hành vi hoặc mục tiêu nào?')
    if not request['scope']:
        questions.append('Bạn muốn kiểm thử endpoint, web hay cả hai?')
    allowed = target.get('capabilities', {}).get('execution_scope', {}).get('allowed_surfaces', [])
    if 'web' in request['scope'] and not any(s in allowed for s in ('web', 'dvwa', 'services_on_target')):
        questions.append('Target chưa có phạm vi web được xác nhận; cần cập nhật target profile.')
    if 'endpoint' in request['scope'] and 'endpoint' not in allowed:
        questions.append('Target chưa có phạm vi endpoint được xác nhận.')
    text = plain(request['text'])
    capabilities = target.get('capabilities', {})
    if capabilities.get('powershell_ready') is False and 'powershell' in text:
        questions.append('Target báo PowerShell chưa sẵn sàng; bạn muốn chọn executor khác hay cập nhật target profile?')
    if capabilities.get('sandcat_online') is False:
        questions.append('Target báo Sandcat chưa online; cần xác nhận agent trên target trước khi lập chuỗi phù hợp.')
    if 'windows' in target.get('os', {}).get('name', '').lower() and 'T1059.004' in request.get('requested_techniques', []):
        questions.append('Yêu cầu Unix shell T1059.004 trên Windows cần môi trường Linux/WSL đã xác nhận; chọn target hoặc technique phù hợp.')
    return list(dict.fromkeys(questions))

def validate_plan(config, plan, request, target, retrieval, plan_id, normalizations=None, evidence_registry=None, evidence_report=None, selected_context=None):
    plan, actions = normalize_catalog_unknowns(plan, retrieval)
    if normalizations is not None:
        normalizations.extend(actions)
    validate_contract(config.root, 'plan', plan)
    if evidence_registry is not None:
        policy = evidence_registry['policy']
        if (request.get('mode') != 'plan_only' or not set(request.get('scope', [])).issubset(policy['planning_scope'])
                or target['id'] != policy['target_id'] or target.get('address') != policy['target_ip']
                or (request.get('max_tests') is not None and not 1 <= request['max_tests'] <= policy['max_steps'])):
            raise ValueError('Request/target violates immutable policy during plan validation or resume')
    meta = plan['metadata']
    if plan['id'] != plan_id or meta['request_id'] != request['id'] or meta['target_id'] != target['id']:
        raise ValueError('Application-assigned identifiers changed')
    if 'objective' in plan:
        raise ValueError('CALDERA objective catalog not loaded; omit objective ID')
    if meta['readiness'] == 'ready_for_review':
        raise ValueError('No live verification provider in v0.1; cannot claim ready_for_review')
    if len(plan['atomic_ordering']) != len(meta['steps']):
        raise ValueError('Ordering and metadata step counts differ')
    records = {x['record']['canonical_id']: x['record'] for x in retrieval['abilities']}
    chains = {x['record']['id']: x['record'] for x in retrieval['adversaries']}
    for chain in chains.values():
        records.update({a['canonical_id']: a for a in chain['abilities']})
    allowed_sources = [a['provenance'] for a in records.values()] + [a['provenance'] for a in chains.values()]
    for source in meta['selection']['sources']:
        if source not in allowed_sources:
            raise ValueError('Unknown/changed selection provenance')
    strategy = meta['selection']['strategy']
    if strategy in ('reuse_adversary', 'adapt_adversary'):
        selected = [c for c in chains.values() if c['provenance'] in meta['selection']['sources']]
        if not selected:
            raise ValueError('Reuse/adapt requires retrieved adversary provenance')
        if strategy == 'reuse_adversary' and not any(c['ordering'] == plan['atomic_ordering'] for c in selected):
            raise ValueError('Reuse must preserve full canonical ordering')
        if strategy == 'adapt_adversary':
            check_adaptation(selected, plan['atomic_ordering'], request)
    max_tests = request['max_tests']
    if max_tests is not None and len(meta['steps']) > max_tests:
        raise ValueError('max_tests exceeded (v0.1 treats selected abilities as tests)')
    for index, (ability_id, step) in enumerate(zip(plan['atomic_ordering'], meta['steps']), 1):
        if step['step_index'] != index or step['ability_id'] != ability_id or ability_id not in records:
            raise ValueError('Noncanonical, unretrieved ID or incorrect ordering/index')
        record = records[ability_id]
        item = record['ability']
        if step['role'] != 'test':
            raise ValueError('v0.1 selected abilities must have role=test')
        if step['name'] != item['name'] or step['technique_ids'] != ([item['technique_id']] if item.get('technique_id') else []):
            raise ValueError('Name/technique differs from catalog')
        if step['executor']['privilege'] != (item.get('privilege') or None):
            raise ValueError('Privilege differs from catalog; unknown must stay null')
        matching = [ex for ex in compatible_executors(record, target) if
                    (ex['platform'], ex['name']) == (step['executor']['platform'], step['executor']['name'])]
        if len(matching) != 1:
            raise ValueError('Executor incompatible, missing or ambiguous')
        ex = matching[0]
        placeholders = set(ex.get('fact_placeholders', []))
        if set(step['parameters']) != placeholders:
            raise ValueError('Parameters must match executor fact_placeholders')
        if evidence_registry is None and any(value is not None for value in step['parameters'].values()):
            raise ValueError('v0.1 has no verified fact binding; keep parameters null')
        if record['provenance'] not in step['sources'] or any(s not in allowed_sources for s in step['sources']):
            raise ValueError('Step provenance mismatch')
        if step['readiness'] == 'ready_for_review' or not step['prerequisites']:
            raise ValueError('Executor/dependencies/scope still require verification')
        if evidence_registry is None and any(c['status'] == 'verified' for c in step['prerequisites']):
            raise ValueError('No live evidence registry; verified prerequisite not supported')
        if any(t['availability'] == 'verified' for t in step['expected_telemetry']):
            raise ValueError('No live telemetry verification; cannot claim verified')
        if not step['baseline'] or not step['cleanup_and_rollback'] or not step['health_checks']:
            raise ValueError('Need baseline, cleanup/rollback and health check instructions')
    covered = {technique.upper() for step in meta['steps'] for technique in step['technique_ids']}
    missing = [technique for technique in request.get('requested_techniques', [])
               if not any(actual == technique.upper() or actual.startswith(technique.upper() + '.') for actual in covered)]
    if missing:
        raise ValueError('Plan omits explicitly requested techniques: ' + ', '.join(missing))
    check_plan_coverage(plan, retrieval.get('behavior_coverage'))
    # Catalog labels do not prove semantic goal coverage or safe command behavior.
    # Every output retains explicit manual review and target-scope limitations.
    required_limit = 'Chưa kiểm chứng thực thi, phạm vi lệnh, dependencies và telemetry; cần người duyệt trước khi tích hợp CALDERA.'
    if required_limit not in meta['limitations']:
        meta['limitations'].append(required_limit)
    validate_contract(config.root, 'plan', plan)
    if evidence_registry is not None:
        from .target_evidence import assess_candidates, select_context, records_in, validate_evidence_plan
        report = evidence_report or assess_candidates(retrieval, evidence_registry, request)
        selected = selected_context or select_context(evidence_registry, request['text'], evidence_registry['policy']['planning_scope'], records_in(retrieval))[0]
        validate_evidence_plan(plan, evidence_registry, report, selected)
    return plan
