"""Semantic invariants beyond JSON Schema. No live verifier exists in v0.1."""
from .catalog import compatible_executors
from .models import validate_contract

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
    return list(dict.fromkeys(questions))

def validate_plan(config, plan, request, target, retrieval, plan_id):
    validate_contract(config.root, 'plan', plan)
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
        if any(value is not None for value in step['parameters'].values()):
            raise ValueError('v0.1 has no verified fact binding; keep parameters null')
        if record['provenance'] not in step['sources'] or any(s not in allowed_sources for s in step['sources']):
            raise ValueError('Step provenance mismatch')
        if step['readiness'] == 'ready_for_review' or not step['prerequisites']:
            raise ValueError('Executor/dependencies/scope still require verification')
        if any(c['status'] == 'verified' for c in step['prerequisites']):
            raise ValueError('No live evidence registry; verified prerequisite not supported')
        if any(t['availability'] == 'verified' for t in step['expected_telemetry']):
            raise ValueError('No live telemetry verification; cannot claim verified')
        if not step['baseline'] or not step['cleanup_and_rollback'] or not step['health_checks']:
            raise ValueError('Need baseline, cleanup/rollback and health check instructions')
    # This gate does not prove semantic goal coverage or safe command behavior.
    # Every output retains explicit manual review and target-scope limitations.
    required_limit = 'Chưa kiểm chứng thực thi, phạm vi lệnh, dependencies và telemetry; cần người duyệt trước khi tích hợp CALDERA.'
    if required_limit not in meta['limitations']:
        meta['limitations'].append(required_limit)
    validate_contract(config.root, 'plan', plan)
    return plan
