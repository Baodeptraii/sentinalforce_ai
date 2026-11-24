"""Explicit historical bindings supplied by an administrator; never inferred from hits."""
import hashlib
import json
from pathlib import Path
from datetime import datetime
from .wazuh_connector import ConnectorError


def date(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timezone required')
    return result


def resolve(root, target, window, filename='telemetry_identity_bindings.json'):
    path = Path(root) / filename
    if not path.exists():
        return None
    if path.is_symlink() or path.stat().st_size > 1_000_000:
        raise ConnectorError('identity_binding_file_invalid')
    doc = json.loads(path.read_text())
    if doc.get('schema_version') != 'historical_identity_bindings_v1':
        raise ConnectorError('identity_binding_schema_invalid')
    matches = []
    for b in doc.get('bindings', []):
        if b.get('target') != {'ip': target.get('ip'), 'host': target.get('host')}:
            continue
        if not (date(b['valid_from']) <= date(window['start']) <= date(window['end']) <= date(b['valid_until'])):
            continue
        date(b['verified_at'])
        if not b.get('verified_by') or b.get('purpose') != 'historical_identity':
            raise ConnectorError('identity_binding_attestation_missing')
        agent = b['agent']
        if not all(isinstance(agent.get(k), str) and agent[k] for k in ('id', 'name', 'ip')) or agent['ip'] != target['ip']:
            raise ConnectorError('identity_binding_agent_invalid')
        if not b.get('evidence_refs'):
            raise ConnectorError('identity_binding_evidence_missing')
        for ref in b['evidence_refs']:
            p = Path(root) / ref['file']
            if Path(root).resolve() not in p.resolve().parents or any(x.is_symlink() for x in (p, *p.parents)):
                raise ConnectorError('identity_binding_evidence_path_invalid')
            if not p.is_file() or p.stat().st_size > 8_000_000 or hashlib.sha256(p.read_bytes()).hexdigest() != ref['sha256']:
                raise ConnectorError('identity_binding_evidence_changed')
        matches.append(b)
    if len(matches) > 1:
        raise ConnectorError('identity_binding_ambiguous')
    return matches[0] if matches else None
