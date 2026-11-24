"""Resolve local JSON Pointer references without leaving a run directory."""
import json
from pathlib import Path


def resolve(directory, reference):
    filename, separator, pointer = reference.partition('#')
    if not separator or not filename or (pointer and not pointer.startswith('/')):
        raise ValueError('Invalid evidence reference')
    root = Path(directory).resolve()
    path = (root / filename).resolve()
    if Path(filename).is_absolute() or root not in path.parents:
        raise ValueError('Evidence outside run directory')
    value = json.loads(path.read_text(encoding='utf-8'))
    for token in pointer.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        if isinstance(value, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith('0')): raise ValueError('Invalid array index')
            value = value[int(token)]
        else: value = value[token]
    return value


def validate_profile_refs(directory, profile):
    # Typed booleans alone cannot establish evidence. Legacy all-null profiles remain valid.
    if any(value is not None for value in profile.get('telemetry', {}).values()):
        from .telemetry import validate_evidence
        evidence = resolve(directory, 'telemetry_evidence.json#')
        validate_evidence(profile, evidence)
    for service in profile['services']:
        for item in [service] + (service.get('applications') or []):
            for key in ('evidence_ref', 'authentication_ref', 'modules_ref'):
                if item.get(key): resolve(directory, item[key])
