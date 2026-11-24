"""Dependency-free validator for the JSON Schema subset used by this project.

Schema files here are authoritative; unsupported keywords fail closed.
"""
from .web_profile import legacy_web_services

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUPPORTED = {'$schema', 'title', 'description', 'type', 'required', 'properties',
             'additionalProperties', 'items', 'minItems', 'minLength',
             'uniqueItems', 'enum', 'minimum', 'not'}


def validate(value, schema, path='$'):
    unknown = set(schema) - SUPPORTED
    if unknown:
        raise ValueError('Unsupported schema keywords: %s' % sorted(unknown))
    types = schema.get('type')
    if types:
        types = types if isinstance(types, list) else [types]
        checks = {'object': isinstance(value, dict), 'array': isinstance(value, list),
                  'string': isinstance(value, str), 'boolean': type(value) is bool,
                  'null': value is None, 'integer': type(value) is int,
                  'number': type(value) in (int, float)}
        if not any(checks[t] for t in types):
            raise ValueError('%s: expected %s' % (path, '/'.join(types)))
    if 'not' in schema:
        try:
            validate(value, schema['not'], path)
        except ValueError:
            pass
        else:
            raise ValueError('%s: forbidden value or field' % path)
    if 'enum' in schema and value not in schema['enum']:
        raise ValueError('%s: value is not allowed' % path)
    if isinstance(value, dict):
        missing = set(schema.get('required', [])) - set(value)
        if missing:
            raise ValueError('%s: missing %s' % (path, sorted(missing)))
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False and set(value) - set(properties):
            raise ValueError('%s: unexpected fields %s' % (path, sorted(set(value) - set(properties))))
        for key, item in value.items():
            if key in properties:
                validate(item, properties[key], path + '.' + key)
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0):
            raise ValueError('%s: too few items' % path)
        if schema.get('uniqueItems') and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
            raise ValueError('%s: duplicate items' % path)
        for i, item in enumerate(value):
            validate(item, schema.get('items', {}), '%s[%s]' % (path, i))
    if isinstance(value, str) and len(value.strip()) < schema.get('minLength', 0):
        raise ValueError('%s: empty string' % path)
    if type(value) in (int, float) and 'minimum' in schema and value < schema['minimum']:
        raise ValueError('%s: below minimum' % path)


def validate_document(value, kind):
    schema = json.loads((ROOT / (kind + '_schema.json')).read_text(encoding='utf-8'))
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        validate(value, schema)
    else:
        errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: str(e.path))
        if errors:
            raise ValueError('; '.join('%s: %s' % (list(e.path), e.message) for e in errors))
    return value


def normalize_profile(profile):
    """Migrate known legacy fields; preserve unknowns and target identity."""
    if not isinstance(profile, dict):
        raise ValueError('Target profile must be an object')
    result = copy.deepcopy(profile)
    result.pop('$schema_description', None)
    capabilities = result.get('capabilities', {})
    if not isinstance(capabilities, dict):
        raise ValueError('capabilities must be an object')
    capabilities.pop('art_ready', None)
    context = capabilities.get('planning_context', {})
    if not isinstance(context, dict):
        raise ValueError('planning_context must be an object')
    if 'assumed_fields' in context:
        context['assumed_fields'] = [x for x in context['assumed_fields'] if x != 'art_ready']
    if 'allowed_execution_tools' in context:
        context['allowed_execution_tools'] = [x for x in context['allowed_execution_tools'] if x != 'atomic_red_team']
    if 'web_execution' in context:
        context['web_execution'] = context['web_execution'].replace('catalog-backed', 'dataset-backed')
    if context.get('basis') == 'User requested assuming ART execution and logging are operational for scenario generation; these assumptions are not live verification.':
        context['basis'] = 'Historical planning assumptions only; execution and logging are not live verified.'
    services = result.get('services', [])
    if not isinstance(services, list) or not all(isinstance(s, dict) for s in services):
        raise ValueError('services must be an array of objects')
    result['services'] = legacy_web_services([s for s in services if s.get('name') != 'Atomic Red Team'])
    validate_document(result, 'target_profile')
    return result
