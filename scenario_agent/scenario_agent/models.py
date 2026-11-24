"""Pydantic structure follows the existing schemas, which remain authoritative.

Generate models from the schemas to avoid maintaining two diverging contracts.
JSON Schema handles patterns, uniqueness and conditional readiness constraints.
"""
import json
from typing import Any, Literal, Union
import yaml
from pydantic import ConfigDict, StrictBool, StrictInt, StrictStr, create_model
from jsonschema import Draft202012Validator

def read_schema(root, kind):
    name = 'user_request.schema.json' if kind == 'request' else 'scenario_plan.schema.yaml'
    return yaml.safe_load((root / 'input/schema' / name).read_text(encoding='utf-8'))

def model_from_schema(schema, name='Contract'):
    serial = [0]
    def build(node):
        if '$ref' in node:
            ref = schema
            for key in node['$ref'].split('/')[1:]:
                ref = ref[key.replace('~1', '/').replace('~0', '~')]
            return build(ref)
        if 'const' in node:
            return Literal[node['const']]
        if 'enum' in node:
            return Literal[tuple(node['enum'])]
        kind = node.get('type')
        if isinstance(kind, list):
            return Union[tuple(build(dict(node, type=k)) for k in kind)]
        if kind == 'object':
            if 'properties' not in node:
                return dict[str, build(node['additionalProperties'])] if isinstance(node.get('additionalProperties'), dict) else dict[str, Any]
            serial[0] += 1
            fields = {key: (build(value), ... if key in node.get('required', []) else None)
                      for key, value in node['properties'].items()}
            return create_model(f'{name}{serial[0]}', __config__=ConfigDict(extra='forbid', strict=True), **fields)
        if kind == 'array':
            return list[build(node.get('items', {}))]
        return {'string': StrictStr, 'integer': StrictInt, 'boolean': StrictBool, 'number': float, 'null': type(None)}.get(kind, Any)
    return build(schema)

def validate_contract(root, kind, value):
    schema = read_schema(root, kind)
    model_from_schema(schema).model_validate(value)
    Draft202012Validator(schema).validate(value)
    return value

def api_schema(schema):
    """Google supported subset only; always validate full contract afterwards."""
    allowed = {'$defs', '$ref', 'type', 'title', 'description', 'enum', 'items',
               'minItems', 'maxItems', 'minimum', 'maximum', 'anyOf', 'properties',
               'additionalProperties', 'required'}
    def clean(node):
        if not isinstance(node, dict):
            return node
        out = {}
        for key, value in node.items():
            if key == 'const':
                out['enum'] = [value]
                out.setdefault('type', 'string')
            elif key in ('properties', '$defs'):
                out[key] = {k: clean(v) for k, v in value.items()}
            elif key in allowed:
                out[key] = [clean(v) for v in value] if isinstance(value, list) else clean(value)
        return out
    return clean(schema)
