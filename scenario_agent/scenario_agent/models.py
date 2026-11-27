"""Pydantic structure follows the existing schemas, which remain authoritative.

Generate models from the schemas to avoid maintaining two diverging contracts.
JSON Schema handles patterns, uniqueness and conditional readiness constraints.
"""
import copy
import json
from typing import Any, Literal, Union
import yaml
from pydantic import ConfigDict, StrictBool, StrictInt, StrictStr, create_model
from jsonschema import Draft202012Validator

def read_schema(root, kind):
    name = 'user_request.schema.json' if kind == 'request' else 'scenario_plan.schema.yaml'
    return yaml.safe_load((root / 'input/schema' / name).read_text(encoding='utf-8'))

def plan_generation_schema(schema, app_context, retrieval=None, evidence_backed=False):
    """Narrow the generation contract to this run; retain the source contract.

    Application identifiers are not model choices. CALDERA objective IDs cannot
    be generated until an objective catalog is supported. Local validation still
    independently checks the model response against the full source contract.
    """
    result = copy.deepcopy(schema)
    properties = result['properties']
    properties.pop('objective', None)
    properties['id'] = {'type': 'string', 'enum': [app_context['id']]}
    metadata = properties['metadata']['properties']
    for name in ('request_id', 'target_id'):
        metadata[name] = {'type': 'string', 'enum': [app_context[name]]}
    # There is no live evidence registry in this version. Target-profile facts
    # do not authorize a model to assert that a prerequisite was verified.
    checks = result['$defs']['check']['properties']
    checks['status']['enum'] = ['verified', 'assumed', 'unknown', 'unmet'] if evidence_backed else ['assumed', 'unknown', 'unmet']
    metadata['readiness']['enum'] = ['needs_information', 'blocked']
    step = result['$defs']['step']
    step['properties']['readiness']['enum'] = ['needs_information', 'blocked']
    telemetry = step['properties']['expected_telemetry']['items']['properties']
    telemetry['availability']['enum'] = ['assumed', 'unknown', 'unavailable']
    if retrieval is not None:
        records = {a['record']['canonical_id']: a['record'] for a in retrieval['abilities']}
        for chain in retrieval['adversaries']:
            records.update({a['canonical_id']: a for a in chain['record']['abilities']})
        if retrieval.get('behavior_coverage'):
            grounded = {m['ability_id'] for row in retrieval['behavior_coverage']['coverage'] for m in row['matches']}
            records = {identifier: record for identifier, record in records.items() if identifier in grounded}
        if not records:
            raise ValueError('Cannot bind plan generation without retrieved ability records')
        properties['atomic_ordering']['items'] = {'type':'string','enum':sorted(records)}
        strategies = ['compose_abilities']
        if retrieval['adversaries']:
            strategies.append('adapt_adversary')
        if any(c['record'].get('reuse_eligible', True) for c in retrieval['adversaries']):
            strategies.append('reuse_adversary')
        metadata['selection']['properties']['strategy']['enum'] = strategies
        groups = {}
        for identifier, record in sorted(records.items()):
            groups.setdefault(record['ability'].get('privilege') or None, []).append(identifier)
        variants = []
        # Group by privilege rather than duplicating the whole step schema for
        # every ability. Each branch couples its IDs to their catalog privilege.
        for index, (privilege, identifiers) in enumerate(groups.items()):
            variant = copy.deepcopy(step)
            fields = variant['properties']
            fields['ability_id'] = {'type': 'string', 'enum': identifiers}
            fields['executor']['properties']['privilege'] = (
                {'type': 'null'} if privilege is None else {'type': 'string', 'enum': [privilege]})
            name = f'planner_step_privilege_{index}'
            result['$defs'][name] = variant
            variants.append({'$ref': '#/$defs/' + name})
        result['$defs']['step'] = {'anyOf': variants}
        sources = [r['provenance'] for r in records.values()] + [c['record']['provenance'] for c in retrieval['adversaries']]
        choices = []
        for source in sources:
            node = {'type': 'object', 'additionalProperties': False, 'required': ['kind','id','location','revision'],
                    'properties': {k: ({'type':'null'} if v is None else {'type':'string','enum':[v]}) for k,v in source.items()}}
            if node not in choices: choices.append(node)
        result['$defs']['source'] = {'anyOf': choices}
    return result

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


def wire_source_contract(data, schema):
    """Provider transport uses source handles; the exported contract stays full.

    Avoid a combinatorial nested union of long paths/hashes in Gemini's decoder.
    These are application-owned facts, selected by a checked reference, never
    inferred or silently repaired after a model emits an incorrect provenance.
    """
    choices=schema.get('$defs',{}).get('source',{}).get('anyOf')
    if not choices:return data,schema,{}
    sources=[]
    for node in choices:
        source={key:(None if field.get('type')=='null' else field['enum'][0])
                for key,field in node['properties'].items()}
        if source not in sources:sources.append(source)
    mapping={f'S{index}':source for index,source in enumerate(sources,1)}
    wire_schema=copy.deepcopy(schema)
    wire_schema['$defs']['source']={'type':'string','enum':list(mapping)}
    wire_data=copy.deepcopy(data)
    wire_data['source_references']=mapping
    retrieval=wire_data.get('retrieval',{})
    records=[a['record'] for a in retrieval.get('abilities',[])]+[a['record'] for a in retrieval.get('adversaries',[])]
    records += [a for chain in retrieval.get('adversaries',[]) for a in chain['record']['abilities']]
    for record in records:
        record['provenance_ref']=next((key for key,value in mapping.items() if value==record['provenance']),None)
    return wire_data,wire_schema,mapping


def expand_source_references(draft, mapping):
    result=copy.deepcopy(draft)
    locations=[result['metadata']['selection']]+result['metadata']['steps']
    for location in locations:
        references=location['sources']
        if not isinstance(references,list) or any(not isinstance(ref,str) or ref not in mapping for ref in references):
            raise ValueError('Model emitted an unknown source reference')
        location['sources']=[copy.deepcopy(mapping[ref]) for ref in references]
    return result
