"""Shared GUI/CLI Survey 2.0 loader. Standard library only; never accesses network."""
import copy
import hashlib
import json
import ipaddress
from urllib.parse import urlsplit
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ADAPTER = 'scenario_survey_v2.2'
MAX_BYTES, MAX_FILE, MAX_FILES = 32_000_000, 8_000_000, 512
SCHEMAS = Path(__file__).resolve().parents[1] / 'input/schema/survey_v2'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def schema_check(value, node, schema, at='$'):
    """Validate the exact subset used by the pinned producer schemas, without extra dependencies."""
    if '$ref' in node:
        ref = node['$ref']
        if not ref.startswith('#/'): raise ValueError('External schema reference forbidden')
        target = schema
        for key in ref[2:].split('/'): target = target[key]
        return schema_check(value, target, schema, at)
    if 'anyOf' in node:
        for choice in node['anyOf']:
            try: schema_check(value, choice, schema, at); return
            except ValueError: pass
        raise ValueError('Schema alternatives failed at '+at)
    if 'const' in node and value != node['const']: raise ValueError('Schema constant mismatch at '+at)
    if 'enum' in node and value not in node['enum']: raise ValueError('Schema enum mismatch at '+at)
    kind = node.get('type')
    types = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool, 'null': type(None)}
    if kind in types and type(value) is not types[kind]: raise ValueError('Schema type mismatch at '+at)
    if kind == 'object':
        if any(k not in value for k in node.get('required', [])): raise ValueError('Required schema field missing at '+at)
        props = node.get('properties', {})
        for key, item in value.items():
            if key in props: schema_check(item, props[key], schema, at+'.'+key)
            elif node.get('additionalProperties') is False: raise ValueError('Extra schema field at '+at+'.'+key)
            elif isinstance(node.get('additionalProperties'), dict): schema_check(item, node['additionalProperties'], schema, at+'.'+key)
    if kind == 'array':
        for i, item in enumerate(value): schema_check(item, node.get('items', {}), schema, at+f'[{i}]')
    if isinstance(value, str) and node.get('pattern') and not re.search(node['pattern'], value):
        raise ValueError('Schema pattern mismatch at '+at)


def validate_schema(value, name):
    schema = json.loads((SCHEMAS/(name+'.schema.json')).read_text())
    schema_check(value, schema, schema)


def safe_path(root, name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
        raise ValueError('Unsafe bundle path')
    p = PurePosixPath(name)
    if p.is_absolute() or any(t in ('..', '.') for t in name.split('/')) or ':' in name:
        raise ValueError('Bundle traversal/absolute path rejected')
    root = Path(root).absolute()
    path = root / name
    for part in [root, *root.parents, path, *path.parents]:
        if part.is_symlink(): raise ValueError('Symlink bundle path rejected')
    if root.resolve() not in path.resolve().parents: raise ValueError('Bundle path escapes root')
    return path


def pointer(doc, location):
    if not isinstance(location, str) or (location and not location.startswith('/')) or re.search(r'~(?![01])', location):
        raise ValueError('Invalid JSON Pointer')
    value = doc
    for token in location.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        if isinstance(value, list):
            if not re.fullmatch(r'0|[1-9][0-9]*', token): raise ValueError('Invalid JSON array index')
            try: value = value[int(token)]
            except IndexError: raise ValueError('Missing JSON Pointer index') from None
        elif isinstance(value, dict) and token in value: value = value[token]
        else: raise ValueError('Missing JSON Pointer value')
    return value


def read_bytes(path):
    if path.stat().st_size > MAX_FILE: raise ValueError('Bundle file too large')
    return path.read_bytes()


def no_duplicate_keys(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=no_duplicate_keys)


def load_directory(root):
    root = Path(root).absolute()
    manifest_bytes = read_bytes(safe_path(root, 'scenario_handoff.json'))
    manifest = decode(manifest_bytes)
    validate_schema(manifest, 'scenario_handoff')
    if manifest['schema_version'] != '2.0': raise ValueError('Unsupported Survey version')
    records = manifest['artifacts']
    if len(records) > MAX_FILES: raise ValueError('Too many bundle artifacts')
    contents, hashes, total = {}, {}, len(manifest_bytes)
    for entry in records:
        name = entry.get('file')
        if name in contents or name == 'scenario_handoff.json': raise ValueError('Duplicate/self-hashed manifest artifact')
        if not isinstance(entry.get('sha256'), str) or not re.fullmatch('[a-f0-9]{64}', entry['sha256']):
            raise ValueError('Invalid artifact hash')
        data = read_bytes(safe_path(root, name)); total += len(data)
        if total > MAX_BYTES: raise ValueError('Bundle exceeds byte budget')
        if sha(data) != entry['sha256']: raise ValueError('Survey artifact hash mismatch: '+name)
        hashes[name] = sha(data); contents[name] = data
    required = {'survey_context.json', 'target_profile_v2.json', 'source_manifest.json'}
    if not required.issubset(contents): raise ValueError('Incomplete Survey bundle')
    docs = {name: decode(data) for name, data in contents.items()}
    def check_secrets(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if re.fullmatch(r'(?i)(?:password|passwd|cookie|cookies|set-cookie|authorization|api_key|access_token|refresh_token|csrf_token|session_token|secret|token|credentials|raw_body|body|stdout|stderr|output|command|payload)', key):
                    if item not in (None, '[REDACTED]', False): raise ValueError('Unredacted secret field in Survey bundle')
                if key == 'inputs' and isinstance(item, list):
                    if any(isinstance(v, dict) and v.get('value') not in (None, '[REDACTED]') for v in item):
                        raise ValueError('Unredacted form values in Survey bundle')
                check_secrets(item)
        elif isinstance(value, list):
            for item in value: check_secrets(item)
    for doc in docs.values(): check_secrets(doc)
    context, profile = docs['survey_context.json'], docs['target_profile_v2.json']
    validate_schema(context, 'survey_context'); validate_schema(profile, 'target_profile_v2')
    for key in ('survey_run_id', 'target_id', 'target_ip', 'scope', 'status', 'started_at', 'finished_at'):
        if context[key] != manifest[key]: raise ValueError('Survey manifest/context identity mismatch: '+key)
    for key in ('target_id', 'target_ip'):
        if profile[key] != context[key]: raise ValueError('Survey profile/context target mismatch')
    if not context['target_id'] or not context['target_ip']: raise ValueError('Survey has no structured target identity')
    ipaddress.ip_address(context['target_ip'])
    for doc in docs.values():
        if isinstance(doc, dict) and doc.get('target_ip') not in (None, context['target_ip']):
            raise ValueError('Evidence source target differs from Survey identity')
    if not set(context['scope']).issubset({'web', 'endpoint'}): raise ValueError('Unsupported Survey scope')
    legacy = docs.get('target_profile.json')
    if legacy and (legacy.get('id') != context['target_id'] or legacy.get('address') != context['target_ip']):
        raise ValueError('Legacy/Survey target mismatch')
    def verify_ref(ref):
        name = ref['file']
        if name not in hashes or hashes[name] != ref['sha256']: raise ValueError('Unattested or mismatched evidence ref')
        return pointer(docs[name], ref['pointer'])
    ids = set()
    for fact in context['observations']:
        if fact['id'] in ids: raise ValueError('Duplicate fact ID')
        ids.add(fact['id'])
        if fact['status'] == 'inferred' and not fact.get('basis'): raise ValueError('Inferred fact lacks basis')
        if fact['status'] != 'unknown' and not fact['evidence_refs']: raise ValueError('Fact lacks provenance')
        for ref in fact['evidence_refs']: verify_ref(ref)
        # Typed predicates must match the pointed observation, not just an existing file.
        values = [verify_ref(r) for r in fact['evidence_refs']]
        predicate, value = fact['predicate'], fact['value']
        if predicate == 'listener':
            valid = False
            for ref in fact['evidence_refs']:
                data = verify_ref(ref)
                if not isinstance(data,dict) or not isinstance(value,dict): continue
                listener = value.get('listener')
                if not isinstance(listener,dict) or listener not in data.get('listeners',[]): continue
                pid = listener.get('OwningProcess')
                valid = (fact['subject']==str(listener.get('LocalPort')) and fact['observed_at']==data.get('collected_at')
                         and all(p in data.get('processes',[]) and p.get('pid')==pid for p in value.get('processes',[]))
                         and all(s in data.get('services',[]) and s.get('process_id')==pid for s in value.get('services',[])))
                if valid: break
            if not valid: raise ValueError('Listener fact differs from its endpoint evidence')
        endpoint_fields = {'os_name', 'os_version', 'architecture', 'hostname', 'is_elevated', 'powershell_version'}
        runner_fields = {'paw', 'executors', 'privilege', 'platform'}
        if predicate in endpoint_fields | runner_fields or predicate.startswith('legacy_os.') or fact['subject'] == 'legacy-survey-capabilities':
            field = predicate.split('.', 1)[1] if predicate.startswith('legacy_os.') else predicate
            if value not in values or any(not r['pointer'].endswith('/'+field) for r in fact['evidence_refs']):
                raise ValueError('Typed endpoint/runner fact is unrelated to its evidence')
            if predicate in endpoint_fields:
                if any(r['file'] != '02_endpoint.json' for r in fact['evidence_refs']): raise ValueError('OS facts require endpoint source')
                source_time = docs['02_endpoint.json'].get('data', docs['02_endpoint.json']).get('collected_at')
                if fact['observed_at'] != source_time: raise ValueError('Endpoint fact time differs from source')
            if predicate in runner_fields and fact['status'] not in ('configured', 'unknown'):
                raise ValueError('Runner metadata must not be elevated to observed')
            if predicate.startswith('legacy_os.') or fact['subject'] == 'legacy-survey-capabilities':
                if fact['status'] not in ('inferred', 'unknown'): raise ValueError('Legacy metadata must not be elevated to observed')
        if predicate == 'application_identity' and fact['status'] not in ('inferred', 'unknown'):
            raise ValueError('Application identification must retain producer inference status')
        if predicate == 'manager_ingestion':
            if not isinstance(value, list) or not value or any(v.get('source') not in ('alerts/alerts.json', 'archives/archives.json') for v in value):
                raise ValueError('Ingestion fact lacks typed manager samples')
            if not any(isinstance(v, dict) and v.get('status') == 'observed' and all(s in v.get('evidence', []) for s in value) for v in values):
                raise ValueError('Ingestion fact differs from referenced check')
        if predicate == 'module_access_and_forms':
            if not isinstance(value, dict) or not isinstance(value.get('forms'), list) or not isinstance(value.get('path'), str):
                raise ValueError('Malformed module/form fact')
        exact = {'module_access_and_forms', 'http_access', 'local_event', 'application_identity'}
        if predicate in exact and value not in values: raise ValueError('Fact value differs from referenced observation')
        if predicate in ('module_access_and_forms', 'survey_session', 'http_access', 'local_event'):
            for ref in fact['evidence_refs']:
                if predicate == 'module_access_and_forms':
                    parent = pointer(docs[ref['file']], ref['pointer'].rsplit('/modules/', 1)[0])
                    stamp = parent.get('checked_at') if isinstance(parent, dict) else None
                else:
                    item = verify_ref(ref)
                    stamp = item.get('event_time') if predicate == 'local_event' else item.get('checked_at')
                if fact['observed_at'] != stamp: raise ValueError('Fact observation time differs from source')
        if predicate == 'module_access_and_forms':
            if not any(isinstance(v, dict) and fact['subject'].endswith(v.get('path', '\x00')) for v in values):
                raise ValueError('Module subject does not match evidence path')
        if predicate == 'application_location':
            if not isinstance(value, dict) or value.get('base_url') not in values or fact['subject'] != value['base_url']:
                raise ValueError('Application URL fact not supported by source')
            u = urlsplit(value['base_url'])
            if u.hostname != context['target_ip'] or value.get('origin') != u.scheme+'://'+u.netloc or value.get('base_path') != u.path or value.get('port') != (u.port or (443 if u.scheme == 'https' else 80)):
                raise ValueError('Application location semantics/target mismatch')
        if predicate == 'survey_session':
            if not any(isinstance(v, dict) and all(v.get(k) == value.get(k) for k in ('session_ready', 'current_security_level', 'status')) and v.get('base_url') == fact['subject'] for v in values):
                raise ValueError('Session fact not supported by source')
            if value.get('reverify_before_execution') is not True or value.get('scope') != 'survey_session_only':
                raise ValueError('Survey session cannot grant execution access')
    for ref in profile['inventory_refs']: verify_ref(ref)
    for row in context['coverage']:
        if row.get('source_ref'): verify_ref(row['source_ref'])
    for conflict in context['conflicts']:
        if not set(conflict.get('observation_ids', [])).issubset(ids): raise ValueError('Conflict cites unknown fact')
    contents['scenario_handoff.json'] = manifest_bytes
    return {'schema_version': '2.0', 'adapter_version': ADAPTER, 'manifest': manifest,
            'target_profile': profile, 'legacy_profile': legacy, 'survey_context': context,
            'evidence_quality': {'mode': manifest['consumer']['mode'], 'integrity': 'hashes_and_pointers_verified',
                                 'source_authenticity': 'local_source_or_untrusted_upload; hashes_are_not_signatures',
                                 'artifacts_checked': len(records), 'observations': len(ids)},
            '_contents': contents}


def load_bundle(source):
    source = Path(source)
    if source.is_dir(): return load_directory(source)
    if source.is_symlink(): raise ValueError('Symlink archive rejected')
    if source.stat().st_size > MAX_BYTES: raise ValueError('Archive too large')
    with tempfile.TemporaryDirectory(prefix='scenario-survey-') as tmp:
        with zipfile.ZipFile(source) as archive:
            seen, total = set(), 0
            entries = archive.infolist()
            if len(entries) > MAX_FILES+1: raise ValueError('Too many archive members')
            for info in entries:
                name = info.filename
                target = safe_path(tmp, name)
                if name in seen or info.is_dir() or stat.S_ISLNK(info.external_attr >> 16): raise ValueError('Invalid/duplicate archive member')
                seen.add(name); total += info.file_size
                if total > MAX_BYTES or info.file_size > MAX_FILE: raise ValueError('Archive expansion exceeds budget')
                if info.flag_bits & 1: raise ValueError('Encrypted archive unsupported')
                target.parent.mkdir(parents=True, exist_ok=True)
                data = archive.read(info)
                if len(data) != info.file_size: raise ValueError('Archive size mismatch')
                target.write_bytes(data)
        result = load_directory(tmp)
        if seen != set(result['_contents']): raise ValueError('Archive contains unattested members')
        return result


def planning_target(bundle):
    if bundle['legacy_profile']:
        return copy.deepcopy(bundle['legacy_profile'])
    c = bundle['survey_context']
    fields = {f['predicate']: f['value'] for f in c['observations'] if f['domain'] == 'endpoint' and f['status'] == 'observed'}
    return {'id': c['target_id'], 'address': c['target_ip'], 'os': {'name': fields.get('os_name'), 'version': fields.get('os_version'),
            'architecture': fields.get('architecture'), 'hostname': fields.get('hostname'), 'status': 'unknown'},
            'services': [], 'capabilities': dict.fromkeys(('sandcat_online', 'powershell_ready', 'admin_ready', 'web_runner_ready', 'web_reachable')), 'telemetry': {}}


def policy_for(target, scope, max_steps):
    if not isinstance(scope, list) or not scope or not set(scope).issubset({'web', 'endpoint'}): raise ValueError('Invalid planning scope')
    if type(max_steps) is not int or not 1 <= max_steps <= 20: raise ValueError('Invalid planning step limit')
    return {'version': ADAPTER, 'mode': 'plan_only', 'target_id': target['id'], 'target_ip': target['address'],
            'planning_scope': sorted(set(scope)), 'max_steps': max_steps, 'execution_authorized': False,
            'cleanup_required': True, 'rollback_required': True}


def snapshot(bundle, destination, request, policy):
    destination = Path(destination)
    if destination.exists(): raise ValueError('Input snapshot already exists')
    c = bundle['survey_context']
    if policy['target_id'] != c['target_id'] or policy['target_ip'] != c['target_ip']: raise ValueError('Policy/Survey target mismatch')
    if not set(policy['planning_scope']).issubset(c['scope']): raise ValueError('Planning scope exceeds surveyed scope')
    destination.mkdir(parents=True)
    try:
        for name, data in bundle['_contents'].items():
            p = safe_path(destination, 'survey/'+name); p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
        target = planning_target(bundle)
        target.setdefault('capabilities', {})['execution_scope'] = {'allowed_surfaces': policy['planning_scope'], 'allowed_targets': [c['target_ip']],
                               'mode': 'plan_only', 'execution_authorized': False}
        envelope = {'schema_version': '2.0', 'adapter_version': ADAPTER, 'request': request, 'policy': policy,
                    'target_profile': bundle['target_profile'], 'survey_context': c, 'evidence_quality': bundle['evidence_quality']}
        validate_schema(envelope, 'scenario_input_envelope')
        (destination/'input_envelope.json').write_bytes(canonical(envelope))
        (destination/'planning_target.json').write_bytes(canonical(target))
        manifest = {'schema_version': '2.0', 'adapter_version': ADAPTER, 'survey_run_id': c['survey_run_id'],
                    'files': {p.relative_to(destination).as_posix(): sha(p.read_bytes()) for p in sorted(destination.rglob('*')) if p.is_file()}}
        (destination/'input_manifest.json').write_bytes(canonical(manifest))
        return manifest
    except Exception:
        shutil.rmtree(destination)
        raise


def verify_snapshot(root, expected=None):
    root = Path(root)
    raw = read_bytes(safe_path(root, 'input_manifest.json'))
    if expected and sha(raw) != expected: raise ValueError('Pinned input snapshot changed; create a new job')
    manifest = decode(raw)
    if manifest.get('schema_version') != '2.0' or not {'input_envelope.json', 'planning_target.json', 'survey/scenario_handoff.json'}.issubset(manifest.get('files', {})):
        raise ValueError('Incomplete input snapshot manifest')
    if manifest.get('adapter_version') != ADAPTER: raise ValueError('Incompatible checkpoint adapter; create a new job from saved request')
    for name, digest in manifest['files'].items():
        if sha(read_bytes(safe_path(root, name))) != digest: raise ValueError('Input snapshot hash mismatch')
    envelope = decode(read_bytes(safe_path(root, 'input_envelope.json')))
    validate_schema(envelope, 'scenario_input_envelope')
    bundle = load_directory(root/'survey')
    if envelope['survey_context'] != bundle['survey_context'] or envelope['target_profile'] != bundle['target_profile']:
        raise ValueError('Envelope differs from attested Survey snapshot')
    policy = envelope['policy']
    target = decode(read_bytes(safe_path(root, 'planning_target.json')))
    if policy != policy_for(target, policy['planning_scope'], policy['max_steps']): raise ValueError('Unsafe or changed policy')
    if target['id'] != bundle['survey_context']['target_id'] or target['address'] != bundle['survey_context']['target_ip']:
        raise ValueError('Snapshot target mismatch')
    if not set(policy['planning_scope']).issubset(bundle['survey_context']['scope']): raise ValueError('Policy exceeds Survey scope')
    return envelope, target
