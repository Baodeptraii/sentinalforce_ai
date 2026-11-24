"""Offline, deterministic evidence-backed Survey export. No network or model calls."""
import hashlib
import io
import json
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field
from .evidence_refs import resolve
from .runner import save

VERSION = '2.0'
MAX_BYTES = 32_000_000
MAX_FACTS = 2000
EXCLUDED = {'state.json', 'handoff.json', 'source_manifest.json', 'scenario_handoff.json',
            'survey_context.json', 'target_profile_v2.json'}
SECRET = re.compile(r'(?i)^(password|passwd|cookie|cookies|set-cookie|authorization|api_key|access_token|refresh_token|csrf_token|session_token|session_id|sessionid|phpsessid|client_secret|credentials|credential|secret|token|value|raw_body|body|stdout|stderr|output|command|payload)$')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def clean(value):
    """Retain metadata, never form values, response bodies or execution payloads."""
    if isinstance(value, dict):
        return {k: '[REDACTED]' if SECRET.match(k) else clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r'(?i)(bearer\s+|(?:password|passwd|token|api_key|cookie|secret)\s*[=:]\s*)[^\s;&]+', r'\1[REDACTED]', value)
        if value.startswith(('http://', 'https://')):
            u = urlsplit(value)
            return urlunsplit((u.scheme, u.netloc.rsplit('@', 1)[-1], u.path, '', ''))
    return value


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Ref(Strict):
    file: str
    pointer: str
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    source: str


class Fact(Strict):
    id: str
    domain: str
    subject: str
    predicate: str
    value: Any
    status: Literal['observed', 'configured', 'inferred', 'unknown']
    observed_at: str | None
    time_reason: str | None
    evidence_refs: list[Ref]
    basis: str | None = None


class Gap(Strict):
    subject: str
    reason: Literal['not_checked', 'out_of_scope', 'tool_error', 'truncated', 'stale', 'invalid_evidence', 'missing_time', 'insufficient_evidence']
    detail: str


class Context(Strict):
    schema_version: Literal['2.0']
    survey_run_id: str
    target_id: str | None
    target_ip: str | None
    scope: list[str]
    started_at: str | None
    finished_at: str | None
    status: str
    observations: list[Fact]
    gaps: list[Gap]
    conflicts: list[dict]
    coverage: list[dict]


class Profile(Strict):
    schema_version: Literal['2.0']
    target_id: str | None
    target_ip: str | None
    domains: dict[str, list[str]]
    summary: dict[str, Any]
    inventory_refs: list[Ref]
    interpretation: dict[str, Any]


class Handoff(Strict):
    schema_version: Literal['2.0']
    survey_run_id: str
    target_id: str | None
    target_ip: str | None
    scope: list[str]
    started_at: str | None
    finished_at: str | None
    status: str
    artifacts: list[dict[str, str]]
    quality: dict[str, Any]
    consumer: dict[str, Any]
    legacy: dict[str, Any]


def checked_ref(root, ref):
    filename = ref['file']
    if re.search(r'~(?![01])', ref['pointer']):
        raise ValueError('Invalid JSON Pointer escape')
    path = Path(filename)
    if path.is_absolute() or '..' in path.parts or '\\' in filename:
        raise ValueError('Unsafe evidence path')
    target = Path(root) / path
    if any(p.is_symlink() for p in [target, *target.parents]):
        raise ValueError('Symlink evidence rejected')
    if digest(target.read_bytes()) != ref['sha256']:
        raise ValueError('Evidence hash mismatch: ' + filename)
    return resolve(root, filename + '#' + ref['pointer'])


def build(root, run_id, job=None):
    root = Path(root)
    job = job or {}
    docs = {p.relative_to(root).as_posix(): json.loads(p.read_text()) for p in sorted(root.rglob('*.json'))}
    profile = docs.get('target_profile.json', {})
    request = docs.get('survey_request.json', {})
    report = docs.get('report.json', {})
    facts, gaps, coverage, inventories = [], [], [], []

    def gap(subject, reason, detail):
        row = {'subject': subject, 'reason': reason, 'detail': detail}
        if row not in gaps: gaps.append(row)

    def ref(file, pointer):
        result = {'file': file, 'pointer': pointer, 'sha256': digest((root/file).read_bytes()),
                  'source': docs[file].get('tool', file)}
        checked_ref(root, result)
        return result

    def add(domain, subject, predicate, value, file, pointer, stamp=None, status='observed', basis=None):
        if len(facts) >= MAX_FACTS:
            gap(file, 'truncated', 'Fact limit reached; full source retained in bundle.')
            return
        if value is None: status = 'unknown'
        key = json.dumps([domain, subject, predicate, value, file, pointer], sort_keys=True)
        facts.append({'id': 'fact-' + digest(key.encode())[:20], 'domain': domain, 'subject': subject,
                      'predicate': predicate, 'value': value, 'status': status, 'observed_at': stamp,
                      'time_reason': None if stamp else 'Source has no observation timestamp',
                      'evidence_refs': [ref(file, pointer)], 'basis': basis})

    # Legacy refs and attested tool hashes are verified separately before sanitization.
    for file, doc in docs.items():
        if not isinstance(doc, dict): continue
        data = doc.get('data', doc)
        if not isinstance(data, dict): continue
        prefix = '/data' if 'data' in doc else ''
        stamp = data.get('collected_at') or data.get('checked_at')
        if file.startswith('tool_') or file in ('02_endpoint.json', '03_web.json', '04_dvwa.json', 'telemetry_evidence.json'):
            coverage.append({'file': file, 'tool': doc.get('tool'), 'status': doc.get('status', 'recorded'),
                             'started_at': doc.get('started_at'), 'source_ref': ref(file, ''),
                             'planned': {k: data[k] for k in ('ports_planned', 'ports_checked', 'request_count') if k in data},
                             'modules_planned': data.get('authentication', {}).get('modules_planned', []) if isinstance(data.get('authentication'), dict) else []})
            if doc.get('status') in ('error', 'rejected'):
                gap(file, 'tool_error', 'Tool did not return successful evidence.')
                continue
        # Prefer canonical endpoint and raw web tools to avoid duplicate aggregate copies.
        if file == '02_endpoint.json':
            for key in ('os_name', 'os_version', 'architecture', 'hostname', 'is_elevated', 'powershell_version'):
                if key in data: add('endpoint', profile.get('id', run_id), key, data[key], file, prefix+'/'+key, stamp)
            for key in ('services', 'processes'):
                if key in data: inventories.append(ref(file, prefix+'/'+key))
            for i, listener in enumerate(data.get('listeners', [])):
                pid = listener.get('OwningProcess')
                value = {'listener': listener, 'processes': [p for p in data.get('processes', []) if p.get('pid') == pid],
                         'services': [s for s in data.get('services', []) if s.get('process_id') == pid]}
                add('endpoint', str(listener.get('LocalPort')), 'listener', value, file, prefix, stamp)
            for field, obs in data.get('telemetry_observations', {}).items():
                if obs.get('kind') in ('sysmon_event_1', 'sysmon_event_3', 'apache_access_entry'):
                    add('telemetry', field, 'local_event', obs, file, prefix+'/telemetry_observations/'+field, obs.get('event_time'))
        if file == '01_agent.json':
            for key in ('paw', 'executors', 'privilege', 'platform'):
                if key in data: add('runner', str(data.get('paw', 'survey-agent')), key, data[key], file, '/'+key, data.get('last_seen'), status='configured', basis='CALDERA agent metadata; revalidate before execution')
        if file.startswith('tool_') or file in ('03_web.json', '04_dvwa.json'):
            for i, obs in enumerate(data.get('requests', [])):
                add('web', obs.get('requested_url') or obs.get('url', file), 'http_access', obs, file, prefix+'/requests/'+str(i), obs.get('checked_at'))
            auth = data.get('authentication')
            if isinstance(auth, dict):
                base = auth.get('base_url')
                if base:
                    u = urlsplit(base)
                    add('web', base, 'application_location', {'base_url': base, 'origin': u.scheme+'://'+u.netloc, 'port': u.port or (443 if u.scheme == 'https' else 80), 'base_path': u.path}, file, prefix+'/authentication/base_url', auth.get('checked_at'))
                session = {k: auth.get(k) for k in ('session_ready', 'current_security_level', 'status')}
                session.update(scope='survey_session_only', reverify_before_execution=True, authentication_required=None)
                add('authentication', base or file, 'survey_session', session, file, prefix+'/authentication', auth.get('checked_at'))
                observed_paths = {m.get('path') for m in auth.get('modules', [])}
                for planned in auth.get('modules_planned', []):
                    if planned not in observed_paths: gap((base or '')+planned, 'not_checked', 'Planned module has no observation.')
                for i, module in enumerate(auth.get('modules', [])):
                    add('web', (base or '')+module.get('path', ''), 'module_access_and_forms', module, file, prefix+'/authentication/modules/'+str(i), auth.get('checked_at'))
        if file == 'web_evidence.json':
            for i, app in enumerate(data.get('applications', [])):
                add('web', app.get('base_url', file), 'application_identity', app, file, '/applications/'+str(i), status='inferred', basis='HTTP title/banner identification; version unverified')
        if file == 'telemetry_evidence.json':
            for field, check in data.get('checks', {}).items():
                # Mixed legacy flags do not prove manager ingestion or detection.
                samples = check.get('evidence', [])
                manager_samples = [s for s in samples if s.get('source') in ('alerts/alerts.json', 'archives/archives.json')]
                if manager_samples and check.get('status') == 'observed':
                    add('telemetry', field, 'manager_ingestion', manager_samples, file, '/checks/'+field, stamp)
                elif field == 'wazuh_ingestion':
                    gap(field, 'insufficient_evidence', 'No typed manager sample confirms ingestion.')
                if check.get('status') != 'observed':
                    gap(field, 'out_of_scope' if check.get('status') == 'out_of_scope' else 'not_checked', check.get('reason', 'No typed evidence'))
        def scan(value, pointer=''):
            if isinstance(value, dict):
                for k, v in value.items():
                    if 'truncat' in k and v is True: gap(file+'#'+pointer, 'truncated', 'Source explicitly reports truncation.')
                    scan(v, pointer+'/'+k)
            elif isinstance(value, list):
                for i, v in enumerate(value): scan(v, pointer+'/'+str(i))
        scan(doc)
    if profile and '02_endpoint.json' not in docs:
        for key, value in profile.get('os', {}).items():
            add('endpoint', profile.get('id', run_id), 'legacy_os.'+key, value, 'target_profile.json', '/os/'+key,
                status='inferred', basis='Legacy profile only; original OS observation not available')
    if profile:
        for key, value in profile.get('capabilities', {}).items():
            add('runner', 'legacy-survey-capabilities', key, value, 'target_profile.json', '/capabilities/'+key,
                status='inferred', basis='Legacy survey capability only; does not establish future runner readiness')
    for row in report.get('missing_information', []):
        gap(row.get('field', 'survey'), 'out_of_scope' if row.get('status') == 'out_of_scope' else 'not_checked', row.get('reason', 'Not checked'))
    attempted = {c['tool'] for c in coverage}
    for scope, tool in [('endpoint', 'collect_endpoint'), ('web', 'probe_web')]:
        if scope in request.get('survey_scope', []) and tool not in attempted and not (scope == 'endpoint' and '02_endpoint.json' in docs):
            coverage.append({'tool': tool, 'status': 'not_checked', 'source_ref': None})
            gap(tool, 'not_checked', 'No saved tool result establishes coverage.')
    for level in ('log_source_exists', 'collection_configuration', 'detection'):
        gap('telemetry.'+level, 'not_checked', 'Not established by typed evidence; service state and legacy booleans are insufficient.')
    gap('execution.authorization', 'out_of_scope', 'Survey observations grant no execution authorization.')
    for f in facts:
        if not f['observed_at']: gap(f['id'], 'missing_time', f['time_reason'])
    grouped = {}
    for f in facts: grouped.setdefault((f['subject'], f['predicate']), []).append(f)
    conflicts = []
    for (subject, predicate), rows in grouped.items():
        if len({json.dumps(r['value'], sort_keys=True) for r in rows}) > 1:
            conflicts.append({'subject': subject, 'predicate': predicate, 'observation_ids': [r['id'] for r in rows], 'resolution': 'unresolved; may represent temporal changes'})
    common = dict(schema_version=VERSION, survey_run_id=run_id, target_id=profile.get('id'),
                  target_ip=profile.get('address') or request.get('target_ip'), scope=request.get('survey_scope', report.get('scope', [])),
                  started_at=job.get('created_at'), finished_at=report.get('finished_at') or job.get('finished_at'), status=job.get('status') or report.get('status', 'partial'))
    context = Context(**common, observations=facts, gaps=gaps, conflicts=conflicts, coverage=coverage).model_dump()
    domains = {d: [f['id'] for f in facts if f['domain'] == d] for d in sorted({f['domain'] for f in facts})}
    summary = {d: [{k: f[k] for k in ('id', 'subject', 'predicate', 'value', 'status', 'observed_at')} for f in facts if f['domain'] == d and f['predicate'] != 'http_access'] for d in domains}
    v2 = Profile(schema_version=VERSION, target_id=common['target_id'], target_ip=common['target_ip'], domains=domains, summary=summary,
                 inventory_refs=inventories, interpretation={'session_scope': 'survey_only', 'execution_authorized': False, 'http_200_proves_exploit': False,
                 'freshness_policy': 'No automatic expiry; revalidate sessions and target before execution.', 'telemetry_unknown_levels': ['log_source_exists', 'collection_configuration', 'detection']}).model_dump()
    save(root/'target_profile_v2.json', v2)
    save(root/'survey_context.json', context)
    artifacts = [{'file': p.relative_to(root).as_posix(), 'sha256': digest(p.read_bytes())} for p in sorted(root.rglob('*.json'))]
    handoff = Handoff(**common, artifacts=artifacts, quality={'gaps': len(gaps), 'conflicts': len(conflicts), 'redacted_export': True},
                      consumer={'mode': 'evidence_backed' if any(f['status'] == 'observed' for f in facts) else 'profile_only', 'context_file': 'survey_context.json', 'profile_file': 'target_profile_v2.json',
                                'execution_authorized': False, 'preflight_required': True, 'verify_all_refs': True},
                      legacy={'profile': 'target_profile.json' if profile else None, 'handoff': 'Original handoff.json remains authoritative only for original bytes; omitted from sanitized export.',
                              'evidence_index': 'Original hashes recorded in source_manifest.json; sanitized hashes are in this manifest.'}).model_dump()
    save(root/'scenario_handoff.json', handoff)
    verify(root)
    return context


def verify(root):
    root = Path(root)
    handoff = Handoff.model_validate(json.loads((root/'scenario_handoff.json').read_text()))
    for entry in handoff.artifacts:
        checked_ref(root, {**entry, 'pointer': '', 'source': 'manifest'})
    context = Context.model_validate(json.loads((root/'survey_context.json').read_text()))
    profile = Profile.model_validate(json.loads((root/'target_profile_v2.json').read_text()))
    for ref in profile.inventory_refs: checked_ref(root, ref.model_dump())
    for row in context.coverage:
        if row.get('source_ref'): checked_ref(root, row['source_ref'])
    for fact in context.observations:
        for ref in fact.evidence_refs: checked_ref(root, ref.model_dump())
    return context


def convert(source, destination, job=None):
    """Publish a new immutable snapshot; never rewrite historical evidence."""
    source, destination = Path(source).resolve(), Path(destination).absolute()
    if destination.exists(): raise ValueError('Destination already exists')
    if source == destination or source in destination.parents and destination.parent != source:
        raise ValueError('Destination must be external or a direct run child')
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.survey-v2-', dir=destination.parent))
    try:
        original = {}
        total = 0
        for path in sorted(source.rglob('*')):
            if not path.is_file() and not path.is_symlink(): continue
            if any(part.startswith('.') for part in path.relative_to(source).parts): continue
            if 'survey_v2' in path.relative_to(source).parts: continue
            if path.is_symlink() or any(p.is_symlink() for p in path.parents): raise ValueError('Symlink source rejected')
            data = path.read_bytes()
            name = path.relative_to(source).as_posix()
            original[name] = digest(data)
            if path.name in EXCLUDED or path.suffix != '.json': continue
            total += len(data)
            if total > MAX_BYTES: raise ValueError('Source exceeds 32 MB; export refused without truncation')
            save(staging/name, clean(json.loads(data)))
        # Validate original ledger hashes and original profile pointers before redaction.
        index = source/'evidence_index.json'
        if index.exists():
            for entry in json.loads(index.read_text()).get('records', []):
                checked_ref(source, {**entry, 'pointer': '', 'source': 'legacy_index'})
        profile_file = source/'target_profile.json'
        if profile_file.exists():
            def refs(v):
                if isinstance(v, dict):
                    for k, x in v.items():
                        if k.endswith('_ref') and isinstance(x, str):
                            name, separator, pointer = x.partition('#')
                            if not separator: raise ValueError('Invalid legacy evidence reference')
                            path = Path(name)
                            if path.is_absolute() or '..' in path.parts: raise ValueError('Unsafe legacy reference')
                            checked_ref(source, {'file': name, 'pointer': pointer, 'sha256': original.get(name, ''), 'source': 'legacy'})
                            checked_ref(staging, {'file': name, 'pointer': pointer, 'sha256': digest((staging/name).read_bytes()), 'source': 'legacy_export'})
                        else: refs(x)
                elif isinstance(v, list):
                    for x in v: refs(x)
            refs(json.loads(profile_file.read_text()))
        save(staging/'source_manifest.json', {'schema_version': VERSION, 'source_run_id': source.name,
             'original_sha256': original, 'redaction': 'Structural secret fields and URL credentials/query values removed. Raw bodies, commands and outputs withheld.',
             'excluded': sorted(EXCLUDED), 'original_bytes_included': False})
        if job is None:
            # Only metadata fields are imported from excluded legacy manifests/state.
            metadata = {}
            for filename in ('handoff.json', 'state.json'):
                path = source/filename
                if path.exists():
                    raw = json.loads(path.read_text())
                    for key, alias in [('started_at', 'created_at'), ('created_at', 'created_at'), ('finished_at', 'finished_at'), ('status', 'status')]:
                        if raw.get(key) is not None: metadata[alias] = raw[key]
            job = clean(metadata)
        context = build(staging, (job or {}).get('id', source.name), job)
        for name, sha in original.items():
            if digest((source/name).read_bytes()) != sha: raise ValueError('Source changed during conversion')
        staging.rename(destination)
        return context
    finally:
        if staging.exists(): shutil.rmtree(staging)


def bundle_v2(root):
    verify(root)
    root = Path(root)
    metadata = json.loads((root/'scenario_handoff.json').read_text())
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        for entry in metadata['artifacts'] + [{'file': 'scenario_handoff.json', 'sha256': digest((root/'scenario_handoff.json').read_bytes())}]:
            checked_ref(root, {**entry, 'pointer': '', 'source': 'manifest'})
            archive.writestr(entry['file'], (root/entry['file']).read_bytes())
    if len(stream.getvalue()) > MAX_BYTES: raise ValueError('Bundle exceeds 32 MB')
    return stream.getvalue()


def select_context(context, domains=None, subjects=None):
    """Illustrative deterministic consumer filter, including shared session/location facts."""
    if not domains and not subjects: return dict(context)
    selected = [f for f in context['observations']
        if (not domains or f['domain'] in domains) and (not subjects or any(s in f['subject'] for s in subjects)
        or f['predicate'] in ('application_location', 'survey_session', 'application_identity'))]
    ids = {f['id'] for f in selected}
    files = {r['file'] for f in selected for r in f['evidence_refs']}
    result = dict(context, observations=selected)
    result['coverage'] = [c for c in context['coverage'] if c.get('file') in files]
    result['conflicts'] = [c for c in context['conflicts'] if ids.intersection(c['observation_ids'])]
    result['gaps'] = [g for g in context['gaps'] if g['subject'] in ids or g['subject'] == 'execution.authorization'
                      or any(g['subject'].startswith(d+'.') for d in domains or [])
                      or any(g['subject'].startswith(f+'#') or g['subject'] == f for f in files)
                      or any(s in g['subject'] for s in subjects or [])]
    return result
