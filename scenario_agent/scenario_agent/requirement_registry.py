"""Versioned requirement registry over immutable Survey evidence; no collection/execution.

Rules describe resource semantics, never fixture application/ability identifiers.
Unsupported source constructs are explicit manual-review requirements.
"""
import copy
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, urljoin, parse_qs
from .survey_input import canonical, sha, load_directory, decode, pointer, schema_check

REGISTRY_VERSION = '1.0'
MAX_INVENTORY_RECORDS = 512
RULES = {
    'target.os': ('os_name',), 'target.architecture': ('architecture',),
    'runner.executor': ('executors',), 'runner.privilege': ('is_elevated', 'privilege'),
    'endpoint.process_inventory': ('inventory', 'process'), 'endpoint.service_inventory': ('inventory', 'service'),
    'endpoint.path': ('process', 'service', 'resource_path'),
    'endpoint.listener': ('listener',),
    'web.application': ('application_location', 'application_identity', 'web_origin'),
    'web.request': ('module_access_and_forms', 'http_access'), 'web.authentication': ('survey_session',),
    'web.csrf': ('module_access_and_forms',), 'catalog.dependency': (), 'catalog.cleanup': (),
    'telemetry.process': ('local_event', 'manager_ingestion'), 'telemetry.network': ('local_event', 'manager_ingestion'),
    'telemetry.web': ('local_event', 'manager_ingestion'), 'demo_receiver': (), 'unsupported': (),
}
PARAMETERS = {
    'target_ip': 'ip', 'target.ip': 'ip', 'victim_ip': 'ip', 'remote.host.ip': 'ip',
    'base_url': 'base_url', 'target_url': 'base_url', 'dvwa_url': 'base_url',
    'port': 'port', 'target_port': 'port', 'remote.host.port': 'listener_port', 'scheme': 'scheme',
    'module_path': 'module_path', 'process_name': 'process_name', 'process.name': 'process_name',
    'process_id': 'process_id', 'process.pid': 'process_id', 'service_name': 'service_name',
    'service.name': 'service_name', 'file_path': 'path', 'executable_path': 'path', 'host.file.path': 'path',
}
BASE_PREDICATES = {'os_name', 'architecture', 'hostname', 'paw', 'executors', 'privilege', 'is_elevated'}


def fact_check(f):
    return {'condition': 'survey.'+f['predicate']+':'+f['subject'],
            'status': 'verified' if f['status'] == 'observed' and f['observed_at'] is not None else 'unknown', 'evidence': f['id']}


def build_registry(envelope, root=None, contents=None):
    """Expand only attested inventory refs. The producer envelope remains byte-for-byte unchanged."""
    source_facts = copy.deepcopy(envelope['survey_context']['observations'])
    if any(f['id'].startswith('derived-') for f in source_facts): raise ValueError('Survey uses reserved adapter fact ID namespace')
    internal = {'process','service','inventory','web_origin','resource_path'}
    opaque = [f for f in source_facts if f['predicate'] in internal]
    facts = [f for f in source_facts if f['predicate'] not in internal]
    gaps = copy.deepcopy(envelope['survey_context']['gaps'])
    for f in opaque:
        gaps.append({'subject':f['id'],'reason':'unsupported_normalizer','detail':'Raw producer extension has no typed source verifier; preserved as opaque evidence, not a verified adapter projection'})
    if root is not None: contents = load_directory(root)['_contents']
    docs = {name: decode(data) for name, data in (contents or {}).items()}
    expanded = []
    for ref in envelope['target_profile'].get('inventory_refs', []):
        if ref['file'] not in docs:
            gaps.append({'subject': ref['file'], 'reason': 'invalid_evidence', 'detail': 'Attested inventory bytes not supplied to adapter'})
            continue
        if sha(contents[ref['file']]) != ref['sha256']: raise ValueError('Inventory ref hash mismatch')
        values = pointer(docs[ref['file']], ref['pointer'])
        kind = ref['pointer'].rsplit('/', 1)[-1]
        if kind not in ('processes', 'services') or not isinstance(values, list):
            gaps.append({'subject': ref['file']+'#'+ref['pointer'], 'reason': 'unsupported_normalizer', 'detail': 'Inventory kind has no typed projector; evidence retained'})
            continue
        parent = pointer(docs[ref['file']], ref['pointer'].rsplit('/', 1)[0])
        stamp = parent.get('collected_at') if isinstance(parent, dict) else None
        def append_fact(predicate, subject, value, source_ref):
            key = [predicate, subject, value, source_ref]
            facts.append({'id': 'derived-'+sha(canonical(key))[:20], 'domain': 'endpoint', 'subject': subject,
                'predicate': predicate, 'value': value, 'status': 'observed', 'observed_at': stamp,
                'time_reason': None if stamp else 'Inventory source has no collected_at', 'evidence_refs': [source_ref],
                'basis': 'Adapter projection of attested '+kind+'; returned inventory is not a completeness assertion'})
        append_fact('inventory', envelope['survey_context']['target_id']+'/'+kind,
                    {'kind': kind, 'returned_records': len(values), 'coverage': 'returned_records_only'}, ref)
        fields = {'pid', 'name', 'executable_path'} if kind == 'processes' else {'name', 'display_name', 'state', 'process_id'}
        projected = 0
        for i, item in enumerate(values[:MAX_INVENTORY_RECORDS]):
            valid = isinstance(item, dict) and isinstance(item.get('name'), str) and bool(item.get('name'))
            if valid and kind=='processes':
                valid = type(item.get('pid')) is int and item['pid']>=0 and (item.get('executable_path') is None or isinstance(item['executable_path'],str))
            if valid and kind=='services':
                valid = (item.get('process_id') is None or type(item['process_id']) is int and item['process_id']>=0) and (item.get('state') is None or isinstance(item['state'],str))
            if not valid:
                gaps.append({'subject': ref['file']+'#'+ref['pointer']+'/'+str(i), 'reason': 'unsupported_normalizer', 'detail': 'Unsupported inventory record shape retained in source'})
                continue
            value = {k: v for k, v in item.items() if k in fields}
            subject = envelope['survey_context']['target_id']+'/'+kind+'/'+str(item.get('pid', item['name']))
            append_fact('process' if kind == 'processes' else 'service', subject, value,
                        dict(ref, pointer=ref['pointer']+'/'+str(i)))
            projected += 1
            if set(item)-fields:
                gaps.append({'subject':ref['file']+'#'+ref['pointer']+'/'+str(i),'reason':'unsupported_normalizer','detail':'Unprojected inventory fields retained in attested source: '+','.join(sorted(set(item)-fields))})
        if len(values) > MAX_INVENTORY_RECORDS:
            gaps.append({'subject': ref['file']+'#'+ref['pointer'], 'reason': 'truncated',
                         'detail': 'Inventory projector limit; full attested source retained. Do not infer absence.'})
        expanded.append({'file': ref['file'], 'pointer': ref['pointer'], 'kind': kind,
                         'returned_records': len(values), 'projected_records': projected})
    for source in list(facts):
        if source['predicate'] != 'http_access' or source['status'] != 'observed': continue
        url = source['value'].get('url') or source['value'].get('requested_url')
        if not url: continue
        u = urlsplit(url)
        if u.scheme not in ('http','https') or u.hostname != envelope['survey_context']['target_ip']: continue
        value = {'origin':u.scheme+'://'+u.netloc,'scheme':u.scheme,'port':u.port or (443 if u.scheme=='https' else 80),
                 'application_base_path_known':False}
        origin = dict(source, id='derived-'+sha(canonical(['web_origin',source['id'],value]))[:20], predicate='web_origin',
                      subject=value['origin'], value=value, basis='Transport origin projected from observed HTTP URL; no application base-path inference')
        facts.append(origin)
    known = set().union(*(set(predicates) for predicates in RULES.values())) | BASE_PREDICATES | {'http_access', 'listener', 'os_version', 'powershell_version', 'platform'}
    for f in facts:
        if f['predicate'] not in known and not (f['predicate'].startswith('legacy_os.') or f['subject'] == 'legacy-survey-capabilities'):
            gaps.append({'subject': f['id'], 'reason': 'unsupported_normalizer', 'detail': 'Fact retained; no requirement resolver is registered for '+f['predicate']})
    result = {'schema_version': '1.0', 'survey_run_id': envelope['survey_context']['survey_run_id'],
              'target_id':envelope['survey_context']['target_id'],'target_ip':envelope['survey_context']['target_ip'],
              'evidence_root':'input/survey', 'survey_manifest_sha256':sha(contents['scenario_handoff.json']) if contents and 'scenario_handoff.json' in contents else None,
              'observations': facts, 'opaque_observations':opaque, 'gaps': gaps, 'expanded_sources': expanded,
              'source_fact_count': len(envelope['survey_context']['observations']),
              'derived_fact_count': sum(f['id'].startswith('derived-') for f in facts)}
    schema = json.loads((Path(__file__).resolve().parents[1]/'input/schema/survey_v2/evidence_registry.schema.json').read_text())
    schema_check(result,schema,schema)
    return result


def registry(envelope):
    return envelope.get('_fact_registry') or {'observations': envelope['survey_context']['observations'],
        'gaps': envelope['survey_context']['gaps'], 'expanded_sources': [], 'derived_fact_count': 0}


_RECEIVER_CONFIG = None


def receiver_config():
    """Typed bundle-local allowlist for the EP-03 internal demo receiver.

    This never widens the web target surface: receiver URLs are excluded from
    web application binding and get their own requirement kind with an
    execution-time verification blocker."""
    global _RECEIVER_CONFIG
    if _RECEIVER_CONFIG is not None:
        return _RECEIVER_CONFIG if _RECEIVER_CONFIG != 'missing' else None
    path = Path(__file__).resolve().parents[1] / 'input/demo_receiver.json'
    try:
        value = json.loads(path.read_text())
        origin = urlsplit(value['origin'])
        assert origin.scheme in ('http', 'https') and origin.hostname
        assert isinstance(value.get('bounds'), dict)
        _RECEIVER_CONFIG = {'origin': origin,
                            'bounds': value['bounds'],
                            'origin_text': value['origin']}
    except (OSError, ValueError, KeyError, AssertionError):
        _RECEIVER_CONFIG = 'missing'
    return None if _RECEIVER_CONFIG == 'missing' else _RECEIVER_CONFIG


def receiver_urls_in(command):
    """Exact literal receiver URLs present in a command; empty when disabled."""
    config = receiver_config()
    if not config:
        return set()
    found = set()
    for url in re.findall(r'https?://[^\s"\'<>]+', command or ''):
        try:
            u = urlsplit(url)
        except ValueError:
            continue
        o = config['origin']
        if (u.scheme, u.hostname, u.port) == (o.scheme, o.hostname, o.port):
            found.add(url.rstrip('.,;'))
    return found


def normal_path(path):
    return str(path).replace('\\', '/').rstrip('/').casefold()


def logical_lines(command):
    return re.sub(r'(?:`|\\)\r?\n\s*', ' ', command).splitlines()


def source_analysis(record, executor):
    command = executor.get('command') or executor.get('code') or ''
    overrides = []
    psh = re.compile(r"(?P<var>\$\w+)\s*=\s*if\s*\(\$env:(?P<env>\w+)\)\s*\{\s*\$env:(?P=env)\s*\}\s*else\s*\{\s*[\"'](?P<url>https?://[^\"']+)[\"']\s*\}", re.I)
    shell = re.compile(r'(?P<var>\w+)="\$\{(?P<env>\w+):-' + r'(?P<url>https?://[^"}]+)\}"')
    for pattern in (psh, shell):
        for m in pattern.finditer(command):
            variable = m['var'] if m['var'].startswith('$') else '$'+m['var']
            if variable in command[m.end():]: overrides.append(dict(m.groupdict(), var=variable))
    literals = []
    for m in re.finditer(r'''(?m)^\s*(\$?\w+)\s*=\s*["'](https?://[^"']+)["']\s*;?\s*$''',command):
        variable=m.group(1) if m.group(1).startswith('$') else '$'+m.group(1)
        literals.append({'var':variable,'url':m.group(2)})
    hosts = []
    for m in re.finditer(r'''(?m)^\s*(\$?\w+)\s*=\s*["']([^"']+)["']\s*;?\s*$''',command):
        variable=m.group(1) if m.group(1).startswith('$') else '$'+m.group(1)
        value=m.group(2);parameter=re.fullmatch(r'#\{([\w.]+)\}',value)
        if parameter and PARAMETERS.get(parameter.group(1).lower())=='ip': hosts.append({'var':variable,'parameter':parameter.group(1)})
        else:
            try: hosts.append({'var':variable,'ip':str(ipaddress.ip_address(value))})
            except ValueError: pass
    calls = []
    for line in logical_lines(command):
        if line.lstrip().startswith('#'): continue
        if not re.search(r'\b(?:curl(?:\.exe)?|Invoke-WebRequest|Invoke-RestMethod)\b', line, re.I): continue
        tokens = re.findall(r'''["']([^"']*)["']''', line)
        urls = [t for t in tokens if re.match(r'^(?:https?://|\$\w+/|\$\{\w+\}/|#\{[\w.]+\})', t)]
        if not urls:
            urls = re.findall(r'https?://[^\s"\x27;<>]+', line)
        method = re.search(r'(?:-Method|--request|-X)\s+["\x27]?(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)', line, re.I)
        dynamic_method = bool(re.search(r'(?:-Method|--request|-X)\s+\$', line, re.I))
        method = method.group(1).upper() if method else ('POST' if re.search(r'(?:\s-d\s|--data\b|--form\b|\s-F\s)', line) else 'GET')
        if re.search(r'(?:\s-G\b|--get\b)', line): method = 'GET'
        if dynamic_method: method = None
        body_unknown = bool(re.search(r'(?:-Body|\s-d|--data(?:-urlencode)?)\s+\$', line, re.I))
        body_names = set()
        for m in re.finditer(r'''(?:\s-d|--data(?:-urlencode)?|--form|-F)\s+["']([^"']*)["']''', line):
            body_names.update(parse_qs(m.group(1), keep_blank_values=True))
        for url in urls:
            query_template = re.sub(r'#\{([\w.]+)\}', r'FACT_\1', url)
            calls.append({'url_template': url, 'method': method, 'parameter_names': sorted(set(parse_qs(urlsplit(query_template).query, keep_blank_values=True)) | body_names),
                          'session_reference_required': bool(re.search(r'(?:\s-b\b|-WebSession\b|-Credential\b)', line, re.I)),
                          'parameter_contract_complete': not body_unknown, 'source_fragment_sha256': sha(line.encode())})
        if not urls: calls.append({'url_template': None, 'method': method, 'parameter_names': [], 'session_reference_required': True, 'parameter_contract_complete': not body_unknown, 'source_fragment_sha256': sha(line.encode())})
    inventory = []
    if re.search(r'Get-Process|tasklist|wmic\s+process|(?:^|[;\n])\s*ps\s', command, re.I): inventory.append('processes')
    if re.search(r'Get-Service|sc(?:\.exe)?\s+(?:query|qc|start|stop)|systemctl|Get-CimInstance\s+Win32_Service', command, re.I): inventory.append('services')
    resource_filters = []
    for kind, name in re.findall(r'''Get-(Process|Service)[^;\n]*?-Name\s+["']?([A-Za-z0-9_.-]+)''', command, re.I):
        resource_filters.append({'kind':kind.lower(),'name':name})
    effects = []
    effect_rules = {
        'file_write': r'(?:>>|Out-File|Set-Content|New-Item|\bcp\s|\bCopy-Item\b)',
        'file_delete': r'(?:Remove-Item|\brm\s|\bdel\s)',
        'service_change': r'(?:Start-Service|Stop-Service|Set-Service|sc(?:\.exe)?\s+(?:start|stop|config)|systemctl\s+(?:start|stop|enable))',
        'remote_dependency': r'(?:DownloadString|DownloadData|Start-BitsTransfer)',
    }
    for kind, pattern in effect_rules.items():
        if re.search(pattern, command, re.I): effects.append(kind)
    if calls: effects.append('network_request')
    unparsed_network = bool(not calls and re.search(r'https?://|requests\.(?:get|post|put|delete)|urllib\.',command,re.I))
    extra = {key:executor.get(key) for key in ('requirements','dependencies','prerequisites','input_arguments','additional_info','build_target') if executor.get(key)}
    return {'host_assignments':hosts, 'literal_url_assignments':literals, 'unparsed_network':unparsed_network, 'resource_filters':resource_filters, 'extra_metadata':extra, 'command_sha256': sha(command.encode()), 'calls': calls, 'overrides': overrides,
            'inventory': inventory, 'effects': effects, 'requirements': record['ability'].get('requirements', []),
            'payloads': executor.get('payloads', []), 'cleanup': executor.get('cleanup', [])}


def same_application(subject, base):
    u, b = urlsplit(subject), urlsplit(base)
    try: equal = (u.scheme, u.hostname, u.port or (443 if u.scheme == 'https' else 80)) == (b.scheme, b.hostname, b.port or (443 if b.scheme == 'https' else 80))
    except ValueError: return False
    return equal and (u.path.rstrip('/') == b.path.rstrip('/') or u.path.startswith(b.path.rstrip('/')+'/'))


def url_bindings(template, base, ip):
    """Project URL placeholders only for compatibility checks, never rewrite catalog commands."""
    u = urlsplit(base)
    result = template
    for name in re.findall(r'#\{([\w.]+)\}', template):
        semantic = PARAMETERS.get(name.lower())
        value = {'ip':ip, 'scheme':u.scheme, 'port':str(u.port or (443 if u.scheme=='https' else 80)),
                 'base_url':base.rstrip('/') if '#{'+name+'}/' in template else base}.get(semantic)
        if value is not None: result = result.replace('#{'+name+'}', value)
    return result


def choose_application(facts, request, analysis, call):
    locations = [f for f in facts if f['predicate'] == 'application_location' and f['status'] == 'observed']
    if not locations:
        # Plain HTTP surveys establish transport facts, never an application's base path or form contract.
        locations = [dict(f, _transport_only=True, value=dict(f['value'],base_url=f['value']['origin']+'/'))
                     for f in facts if f['predicate']=='web_origin' and f['status']=='observed']
    groups = {}
    for f in locations: groups.setdefault(f['value']['base_url'], []).append(f)
    url = call.get('url_template') or ''
    override = next((o for o in analysis['overrides'] if url.startswith(o['var']+'/')), None)
    literal = next((o for o in analysis['literal_url_assignments'] if url.startswith(o['var']+'/')),None)
    if literal: url=literal['url']+url[len(literal['var']):]
    if override:
        desired = urlsplit(override['url']).path.rstrip('/')
        matching = [base for base in groups if urlsplit(base).path.rstrip('/') == desired]
    elif url.startswith(('http://', 'https://')):
        u = urlsplit(url)
        matching = [base for base in groups if same_application(url, base)]
        # Dynamic host still retains exact scheme/port/path constraints.
        if not matching and ((u.hostname or '').startswith('$') or '#{' in url):
            matching = [base for base in groups if urlsplit(base).scheme == u.scheme and urlsplit(base).path.rstrip('/') in u.path]
    else: matching = list(groups)
    if not matching and len(groups) == 1: matching = list(groups)
    if len(matching) > 1:
        text = request.get('text', '').casefold()
        identity = [f for f in facts if f['predicate'] == 'application_identity']
        named = [base for base in matching if base.casefold() in text or any(f['value'].get('base_url') == base and str(f['value'].get('name', '')).casefold() in text for f in identity)]
        if len(named) == 1: matching = named
    if len(matching) == 1:
        # Repeated observations of the same URL are retained as evidence, never choose a different app's session.
        return groups[matching[0]], override, None
    return [], override, 'Multiple observed application locations; select an application explicitly' if matching else 'Application location has not been observed'


def evaluate_requirements(record, executor, envelope, request):
    c = envelope['survey_context']; policy = envelope['policy']; reg = registry(envelope)
    facts = reg['observations']; ids = {f['id']: f for f in facts}; analysis = source_analysis(record, executor)
    receiver_urls = receiver_urls_in(executor.get('command'))
    receiver_calls = [call for call in analysis['calls'] if call['url_template'] in receiver_urls]
    web_calls = [call for call in analysis['calls'] if call['url_template'] not in receiver_urls]
    requirements, blockers, reasons, support = [], [], [], set()
    bindings, environment, applications, module_bindings = {}, {}, {}, {}
    conflicts = {i for item in c['conflicts'] for i in item['observation_ids']}
    def requirement(kind, subject, expected, candidates=(), state=None, detail=None):
        candidates = sorted(set(candidates)); support.update(candidates)
        values = [ids[i] for i in candidates]
        status = state or ('observed' if values and all(f['status'] == 'observed' for f in values) else
                           'configured' if values and all(f['status'] in ('configured', 'observed') for f in values) else 'unknown')
        if conflicts.intersection(candidates): status = 'conflicting'
        if kind not in RULES: kind, status = 'unsupported', 'unsupported'
        row = {'id': 'req-'+sha(canonical([record['canonical_id'], executor['platform'], executor['name'], kind, subject, expected]))[:20],
               'kind': kind, 'subject': subject, 'expected': expected, 'status': status,
               'fact_ids': candidates, 'detail': detail, 'source': {'ability_id': record['canonical_id'], 'revision': record['provenance'].get('revision'), 'command_sha256': analysis['command_sha256']}}
        requirements.append(row)
        if status in ('unknown', 'unsupported', 'ambiguous', 'conflicting'):
            blockers.append(detail or 'Resolve '+kind+' for '+subject+' ('+status+')')
        return row
    def find(predicate): return [f for f in facts if f['predicate'] == predicate]
    osfacts = find('os_name'); os_names = ' '.join(str(f['value']).lower() for f in osfacts if f['status'] == 'observed')
    osplatform = next((p for p, patterns in [('windows', ('windows',)), ('linux', ('linux',)), ('darwin', ('darwin', 'mac'))] if any(v in os_names for v in patterns)), None)
    requirement('target.os', c['target_id'], executor['platform'], [f['id'] for f in osfacts])
    if osplatform and executor['platform'] != osplatform: reasons.append('executor_platform_mismatch')
    architecture = executor.get('architecture') or record['ability'].get('architecture')
    if architecture:
        archfacts = find('architecture'); requirement('target.architecture', c['target_id'], architecture, [f['id'] for f in archfacts])
        def normalize(x):
            value = re.sub(r'[^a-z0-9]', '', str(x).lower())
            return {'amd64':'64bit','x8664':'64bit','x64':'64bit','x86':'32bit','i386':'32bit','i686':'32bit'}.get(value,value)
        known_arch = [f for f in archfacts if f['status']=='observed' and f['value'] is not None and f['id'] not in conflicts]
        if known_arch and all(normalize(f['value']) != normalize(architecture) for f in known_arch): reasons.append('executor_architecture_mismatch')
    runners = [f for f in find('executors') if f['domain'] == 'runner']
    requirement('runner.executor', 'configured-survey-runner', executor['name'], [f['id'] for f in runners],
                detail='Confirm runner executor; configured metadata does not prove execution availability' if not runners else None)
    if runners and not any(executor['name'] in (f['value'] or []) for f in runners): blockers.append('Selected executor is not in configured CALDERA runner metadata')
    blockers.append('Revalidate runner identity, executor availability and privilege before execution')
    privilege = record['ability'].get('privilege')
    elevated = str(privilege or '').lower() in ('admin', 'administrator', 'elevated', 'root', 'system')
    elevatedfacts = find('is_elevated')
    privilegefacts = elevatedfacts if elevated else find('privilege') if privilege else []
    requirement('runner.privilege', 'survey-runner', privilege, [f['id'] for f in privilegefacts],
                detail='Required privilege is unspecified in catalog; manual review' if not privilege else 'Verify runner privilege '+str(privilege))
    if elevated and any(f['status'] == 'observed' and f['value'] is False and f['id'] not in conflicts for f in elevatedfacts): reasons.append('required_privilege_not_observed')
    for inventory in analysis['inventory']:
        baseline = [f for f in find('inventory') if f['value'].get('kind') == inventory]
        requirement('endpoint.'+('process_inventory' if inventory == 'processes' else 'service_inventory'), c['target_id'], 'returned inventory baseline', [f['id'] for f in baseline],
                    detail='Survey inventory missing or only partially covered; do not infer resource absence' if not baseline else None)
    for resource in analysis['resource_filters']:
        matching = [f for f in find(resource['kind']) if str(f['value'].get('name', '')).casefold() == resource['name'].casefold()]
        requirement('endpoint.'+('process_inventory' if resource['kind']=='process' else 'service_inventory'), resource['name'],
                    'Named resource observation; missing record does not prove absence', [f['id'] for f in matching],
                    detail='Named resource '+resource['name']+' was not surveyed' if not matching else None)
    scope = 'web' if web_calls else 'endpoint'
    if analysis['unparsed_network'] and 'remote_dependency' not in analysis['effects']:
        scope = None
        requirement('unsupported','source.network_construct','Network construct needs a dedicated normalizer',state='unsupported',
                    detail='Unsupported network source construct; target/surface semantics require manual review')
    if scope is not None and scope not in policy['planning_scope']: reasons.append(scope+'_command_outside_planning_scope')
    if scope == 'endpoint':
        literal_paths = sorted(set(re.findall(r'''[A-Za-z]:\\[^\s"']+''', executor.get('command') or '')))
        for path in literal_paths:
            matched = [f for f in find('process') if f['value'].get('executable_path') and normal_path(f['value']['executable_path']) == normal_path(path)]
            requirement('endpoint.path', path, 'Observed resource path; filesystem existence/access must be checked separately', [f['id'] for f in matched],
                        detail='Required path was not surveyed: '+path if not matched else None)
            blockers.append('Verify filesystem existence/access and cleanup scope for source path '+path)
    app_contexts = []
    for index, call in enumerate(analysis['calls']):
        if call['url_template'] in receiver_urls:
            requirement('demo_receiver', call['url_template'],
                        {'method': call['method'], 'parameter_names': call['parameter_names']}, state='unknown',
                        detail='Verify demo receiver availability, bounds and receipt capture at execution time')
            continue
        effective=call['url_template'] or ''
        declared=next((o for o in analysis['literal_url_assignments'] if effective.startswith(o['var']+'/')),None)
        if declared: effective=declared['url']+effective[len(declared['var']):]
        unresolved_host=False
        if effective.startswith(('http://','https://')):
            host=urlsplit(effective).hostname or ''
            if host.startswith('$'):
                binding=next((o for o in analysis['host_assignments'] if o['var']==host),None)
                if binding: effective=effective.replace(host,binding.get('ip',c['target_ip']),1)
                else: unresolved_host=True;blockers.append('Source URL host variable has no recognized IP binding: '+host)
            known_host=urlsplit(effective).hostname or ''
            if known_host and not known_host.startswith('$') and known_host!=c['target_ip']: reasons.append('unapproved_external_or_fixed_host')
        appfacts, override, issue = choose_application(facts, request, analysis, call)
        app = appfacts[0] if appfacts else None; base = app['value']['base_url'] if app else None
        key = override['env'] if override else str(index)
        transport_only = bool(app and app.get('_transport_only'))
        applications[key] = {'base_url': None if transport_only else base, 'origin':urlsplit(base).scheme+'://'+urlsplit(base).netloc if base else None,
                             'location_fact_ids': [f['id'] for f in appfacts]}
        requirement('web.application', base or 'unresolved-application:'+key, {'source_url_template': call['url_template']}, [f['id'] for f in appfacts],
                    state='ambiguous' if issue and 'Multiple' in issue else 'unknown' if transport_only else None,
                    detail=issue or ('Only transport origin observed; application base path/identity not established' if transport_only else None))
        if issue: blockers.append(issue)
        if not app:
            requirement('web.request', 'unresolved-request:'+key, call, state='unknown', detail='Resolve application association before checking endpoint, method, parameters or authentication')
            continue
        app_contexts.append((app, call))
        template = call['url_template'] or ''
        literal = next((o for o in analysis['literal_url_assignments'] if template.startswith(o['var']+'/')),None)
        if literal: template=literal['url']+template[len(literal['var']):]
        unresolved_variable = bool(template.startswith('$') and not override and not literal)
        if unresolved_variable:
            requirement('web.application',call['url_template'].split('/',1)[0],'Resolve source URL variable before assuming application binding',
                        state='unknown',detail='Source URL variable has no recognized literal/environment binding: '+call['url_template'].split('/',1)[0])
        projected = url_bindings(effective if effective.startswith(('http://','https://')) else template, base, c['target_ip'])
        if override:
            suffix = template[len(override['var']):]
            endpoint = base.rstrip('/')+suffix
            if not transport_only:
                environment[override['env']] = {'value': base.rstrip('/'), 'type': 'url', 'source': app['id'], 'fact_ids': [app['id']],
                    'transform': 'remove_trailing_slash_for_source_suffix', 'status': 'proposed_setup'}
                blockers.append('Configure and verify runner environment '+override['env']+' using proposed binding; source fallback must not be used')
            else: blockers.append('Resolve application base path before binding environment '+override['env'])
        elif projected.startswith(('http://', 'https://')):
            endpoint = projected
            u = urlsplit(projected)
            if (u.hostname or '').startswith('$'):
                endpoint = re.sub(r'\$\{?\w+\}?', c['target_ip'], projected, count=1)
            u, b = urlsplit(endpoint), urlsplit(base)
            try:
                if u.hostname != c['target_ip']: reasons.append('unapproved_external_or_fixed_host')
                elif (u.scheme, u.hostname, u.port or (443 if u.scheme == 'https' else 80)) != (b.scheme, b.hostname, b.port or (443 if b.scheme == 'https' else 80)):
                    if transport_only: blockers.append('Source origin was not observed; confirm scheme/port without inferring its absence')
                    else: reasons.append('hardcoded_origin_or_port_mismatch')
            except ValueError: blockers.append('Unresolved dynamic URL port; verify source binding')
        else:
            match = re.match(r'(?:\$\{?\w+\}?|#\{[\w.]+\})(.*)', template)
            endpoint = base.rstrip('/')+(match.group(1) if match else '')
            if not template: blockers.append('Unsupported dynamic request URL expression')
        for name in re.findall(r'#\{([\w.]+)\}', endpoint):
            if PARAMETERS.get(name.lower()) != 'module_path': continue
            possible = [f for f in find('module_access_and_forms') if same_application(f['subject'], base)
                        and any(form.get('method','').upper()==call['method'] and set(call['parameter_names']).issubset({i.get('name') for i in form.get('inputs',[])}) for form in f['value'].get('forms',[]))]
            mentioned = [f for f in possible if f['value']['path'].strip('/').casefold() in request.get('text','').casefold()]
            if mentioned: possible = mentioned
            choices = {f['value']['path'] for f in possible}
            if len(choices)==1:
                value = next(iter(choices))
                endpoint = endpoint.replace('#{'+name+'}', value)
                module_bindings.setdefault(name, []).extend((value, f['id']) for f in possible)
        target = urlsplit(endpoint)
        candidates = [f for f in find('module_access_and_forms') if same_application(f['subject'], base) and urlsplit(f['subject']).path == target.path]
        access = [f for f in find('http_access') if (f['value'].get('url') or f['value'].get('requested_url','')).split('?')[0] == endpoint.split('?')[0]]
        requirement('web.request', endpoint.split('?')[0], {'method': call['method'], 'parameter_names': call['parameter_names'], 'application': base},
                    [f['id'] for f in candidates or access], state='unknown' if unresolved_host or unresolved_variable or not candidates or call['method'] is None or not call.get('parameter_contract_complete', True) else None,
                    detail='Required module '+target.path+' has no observed form contract' if not candidates else 'Source method/body expression needs manual review' if call['method'] is None or not call.get('parameter_contract_complete', True) else None)
        for f in candidates:
            value = f['value']; forms = value.get('forms', [])
            if (value.get('http_status') or 0) >= 400: reasons.append('module_access_unavailable_in_survey')
            methods = [form for form in forms if form.get('method', '').upper() == call['method']]
            if call['method'] is not None and forms and not methods: reasons.append('observed_form_method_mismatch')
            matching = [form for form in methods if set(call['parameter_names']).issubset({i.get('name') for i in form.get('inputs', [])})]
            if methods and not matching: reasons.append('observed_form_parameter_mismatch')
            if not forms: blockers.append('Module has no observed forms; review request method/parameters')
            if matching and all(urlsplit(urljoin(f['subject'], form.get('action_path') or '')).path != target.path for form in matching): blockers.append('Observed form action differs from source endpoint; verify routing before execution')
            if any(form.get('csrf_present') is True for form in matching):
                requirement('web.csrf', f['subject'], 'Fresh execution-session token reference; never reuse Survey token', [f['id']], state='unknown', detail='Obtain fresh CSRF token through approved execution session; Survey stores names/presence only')
            if value.get('forms_truncated'): blockers.append('Observed form metadata is truncated; verify the full request contract')
        sessions = [f for f in find('survey_session') if f['subject'].rstrip('/') == base.rstrip('/')]
        requirement('web.authentication', base, 'Survey session observation only; execution session requires revalidation', [f['id'] for f in sessions],
                    detail='Authentication for this application was not checked' if not sessions else None)
        if sessions or call['session_reference_required']: blockers.append('Survey session is historical; obtain and verify execution session reference separately')
        if call['session_reference_required']: blockers.append('Resolve and validate execution cookie/session file reference; no Survey secret is transferred')
        level = re.search(r'security=(low|medium|high|impossible)', executor.get('command') or '', re.I)
        if level:
            if not sessions or any(f['value'].get('current_security_level') is None for f in sessions): blockers.append('Verify application security level required by source: '+level.group(1).lower())
            if any(f['value'].get('current_security_level') not in (None, level.group(1).lower()) for f in sessions): reasons.append('observed_security_level_mismatch')
    # Parameter resolver registry: ambiguity never selects the first application/resource.
    unique_apps = {a['value']['base_url']: a for a, _ in app_contexts}
    if not unique_apps and any(PARAMETERS.get(p.lower()) in ('base_url', 'scheme', 'port', 'module_path') for p in executor.get('fact_placeholders', [])):
        matching, _, issue = choose_application(facts, request, analysis, {'url_template': None})
        if matching: unique_apps[matching[0]['value']['base_url']] = matching[0]
    for name in executor.get('fact_placeholders', []):
        semantic = PARAMETERS.get(name.lower()); value = None; candidates = []; source = None; kind = semantic or 'unknown'
        transform = None
        if semantic == 'ip': value, source, kind = c['target_ip'], 'survey_context.target_ip', 'ip_address'
        elif semantic == 'listener_port':
            listeners = [f for f in find('listener') if isinstance(f['value'],dict) and f['value'].get('listener',{}).get('LocalPort') is not None]
            ports = set(re.findall(r'(?:port|cổng|:)\s*(\d{1,5})\b', request.get('text',''), re.I))
            if ports: listeners = [f for f in listeners if str(f['value']['listener']['LocalPort']) in ports]
            choices = {str(f['value']['listener']['LocalPort']) for f in listeners}
            if len(choices)==1:
                value=next(iter(choices));candidates=[f['id'] for f in listeners];source=candidates[0];kind='port'
            requirement('endpoint.listener', name, {'parameter':name,'target_ip':c['target_ip']}, candidates,
                        state='ambiguous' if len(choices)>1 else None, detail='Select an observed target listener port' if value is None else None)
        elif semantic in ('base_url', 'scheme', 'port') and len(unique_apps) == 1 and not (semantic=='base_url' and next(iter(unique_apps.values())).get('_transport_only')):
            app = next(iter(unique_apps.values())); u = urlsplit(app['value']['base_url'])
            value = {'base_url': app['value']['base_url'], 'scheme': u.scheme, 'port': str(u.port or (443 if u.scheme == 'https' else 80))}[semantic]
            if semantic=='base_url' and '#{'+name+'}/' in (executor.get('command') or ''):
                value=value.rstrip('/');transform='remove_trailing_slash_for_source_suffix'
            candidates, source = [app['id']], app['id']; support.add(app['id'])
            kind = 'url' if semantic == 'base_url' else semantic
        elif semantic == 'module_path' and name in module_bindings and len({v for v, _ in module_bindings[name]})==1:
            value=module_bindings[name][0][0];candidates=sorted({i for _,i in module_bindings[name]});source=candidates[0];kind='relative_module_path'
        elif semantic in ('path', 'process_name', 'process_id', 'service_name'):
            resources = [f for f in facts if f['predicate'] == ('service' if semantic == 'service_name' else 'process')]
            field = {'path': 'executable_path', 'process_name': 'name', 'process_id': 'pid', 'service_name': 'name'}[semantic]
            text = request.get('text', '')+' '+(executor.get('command') or '')
            named = [f for f in resources if str(f['value'].get('name', '')).casefold() in text.casefold()]
            if named: resources = named
            choices = {str(f['value'][field]): [] for f in resources if f['value'].get(field) is not None}
            for f in resources:
                if f['value'].get(field) is not None: choices[str(f['value'][field])].append(f['id'])
            if len(choices) == 1: value = next(iter(choices)); candidates = choices[value]; source = candidates[0]
            requirement('endpoint.path' if semantic == 'path' else ('endpoint.service_inventory' if semantic == 'service_name' else 'endpoint.process_inventory'), name,
                        {'parameter': name, 'type': semantic}, candidates,
                        state='ambiguous' if len(choices) > 1 else None, detail='Resolve required parameter '+name+' using a unique observed resource' if value is None else None)
            if semantic == 'path' and value is not None: blockers.append('Revalidate file existence/access for observed process path '+value+'; process metadata is not a filesystem permission check')
        else:
            requirement('unsupported' if semantic is None else 'web.request', name, {'parameter': name, 'semantic': semantic}, state='unsupported' if semantic is None else 'unknown',
                        detail='Resolve required parameter '+name+'; unsupported or ambiguous semantic binding')
        if value is None: blockers.append('Resolve required parameter '+name+' from appropriate target evidence')
        support.update(candidates)
        bindings[name] = {'value': value, 'type': kind, 'source': source, 'fact_ids': candidates}
        if transform: bindings[name]['transform']=transform
    for key, value in analysis['extra_metadata'].items():
        requirement('catalog.dependency', 'executor.'+key, value, state='unsupported', detail='Executor metadata '+key+' has no typed resolver; manual review')
    for item in analysis['requirements']:
        requirement('catalog.dependency', c['target_id'], item, state='unsupported', detail='Unsupported catalog dependency predicate; manual review '+json.dumps(item, ensure_ascii=False)[:300])
    for payload in analysis['payloads']:
        requirement('catalog.dependency', str(payload), {'payload': payload}, state='unknown', detail='Verify payload/dependency availability on selected runner: '+str(payload))
    if 'remote_dependency' in analysis['effects'] and not analysis['calls']:
        requirement('catalog.dependency', 'external-source', {'network_dependency': True}, state='unknown', detail='External dependency URL requires scope/integrity review; not evidence of a web target surface')
    requirement('catalog.cleanup', c['target_id'], {'effects': analysis['effects'], 'cleanup': analysis['cleanup']}, state='unknown',
                detail='Manual review source effects, baseline, health checks and cleanup/rollback; absence of cleanup commands is not proof none is needed')
    telemetry_kinds = ['web'] if web_calls else ['process']
    if analysis['calls'] or 'remote_dependency' in analysis['effects'] or analysis['unparsed_network'] or re.search(r'\bnmap\b|\bping\b|Test-NetConnection',executor.get('command') or '',re.I):
        telemetry_kinds.append('network')
    for telemetry in telemetry_kinds:
        subjects = sorted(unique_apps) if telemetry=='web' and unique_apps else [c['target_id']]
        for subject in subjects:
            telemetryfacts = []
            for f in facts:
                if f['predicate'] not in ('local_event', 'manager_ingestion'): continue
                values = f['value'] if isinstance(f['value'], list) else [f['value']]
                event_id = 1 if telemetry=='process' else 3
                if telemetry in ('process','network') and any(v.get('kind')=='sysmon_event_'+str(event_id) or v.get('event_id') in (event_id,str(event_id)) and 'sysmon' in str(v.get('channel','')).lower() for v in values): telemetryfacts.append(f['id'])
                if telemetry=='web' and subject in unique_apps:
                    if unique_apps[subject].get('_transport_only'):
                        endpoints={r['subject'] for r in requirements if r['kind']=='web.request' and r['expected'].get('application')==subject}
                        attributed=any((v.get('url') or '').split('?')[0] in endpoints for v in values)
                    else:
                        attributed=any(v.get('application')==subject or same_application(v.get('url') or '',subject) for v in values)
                    if attributed: telemetryfacts.append(f['id'])
            requirement('telemetry.'+telemetry, subject, 'Historical source availability; manager ingestion and detection are separate', telemetryfacts,
                        detail='No application-attributed web telemetry observation; shared/unattributed logs do not prove this application coverage' if telemetry == 'web' and not telemetryfacts else None)
    # Secondary, extensible effect tags protect against known compound behaviors; primary compatibility uses typed requirements above.
    effect_tags = {'xss': r'<script|onerror\s*=|javascript:|\$xss', 'fuzz': r'fuzz|for\s*\('}
    requested_text = request.get('text', '')+' '+(request.get('objective') or '')
    explicit_focus = bool(re.search(r'injection|sqli|xss|csrf|upload|discovery|process|service', requested_text, re.I))
    if analysis['calls'] and explicit_focus:
        for tag, pattern in effect_tags.items():
            if re.search(pattern, executor.get('command') or '', re.I) and not re.search(tag, requested_text, re.I): reasons.append('extra_behavior_'+tag)
    for identifier in sorted(support):
        if identifier in conflicts: blockers.append('Resolve conflicting Survey evidence for '+identifier)
        if ids[identifier]['observed_at'] is None: blockers.append('Observation time unknown for '+identifier)
    if any(g['reason'] in ('stale', 'truncated', 'tool_error') for g in reg['gaps']): blockers.append('Review Survey stale/truncated/error gaps; unobserved is not absent')
    report = {'ability_id': record['canonical_id'], 'executor': {'platform': executor['platform'], 'name': executor['name']},
        'compatibility': 'incompatible' if reasons else 'needs_information' if blockers else 'compatible',
        'reasons': sorted(set(reasons)), 'blockers': sorted(set(blockers)), 'bindings': bindings, 'environment_bindings': environment,
        'applications': applications, 'supporting_fact_ids': sorted(support), 'survey_checks': [fact_check(ids[i]) for i in sorted(support)],
        'requirements': requirements, 'registry_version': REGISTRY_VERSION, 'source': record['provenance'],
        'source_requirements': analysis, 'manual_review': True}
    schema = json.loads((Path(__file__).resolve().parents[1]/'input/schema/survey_v2/requirement_assessment.schema.json').read_text())
    schema_check(report, schema, schema)
    return report
