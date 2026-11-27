import json
import re
import sqlite3
from contextlib import contextmanager
from scripts.resolve_ability import resolve_ability

@contextmanager
def connect(path):
    db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()

def ability(db, reference):
    result = resolve_ability(db, reference)
    source = result['source']
    result['provenance'] = {
        'kind': 'converted_atomic' if 'atomic' in source['source'].lower() else 'caldera_ability',
        'id': result['canonical_id'], 'location': source['original_path'],
        'revision': source['source_sha256']}
    return result

def compatible_executors(record, target):
    os_name = (target.get('os', {}).get('name') or '').lower()
    platform = 'windows' if 'windows' in os_name else 'linux' if 'linux' in os_name else 'darwin' if 'mac' in os_name else None
    if platform is None:
        return []
    if target.get('capabilities', {}).get('admin_ready') is not True and str(record['ability'].get('privilege', '')).lower() in ('elevated', 'admin', 'administrator', 'system', 'root'):
        return []
    capabilities = target.get('capabilities', {})
    if capabilities.get('sandcat_online') is False:
        return []
    flags = {'psh': 'powershell_ready', 'powershell': 'powershell_ready',
             'pwsh': 'pwsh_ready', 'cmd': 'cmd_ready', 'sh': 'shell_ready', 'bash': 'bash_ready'}
    return [ex for ex in record['ability'].get('executors', [])
            if ex.get('platform') == platform and (ex.get('command') or ex.get('code'))
            and capabilities.get(flags.get(ex.get('name'), ''), None) is not False]

def technique_abilities(db, requested, target):
    """Exact SQL technique lookup, then normal provenance and target gates.

    A parent technique accepts its subtechniques; a requested subtechnique
    cannot be satisfied by its parent or by a sibling.
    """
    result = {}
    for value in requested:
        technique = value.upper()
        if not re.fullmatch(r'T[0-9]{4}(?:\.[0-9]{3})?', technique):
            raise ValueError('Invalid requested technique: ' + value)
        matches = {}
        rows = db.execute('SELECT DISTINCT ability_id FROM abilities '
                          'WHERE UPPER(technique_id)=? OR UPPER(technique_id) LIKE ? ORDER BY ability_id',
                          (technique, technique + '.%')).fetchall()
        for row in rows:
            try:
                record = ability(db, row[0])
            except LookupError:
                continue
            actual = str(record['ability'].get('technique_id') or '').upper()
            if (actual == technique or actual.startswith(technique + '.')) and compatible_executors(record, target):
                matches[record['canonical_id']] = record
        result[technique] = matches
    return result

def adversary(db, item_id):
    row = db.execute('SELECT * FROM adversary_retrieval WHERE adversary_id=?', (item_id,)).fetchone()
    if row is None:
        raise LookupError(f'Adversary excluded, missing or incomplete: {item_id}')
    row = dict(row)
    normalized = json.loads(row['normalized_json'])
    steps = [ability(db, ref) for ref in normalized['atomic_ordering']]
    return {'id': item_id, 'name': normalized['name'], 'description': normalized.get('description', ''),
            'ordering': [step['canonical_id'] for step in steps], 'abilities': steps,
            'provenance': {'kind': 'scenario' if row['source'] == 'scenarios' else 'caldera_adversary',
                           'id': item_id, 'location': row['original_path'], 'revision': row['source_sha256']}}

def corpus(path):
    passages, excluded = [], []
    with connect(path) as db:
        for row in db.execute('SELECT DISTINCT ability_id FROM abilities ORDER BY ability_id').fetchall():
            try:
                item = ability(db, row[0])
                a = item['ability']
                text = ' | '.join(str(a.get(key) or '') for key in ('name', 'description', 'tactic', 'technique_id', 'technique_name'))
                passages.append({'key': 'ability:' + item['canonical_id'], 'kind': 'ability', 'id': item['canonical_id'],
                                 'text': text, 'source': item['provenance']})
            except LookupError as e:
                excluded.append({'kind': 'ability', 'id': row[0], 'reason': str(e)})
        for row in db.execute('SELECT adversary_id FROM adversary_retrieval ORDER BY adversary_id').fetchall():
            try:
                a = adversary(db, row[0])
                text = ' | '.join([a['name'], a['description']] + [s['ability'].get('name', '') + ' ' + str(s['ability'].get('technique_id') or '') for s in a['abilities']])
                passages.append({'key': 'adversary:' + a['id'], 'kind': 'adversary', 'id': a['id'],
                                 'text': text, 'source': a['provenance']})
            except LookupError as e:
                excluded.append({'kind': 'adversary', 'id': row[0], 'reason': str(e)})
    return passages, excluded
