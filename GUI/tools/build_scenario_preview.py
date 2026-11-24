"""Build read-only UI fixtures from supplied data; never generates new scenarios."""
import json
from pathlib import Path
import sys

import yaml

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))
from final_template.contracts import normalize_profile, validate_document


def build():
    source = PROJECT / 'generated_adversaries'
    items = []
    for path in sorted((source / 'adversaries').glob('*.yml')):
        raw = path.read_text(encoding='utf-8')
        value = yaml.safe_load(raw)
        validate_document(value, 'scenario_adversary')
        stem = path.stem
        request_name = 'SCENARIO-' + stem[9:-10] if stem.startswith('scenario-') else stem
        request = json.loads((source / 'requests' / ('REQ-' + request_name + '.json')).read_text(encoding='utf-8'))
        family = ('scenario' if stem.startswith('scenario-') else
                  'caldera' if stem.startswith('caldera_stock_') else
                  'dvwa' if stem.startswith('dvwa_') else 'nckh')
        items.append({'id': value['id'], 'name': value['name'].strip(),
                      'description': value['description'], 'family': family,
                      'scope': request['scope'], 'abilities': value['atomic_ordering'],
                      'file': str(path.relative_to(PROJECT)), 'yaml': raw})
    profiles = []
    for name in ['target_profile_04-11.json', 'target_profile_02-11.json', 'target_profile_dvwa.proposed.json']:
        path = source / 'target_profiles' / name
        profiles.append({'name': name, 'file': str(path.relative_to(PROJECT)),
                         'profile': normalize_profile(json.loads(path.read_text(encoding='utf-8')))})
    template = PROJECT / 'final_template/scenario_adversary_template.yaml'
    value = yaml.safe_load(template.read_text(encoding='utf-8'))
    validate_document(value, 'scenario_adversary')
    data = {'mode': 'ui_preview', 'source': 'generated_adversaries', 'items': items,
            'profiles': profiles,
            'profileSchema': json.loads((PROJECT / 'final_template/target_profile_schema.json').read_text(encoding='utf-8')),
            'template': {'name': value['name'], 'yaml': template.read_text(encoding='utf-8'),
                         'file': str(template.relative_to(PROJECT)), 'abilities': value['atomic_ordering']}}
    destination = PROJECT / 'GUI/static/scenario-data.json'
    destination.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('UI snapshot: %d scenarios, %d profiles -> %s' % (len(items), len(profiles), destination))


if __name__ == '__main__':
    build()
