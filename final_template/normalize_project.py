"""Explicit, idempotent migration of supplied inputs; preserves target/ability IDs."""
import json
from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from final_template.contracts import ROOT, normalize_profile, validate_document


def write_if_changed(path, text):
    if path.read_text(encoding='utf-8') == text:
        return False
    path.write_text(text, encoding='utf-8')
    return True


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + '\n'


def normalize(project):
    generated = project / 'generated_adversaries'
    changed = []
    removed = 0
    for path in sorted((generated / 'target_profiles').glob('*.json')):
        value = normalize_profile(json.loads(path.read_text(encoding='utf-8')))
        if write_if_changed(path, json_text(value)):
            changed.append(str(path.relative_to(project)))
    for path in sorted((project / 'target_profile').glob('*.json')):
        preferred = generated / 'target_profiles' / path.name
        source = preferred if preferred.exists() else path
        value = normalize_profile(json.loads(source.read_text(encoding='utf-8')))
        if write_if_changed(path, json_text(value)):
            changed.append(str(path.relative_to(project)))
    for path in sorted((generated / 'adversaries').glob('*.yml')):
        value = yaml.safe_load(path.read_text(encoding='utf-8'))
        original = value['atomic_ordering']
        value['atomic_ordering'] = list(dict.fromkeys(original))
        removed += len(original) - len(value['atomic_ordering'])
        validate_document(value, 'scenario_adversary')
        if value['atomic_ordering'] != original:
            path.write_text(yaml.safe_dump(value, allow_unicode=True, sort_keys=False), encoding='utf-8')
            changed.append(str(path.relative_to(project)))
        stem = path.stem
        request_name = ('SCENARIO-' + stem[9:-10]) if stem.startswith('scenario-') else stem
        request_path = generated / 'requests' / ('REQ-' + request_name + '.json')
        if request_path.exists():
            request = json.loads(request_path.read_text(encoding='utf-8'))
            if request['max_steps'] != len(value['atomic_ordering']):
                request['max_steps'] = len(value['atomic_ordering'])
                validate_document(request, 'user_request')
                request_path.write_text(json_text(request), encoding='utf-8')
                changed.append(str(request_path.relative_to(project)))
    return {'changed_files': changed, 'removed_duplicate_steps': removed,
            'preferred_profiles': 'generated_adversaries/target_profiles',
            'target_id_linking': 'deferred', 'ability_resolution': 'dataset_pending'}


if __name__ == '__main__':
    print(json.dumps(normalize(ROOT.parent), ensure_ascii=False, indent=2))
