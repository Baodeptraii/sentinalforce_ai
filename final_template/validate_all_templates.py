"""Offline structure checks; never contacts CALDERA or executes abilities."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from final_template.contracts import ROOT, validate_document


def load(path):
    if path.suffix == '.json':
        return json.loads(path.read_text(encoding='utf-8'))
    import yaml
    return yaml.safe_load(path.read_text(encoding='utf-8'))


def run_validation(include_project=False):
    files = [(ROOT / 'target_profile_template.json', 'target_profile'),
             (ROOT / 'user_request_template.json', 'user_request'),
             (ROOT / 'scenario_adversary_template.yaml', 'scenario_adversary'),
             (ROOT / 'scenario_web_dvwa_template.yaml', 'scenario_adversary')]
    if include_project:
        project = ROOT.parent
        files += [(p, 'target_profile') for p in sorted((project / 'generated_adversaries/target_profiles').glob('*.json'))]
        files += [(p, 'target_profile') for p in sorted((project / 'target_profile').glob('*.json'))]
        files += [(p, 'user_request') for p in sorted((project / 'generated_adversaries/requests').glob('*.json'))]
        files += [(p, 'scenario_adversary') for p in sorted((project / 'generated_adversaries/adversaries').glob('*.yml'))]
    errors = []
    for path, kind in files:
        try:
            validate_document(load(path), kind)
        except (ValueError, OSError) as exc:
            errors.append('%s: %s' % (path, exc))
    if errors:
        raise ValueError('\n'.join(errors))
    if include_project:
        for path in sorted((ROOT.parent / 'generated_adversaries/requests').glob('*.json')):
            request = load(path)
            stem = path.stem[4:]
            if stem.startswith('SCENARIO-'):
                stem = 'scenario-' + stem[9:] + '_adversary'
            adversary = load(ROOT.parent / 'generated_adversaries/adversaries' / (stem + '.yml'))
            if len(adversary['atomic_ordering']) > request['max_steps']:
                raise ValueError('%s exceeds max_steps' % stem)
    print('[OK] %d documents pass structure checks.' % len(files))
    print('Target ID linking is deferred. Ability availability and lab execution are not verified.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', action='store_true', help='Also check supplied project data')
    args = parser.parse_args()
    try:
        run_validation(args.project)
    except (ValueError, OSError, ImportError) as exc:
        parser.exit(1, str(exc) + '\n')
