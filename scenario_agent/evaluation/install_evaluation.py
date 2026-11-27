"""Copy evaluation tools/evidence into the deployment; leave agent code unchanged."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

source = Path(__file__).resolve().parent
root = Path(sys.argv[1] if len(sys.argv) > 1 else '/home/soc/build_scenario_agent').resolve()
if not (root / 'data/catalog.sqlite').is_file() or not (root / '.venv/bin/python').exists():
    raise SystemExit('Expected the installed Scenario Agent and its .venv at the destination.')
destination = root / 'evaluation'
names = ['run_verification.py', 'README.md', 'install_evaluation.py', 'install_and_run_live.sh']
for name in names:
    src = source / name
    dst = destination / name
    if dst.exists() and src.resolve() != dst.resolve() and src.read_bytes() != dst.read_bytes():
        raise SystemExit('Evaluation file already exists with different content: ' + str(dst))
destination.mkdir(exist_ok=True)
for name in names:
    if (source / name).resolve() != (destination / name).resolve():
        shutil.copy2(source / name, destination / name)
archive_source = source / 'results_20261112'
archive = root / 'outputs/verification_20261112_offline'
if archive_source.exists() and not archive.exists():
    archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(archive_source, archive)
    # Artifact paths change when evidence is copied; underlying plans, catalog
    # references and original deployment paths remain unchanged.
    for path in archive.rglob('*'):
        if path.is_file() and path.suffix in ('.json', '.md', '.log', '.yml', '.yaml'):
            text = path.read_text(encoding='utf-8')
            replaced = text.replace(str(archive_source), str(archive))
            if replaced != text:
                path.write_text(replaced, encoding='utf-8')
manifest_file = root / 'BUNDLE_MANIFEST.json'
manifest = json.loads(manifest_file.read_text())
assets = {entry['path']: entry for entry in manifest['assets']}
for name in names:
    path = destination / name
    relative = str(path.relative_to(root))
    assets[relative] = {'path': relative, 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
manifest['assets'] = [assets[key] for key in sorted(assets)]
manifest['acceptance_evaluation'] = {'offline_evidence': 'outputs/verification_20261112_offline/results.json',
                                     'agent_code_changed': False,
                                     'full_acceptance_passed': False}
temp = manifest_file.with_suffix('.json.tmp')
temp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
temp.replace(manifest_file)
print('Evaluation tools installed at:', destination)
print('Offline evidence:', archive)
print('No agent code, schema, key, source YAML, catalog or index was changed.')
