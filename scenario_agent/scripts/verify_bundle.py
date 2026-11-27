"""Verify packaged inputs, rebuildability and RAG without Gemini or CALDERA."""
import argparse
import json
import os
from pathlib import Path
import site
import sqlite3
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scenario_agent.config import Config, sha256
from scenario_agent.rag import check_index, retrieve
from scripts.import_caldera_catalog import rebuild, local_path

ROOT=Path(__file__).resolve().parents[1]

def verify(rebuild_catalog=True, hybrid=False):
    import scenario_agent
    if not Path(scenario_agent.__file__).resolve().is_relative_to(ROOT):
        raise ValueError('Agent import points outside this bundle')
    venv=Path(sys.prefix)/'pyvenv.cfg'
    if sys.prefix==sys.base_prefix or site.ENABLE_USER_SITE or not venv.exists() or 'include-system-site-packages = false' not in venv.read_text().lower():
        raise ValueError('Use an isolated venv, without --system-site-packages')
    bundle_manifest=ROOT/'BUNDLE_MANIFEST.json'
    if bundle_manifest.exists():
        for entry in json.loads(bundle_manifest.read_text())['assets']:
            path=local_path(ROOT,entry['path'])
            if 'sha256' in entry and sha256(path)!=entry['sha256']:
                raise ValueError('Packaged asset changed: '+entry['path'])
            if 'symlink' in entry and (not (ROOT/entry['path']).is_symlink() or os.readlink(ROOT/entry['path'])!=entry['symlink']):
                raise ValueError('Packaged symlink changed: '+entry['path'])
    if (ROOT/'.env').exists() and (ROOT/'.env').stat().st_mode & 0o077:
        raise ValueError('.env permissions must be 600')
    manifest=json.loads((ROOT/'data/catalog_manifest.json').read_text())
    scenarios=0
    for entry in manifest['files']:
        path=local_path(ROOT,entry['original_path'])
        if sha256(path)!=entry['sha256']:raise ValueError('Source hash mismatch: '+entry['original_path'])
        scenarios+=entry['source']=='scenarios'
    if scenarios!=113:raise ValueError('Expected 113 scenario sources')
    asset_roots=[ROOT/name for name in ('input','data','scenario_agent','scripts','tests','.cache/huggingface')]
    escaped=[str(p.relative_to(ROOT)) for base in asset_roots for p in base.rglob('*') if p.is_symlink() and (not p.exists() or not p.resolve().is_relative_to(ROOT))]
    if escaped:raise ValueError('Symlinks escape bundle: '+str(escaped[:5]))
    with sqlite3.connect((ROOT/'data/catalog.sqlite').as_uri()+'?mode=ro',uri=True) as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok' or db.execute('PRAGMA foreign_key_check').fetchall():raise ValueError('SQLite integrity failure')
        for path, in db.execute('SELECT original_path FROM source_files'):local_path(ROOT,path)
        summary={name:db.execute('SELECT COUNT(*) FROM '+name).fetchone()[0] for name in ('abilities','adversaries','adversary_retrieval','ability_aliases')}
    rebuilt=False
    if rebuild_catalog:
        with tempfile.TemporaryDirectory(prefix='scenario-bundle-check-') as folder:
            copy=Path(folder)/'catalog.sqlite';rebuild(ROOT,copy)
            if sha256(copy)!=sha256(ROOT/'data/catalog.sqlite'):raise ValueError('Catalog rebuild is not byte-for-byte reproducible')
        rebuilt=True
    config=Config(ROOT)
    index=check_index(config)
    semantic=None
    if hybrid:
        target=json.loads((ROOT/'input/target_profile.json').read_text())
        result=retrieve(config,{'text':'Khảo sát thông tin người dùng Windows','objective':None,'requested_techniques':[],'max_tests':1},target,'hybrid',3)
        if not result['abilities']:raise ValueError('Hybrid retrieval returned no candidates')
        semantic=[{'id':x['record']['canonical_id'],'name':x['record']['ability']['name']} for x in result['abilities']]
    return {'bundle_root':str(ROOT),'isolated_python':True,'agent_import_from_bundle':True,'source_files_verified':len(manifest['files']),'scenario_files':scenarios,'external_symlinks':0,'catalog_rebuilt_identically':rebuilt,'catalog':summary,'index':index,'hybrid_top_candidates':semantic,'live_gemini_verified':False,'caldera_execution_supported':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hybrid',action='store_true')
    args=parser.parse_args()
    print(json.dumps(verify(hybrid=args.hybrid),ensure_ascii=False,indent=2))

if __name__=='__main__':main()
