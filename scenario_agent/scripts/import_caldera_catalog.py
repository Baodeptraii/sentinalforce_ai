#!/usr/bin/env python3
"""Import CALDERA YAML and single-source project scenarios into a plan-only catalog.

Requires PyYAML and jsonschema. Uses Python's built-in sqlite3; never executes CALDERA.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile

import yaml
from jsonschema import Draft202012Validator

try:
    from .resolve_ability import resolve_ability
except ImportError:
    from resolve_ability import resolve_ability


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def as_list(value):
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def normalize_executors(record):
    if "platforms" in record:
        entries = []
        for platforms, executors in (record["platforms"] or {}).items():
            for names, details in executors.items():
                for platform in platforms.split(","):
                    for name in names.split(","):
                        entries.append({**details, "platform": platform.strip(), "name": name.strip()})
    else:
        entries = record.get("executors") or []
    result = []
    for entry in entries:
        item = dict(entry)
        item["platform"] = (item.get("platform") or "unknown").lower()
        item["name"] = item.get("name") or "unknown"
        item["cleanup"] = as_list(item.get("cleanup"))
        item["payloads"] = as_list(item.get("payloads"))
        item["uploads"] = as_list(item.get("uploads"))
        item.setdefault("timeout", 60)
        # These are CALDERA placeholders, not an inferred Atomic input schema.
        text = encode({key: item.get(key) for key in ("command", "cleanup", "variations")})
        item["fact_placeholders"] = sorted(set(re.findall(r"#\{([^{}]+)\}", text)))
        result.append(item)
    return result


def normalize_ability(record):
    technique = record.get("technique") or {}
    return {
        "id": str(record.get("id") or record.get("ability_id") or ""),
        "name": record.get("name"), "description": record.get("description"),
        "tactic": record.get("tactic"),
        "technique_id": technique.get("attack_id", record.get("technique_id")),
        "technique_name": technique.get("name", record.get("technique_name")),
        "privilege": record.get("privilege"),
        "requirements": record.get("requirements") or [],
        "repeatable": record.get("repeatable", False),
        "singleton": record.get("singleton", False),
        "executors": normalize_executors(record),
    }


def normalize_adversary(record):
    if "phases" in record and "atomic_ordering" in record:
        raise ValueError("phases and atomic_ordering cannot coexist")
    ordering = record.get("atomic_ordering")
    if ordering is None:
        ordering = [item for phase in (record.get("phases") or {}).values() for item in phase]
    if not isinstance(ordering, list) or not all(isinstance(item, str) and item for item in ordering):
        raise ValueError("atomic_ordering must be a list of nonempty ability IDs")
    if record.get("id") and record.get("adversary_id") and record["id"] != record["adversary_id"]:
        raise ValueError("id and adversary_id disagree")
    return {
        "id": str(record.get("id") or record.get("adversary_id") or ""),
        "name": record.get("name"), "description": record.get("description"),
        "atomic_ordering": ordering, "objective": record.get("objective"),
        "tags": record.get("tags") or [],
    }


def adversary_equivalence_hash(normalized):
    """Treat omitted objective like CALDERA's default without changing the source."""
    value = dict(normalized)
    value["objective"] = value["objective"] or "495a9828-cab1-44dd-a0ca-66e58177d8cc"
    return hashlib.sha256(encode(value).encode()).hexdigest()


def classify_reference(connection, identifier, placeholders, registry):
    if identifier in placeholders:
        return "placeholder_only", None, 0
    if registry.get(identifier, {}).get("status") == "manual_required":
        return "manual_required", None, 0
    try:
        resolved = resolve_ability(connection, identifier)
        return ("alias_resolved" if resolved["resolved_via_alias"] else "resolved"), resolved["canonical_id"], 1
    except LookupError as error:
        message = str(error)
        status = ("ability_structure_issue" if "no executable" in message else
                  "conflict" if "Conflicting" in message else
                  "stale_alias" if "stale" in message else "missing")
        return status, None, 0


DDL = """
PRAGMA foreign_keys=ON;
CREATE TABLE import_info (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE source_files (
 file_id INTEGER PRIMARY KEY, source TEXT NOT NULL, kind TEXT NOT NULL,
 original_path TEXT NOT NULL UNIQUE, snapshot_path TEXT,
 storage_mode TEXT NOT NULL CHECK(storage_mode IN ('direct', 'snapshot')),
 sha256 TEXT NOT NULL, git_revision TEXT, byte_size INTEGER NOT NULL);
CREATE TABLE abilities (
 record_id INTEGER PRIMARY KEY, ability_id TEXT NOT NULL,
 file_id INTEGER NOT NULL REFERENCES source_files, entry_index INTEGER NOT NULL,
 source_kind TEXT NOT NULL, name TEXT, description TEXT, tactic TEXT,
 technique_id TEXT, technique_name TEXT, privilege TEXT,
 requirements_json TEXT NOT NULL, normalized_json TEXT NOT NULL,
 normalized_sha256 TEXT NOT NULL, original_json TEXT NOT NULL,
 review_status TEXT NOT NULL DEFAULT 'not_reviewed',
 UNIQUE(file_id, entry_index));
CREATE TABLE executors (
 executor_id INTEGER PRIMARY KEY, ability_record_id INTEGER NOT NULL REFERENCES abilities,
 platform TEXT NOT NULL, name TEXT NOT NULL, command TEXT, cleanup_json TEXT NOT NULL,
 timeout INTEGER, payloads_json TEXT NOT NULL, placeholders_json TEXT NOT NULL,
 details_json TEXT NOT NULL);
CREATE TABLE adversaries (
 record_id INTEGER PRIMARY KEY, adversary_id TEXT NOT NULL UNIQUE,
 file_id INTEGER NOT NULL REFERENCES source_files, entry_index INTEGER NOT NULL,
 name TEXT, description TEXT, objective TEXT, normalized_json TEXT NOT NULL,
 normalized_sha256 TEXT NOT NULL, original_json TEXT NOT NULL,
 review_status TEXT NOT NULL DEFAULT 'not_reviewed',
 reference_status TEXT NOT NULL DEFAULT 'unchecked', UNIQUE(file_id, entry_index));
CREATE TABLE adversary_variants (
 variant_id INTEGER PRIMARY KEY, adversary_record_id INTEGER NOT NULL REFERENCES adversaries,
 file_id INTEGER NOT NULL REFERENCES source_files, entry_index INTEGER NOT NULL,
 normalized_json TEXT NOT NULL, normalized_sha256 TEXT NOT NULL,
 equivalence_sha256 TEXT NOT NULL, original_json TEXT NOT NULL,
 reference_status TEXT NOT NULL DEFAULT 'unchecked', UNIQUE(file_id, entry_index));
CREATE TABLE adversary_steps (
 adversary_record_id INTEGER NOT NULL REFERENCES adversaries,
 step_index INTEGER NOT NULL, ability_id TEXT NOT NULL,
 resolution_status TEXT NOT NULL, matching_records INTEGER NOT NULL,
 resolved_ability_id TEXT,
 PRIMARY KEY(adversary_record_id, step_index));
CREATE TABLE adversary_variant_steps (
 variant_id INTEGER NOT NULL REFERENCES adversary_variants,
 step_index INTEGER NOT NULL, ability_id TEXT NOT NULL,
 resolution_status TEXT NOT NULL, matching_records INTEGER NOT NULL,
 resolved_ability_id TEXT, PRIMARY KEY(variant_id, step_index));
CREATE TABLE ability_aliases (
 alias_id TEXT PRIMARY KEY, canonical_id TEXT NOT NULL,
 target_source_sha256 TEXT NOT NULL, reason TEXT NOT NULL, evidence_json TEXT NOT NULL);
CREATE INDEX ability_lookup ON abilities(ability_id);
CREATE INDEX ability_technique ON abilities(technique_id);
CREATE INDEX executor_filter ON executors(platform, name);
CREATE INDEX adversary_lookup ON adversaries(adversary_id);
CREATE INDEX adversary_variant_lookup ON adversary_variants(adversary_record_id);
CREATE INDEX step_ability ON adversary_steps(ability_id);
CREATE VIEW ability_sources AS
 SELECT a.*, s.source, s.original_path, s.snapshot_path, s.sha256 AS source_sha256,
 s.git_revision, s.storage_mode FROM abilities a JOIN source_files s USING(file_id);
CREATE VIEW adversary_sources AS
 SELECT a.*, s.source, s.original_path, s.snapshot_path, s.sha256 AS source_sha256,
 s.git_revision, s.storage_mode FROM adversaries a JOIN source_files s USING(file_id);
CREATE VIEW adversary_variant_sources AS
 SELECT v.*, a.adversary_id, s.source, s.original_path, s.snapshot_path,
 s.sha256 AS source_sha256, s.git_revision, s.storage_mode
 FROM adversary_variants v JOIN adversaries a ON a.record_id=v.adversary_record_id
 JOIN source_files s ON s.file_id=v.file_id;
CREATE VIEW adversary_retrieval AS
 SELECT * FROM adversary_sources
 WHERE review_status != 'source_conflict' AND reference_status='complete';
"""


def git_revision(path):
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def local_path(root, value):
    path = Path(value)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Source paths must be bundle-relative: ' + value)
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError('Source escapes bundle: ' + value)
    return resolved


def rebuild(root, destination=None):
    root = Path(root).resolve()
    manifest = json.loads((root / 'data/catalog_manifest.json').read_text())
    entries = manifest['files']
    destination = Path(destination) if destination else root / 'data/catalog.sqlite'
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='catalog-', suffix='.sqlite', dir=destination.parent)
    import os
    os.close(fd)
    temp = Path(temp)
    scenario_validator = Draft202012Validator(yaml.safe_load((root / 'input/schema/scenario_adversary.schema.yaml').read_text()))
    try:
        with sqlite3.connect(temp) as conn:
            conn.executescript(DDL)
            for key,value in {'format_version':'3', 'source_mode':'portable_manifest', 'mode':'plan_only'}.items():
                conn.execute('INSERT INTO import_info VALUES (?,?)',(key,value))
            for entry in entries:
                relative=entry['original_path']; path=local_path(root, relative)
                content=path.read_bytes()
                if hashlib.sha256(content).hexdigest()!=entry['sha256']:
                    raise ValueError('Source hash mismatch: '+relative)
                source,kind=entry['source'],entry['kind']
                file_id=conn.execute('INSERT INTO source_files(source,kind,original_path,snapshot_path,storage_mode,sha256,git_revision,byte_size) VALUES (?,?,?,?,?,?,?,?)',
                    (source,kind,relative,None,'direct',entry['sha256'],entry.get('git_revision'),len(content))).lastrowid
                index=0
                for doc in yaml.safe_load_all(content):
                    for record in doc if isinstance(doc,list) else [doc]:
                        index+=1
                        if source=='scenarios': scenario_validator.validate(record)
                        n=normalize_ability(record) if kind=='abilities' else normalize_adversary(record)
                        if not n['id'].strip():raise ValueError('Missing ID: '+relative)
                        norm=encode(n); normhash=hashlib.sha256(norm.encode()).hexdigest()
                        if kind=='abilities':
                            columns='ability_id,file_id,entry_index,source_kind,name,description,tactic,technique_id,technique_name,privilege,requirements_json,normalized_json,normalized_sha256,original_json,review_status'
                            values=(n['id'],file_id,index,'converted_atomic' if source in ('atomic','atomic_extra') else 'caldera_ability',n['name'],n['description'],n['tactic'],n['technique_id'],n['technique_name'],n['privilege'],encode(n['requirements']),norm,normhash,encode(record),'needs_review' if source in ('custom_dvwa','stockpile_extra','atomic_extra') else 'not_reviewed')
                            rid=conn.execute('INSERT INTO abilities('+columns+') VALUES ('+','.join('?' for _ in values)+')',values).lastrowid
                            for ex in n['executors']:
                                conn.execute('INSERT INTO executors(ability_record_id,platform,name,command,cleanup_json,timeout,payloads_json,placeholders_json,details_json) VALUES (?,?,?,?,?,?,?,?,?)',
                                    (rid,ex['platform'],ex['name'],ex.get('command'),encode(ex['cleanup']),ex.get('timeout'),encode(ex['payloads']),encode(ex['fact_placeholders']),encode(ex)))
                        else:
                            eq=adversary_equivalence_hash(n)
                            old=conn.execute('SELECT record_id,normalized_json FROM adversaries WHERE adversary_id=?',(n['id'],)).fetchone()
                            if old:
                                rid=old[0]
                                if adversary_equivalence_hash(json.loads(old[1]))!=eq:
                                    conn.execute("UPDATE adversaries SET review_status='source_conflict' WHERE record_id=?",(rid,))
                            else:
                                rid=conn.execute('INSERT INTO adversaries(adversary_id,file_id,entry_index,name,description,objective,normalized_json,normalized_sha256,original_json) VALUES (?,?,?,?,?,?,?,?,?)',
                                    (n['id'],file_id,index,n['name'],n['description'],n['objective'],norm,normhash,encode(record))).lastrowid
                            conn.execute('INSERT INTO adversary_variants(adversary_record_id,file_id,entry_index,normalized_json,normalized_sha256,equivalence_sha256,original_json) VALUES (?,?,?,?,?,?,?)',
                                (rid,file_id,index,norm,normhash,eq,encode(record)))
            alias_data=json.loads((root/'input/knowledge base/ability_aliases.json').read_text())
            for alias in alias_data['aliases']:
                if conn.execute('SELECT 1 FROM abilities WHERE ability_id=?',(alias['alias_id'],)).fetchone():raise ValueError('Alias shadows real ability')
                matches=conn.execute('SELECT normalized_sha256 FROM ability_sources WHERE ability_id=? AND source_sha256=?',(alias['canonical_id'],alias['target_source_sha256'])).fetchall()
                if not matches or len({row[0] for row in matches})!=1:raise ValueError('Alias target missing or conflicting')
                conn.execute('INSERT INTO ability_aliases VALUES (?,?,?,?,?)',(alias['alias_id'],alias['canonical_id'],alias['target_source_sha256'],alias['reason'],encode(alias['evidence'])))
            quarantine=root/'input/knowledge base/quarantine/custom_abilities'
            placeholders={p.stem for p in quarantine.glob('*.yml')}
            registry=json.loads((root/'input/knowledge base/unresolved_ability_references.json').read_text())['references']
            for table,steps,key in [('adversaries','adversary_steps','record_id'),('adversary_variants','adversary_variant_steps','variant_id')]:
                for rid,norm in conn.execute('SELECT '+key+',normalized_json FROM '+table).fetchall():
                    ordering=json.loads(norm)['atomic_ordering']; complete=bool(ordering)
                    for pos,identifier in enumerate(ordering,1):
                        status,canonical,count=classify_reference(conn,identifier,placeholders,registry)
                        conn.execute('INSERT INTO '+steps+' VALUES (?,?,?,?,?,?)',(rid,pos,identifier,status,count,canonical))
                        complete=complete and status in ('resolved','alias_resolved')
                    conn.execute('UPDATE '+table+' SET reference_status=? WHERE '+key+'=?',('complete' if complete else 'incomplete',rid))
            if conn.execute('PRAGMA integrity_check').fetchone()[0]!='ok' or conn.execute('PRAGMA foreign_key_check').fetchall():raise ValueError('Catalog integrity check failed')
            summary={table:conn.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in ['source_files','abilities','executors','adversaries','adversary_variants','ability_aliases','adversary_retrieval']}
        temp.replace(destination)
        return summary
    finally:
        temp.unlink(missing_ok=True)


def main():
    parser=argparse.ArgumentParser(description='Rebuild catalog from bundle-local manifest/YAML; no external CALDERA required.')
    parser.add_argument('--project-root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    print(json.dumps(rebuild(args.project_root,args.output),ensure_ascii=False,indent=2))

if __name__=='__main__':main()
