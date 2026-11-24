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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caldera-root", type=Path, required=True,
                        help="Path to an existing CALDERA checkout; no default lab path is assumed.")
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root, project = args.caldera_root.resolve(), args.project_root.resolve()
    sources = [("stockpile", root / "plugins/stockpile/data"),
               ("atomic", root / "plugins/atomic/data"), ("local", root / "data")]
    extra_sources = {"custom_dvwa", "stockpile_extra", "atomic_extra"}
    for label in sorted(extra_sources):
        custom = project / "input/knowledge base" / label
        if custom.is_dir():
            sources.append((label, custom))
    scenario_directory = project / "input/knowledge base/scenarios"
    if scenario_directory.is_dir():
        sources.append(("scenarios", scenario_directory))
    for label, directory in sources:
        if not directory.is_dir():
            raise FileNotFoundError(f"Missing CALDERA source: {label}: {directory}")
    data = project / "data"
    data.mkdir(exist_ok=True)
    raw = project / "input/knowledge base/raw"
    imported_at = datetime.now(timezone.utc).isoformat()
    report = {"imported_at": imported_at, "caldera_root": str(root),
              "scope": [label for label, _ in sources], "files": {}, "issues": []}
    manifest = []
    scenario_schema = Draft202012Validator(yaml.safe_load((project / "input/schema/scenario_adversary.schema.yaml").read_text()))
    fd, db_path = tempfile.mkstemp(prefix="catalog-", suffix=".sqlite", dir=data)
    import os
    os.close(fd)
    db_path = Path(db_path)
    try:
        with sqlite3.connect(db_path) as conn:
            conn.executescript(DDL)
            for key, value in {"format_version": "3", "imported_at": imported_at,
                               "mode": "plan_only", "caldera_root": str(root)}.items():
                conn.execute("INSERT INTO import_info VALUES (?,?)", (key, value))
            counts = Counter()
            for label, directory in sources:
                revision = None if label in extra_sources or label == "scenarios" else git_revision(directory)
                for kind in (("adversaries",) if label == "scenarios" else ("abilities", "adversaries")):
                    kind_directory = directory if label == "scenarios" else directory / kind
                    paths = sorted(p for p in kind_directory.rglob("*")
                                   if p.is_file() and p.suffix in (".yml", ".yaml"))
                    counts[f"{label}/{kind}"] = len(paths)
                    for path in paths:
                        content = path.read_bytes()
                        digest = hashlib.sha256(content).hexdigest()
                        relative = path.relative_to(kind_directory)
                        snapshot = None
                        if label != "scenarios":
                            snapshot = raw / kind / label / relative.parent / f"{relative.stem}.{digest[:12]}{relative.suffix}"
                            snapshot.parent.mkdir(parents=True, exist_ok=True)
                            if snapshot.exists() and snapshot.read_bytes() != content:
                                raise ValueError(f"Snapshot hash collision or modified snapshot: {snapshot}")
                            snapshot.write_bytes(content)
                        entry = {"source": label, "kind": kind, "original_path": str(path),
                                 "snapshot_path": str(snapshot.relative_to(project)) if snapshot else None,
                                 "storage_mode": "direct" if label == "scenarios" else "snapshot",
                                 "sha256": digest, "git_revision": revision, "byte_size": len(content)}
                        manifest.append(entry)
                        file_id = conn.execute(
                            "INSERT INTO source_files(source,kind,original_path,snapshot_path,storage_mode,sha256,git_revision,byte_size) VALUES (?,?,?,?,?,?,?,?)",
                            tuple(entry[k] for k in ("source", "kind", "original_path", "snapshot_path", "storage_mode", "sha256", "git_revision", "byte_size"))).lastrowid
                        try:
                            docs = list(yaml.safe_load_all(content))
                        except yaml.YAMLError as error:
                            if label == "scenarios":
                                raise ValueError(f"Invalid scenario YAML: {path}") from error
                            report["issues"].append({"type": "yaml_error", "path": str(path), "detail": str(error)})
                            continue
                        entry_index = 0
                        for doc in docs:
                            records = doc if isinstance(doc, list) else [doc]
                            for record in records:
                                entry_index += 1
                                try:
                                    if not isinstance(record, dict):
                                        raise ValueError("YAML record must be an object")
                                    if label == "scenarios":
                                        scenario_schema.validate(record)
                                    normalized = (normalize_ability(record) if kind == "abilities" else normalize_adversary(record))
                                    if not normalized["id"].strip():
                                        raise ValueError("Missing record ID")
                                    normalized_json = encode(normalized)
                                    normalized_hash = hashlib.sha256(normalized_json.encode()).hexdigest()
                                except (ValueError, TypeError, AttributeError) as error:
                                    report["issues"].append({"type": "record_error", "path": str(path), "entry_index": entry_index, "detail": str(error)})
                                    continue
                                n = normalized
                                if kind == "abilities":
                                    record_id = conn.execute(
                                        "INSERT INTO abilities(ability_id,file_id,entry_index,source_kind,name,description,tactic,technique_id,technique_name,privilege,requirements_json,normalized_json,normalized_sha256,original_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                        (n["id"], file_id, entry_index, "converted_atomic" if label in ("atomic", "atomic_extra") else "caldera_ability",
                                         n["name"], n["description"], n["tactic"], n["technique_id"], n["technique_name"], n["privilege"], encode(n["requirements"]), normalized_json, normalized_hash, encode(record))).lastrowid
                                    if label in extra_sources:
                                        conn.execute("UPDATE abilities SET review_status='needs_review' WHERE record_id=?", (record_id,))
                                    for ex in n["executors"]:
                                        conn.execute("INSERT INTO executors(ability_record_id,platform,name,command,cleanup_json,timeout,payloads_json,placeholders_json,details_json) VALUES (?,?,?,?,?,?,?,?,?)",
                                                     (record_id, ex["platform"], ex["name"], ex.get("command"), encode(ex["cleanup"]), ex.get("timeout"), encode(ex["payloads"]), encode(ex["fact_placeholders"]), encode(ex)))
                                    reasons = []
                                    if not n["executors"]:
                                        reasons.append("no_executor")
                                    if any(ex["platform"] == "unknown" for ex in n["executors"]):
                                        reasons.append("unknown_platform")
                                    if n["privilege"] in (None, ""):
                                        reasons.append("privilege_unspecified")
                                    if reasons:
                                        report["issues"].append({"type": "incomplete_ability_metadata", "record_id": record_id, "ability_id": n["id"], "reasons": reasons})
                                else:
                                    equivalence = adversary_equivalence_hash(n)
                                    existing = conn.execute("SELECT record_id,normalized_json FROM adversaries WHERE adversary_id=?", (n["id"],)).fetchone()
                                    if existing:
                                        record_id = existing[0]
                                        equivalent = adversary_equivalence_hash(json.loads(existing[1])) == equivalence
                                        report["issues"].append({"type": "adversary_deduplicated", "id": n["id"], "incoming_path": str(path), "equivalent": equivalent})
                                        if not equivalent:
                                            conn.execute("UPDATE adversaries SET review_status='source_conflict' WHERE record_id=?", (record_id,))
                                    else:
                                        record_id = conn.execute("INSERT INTO adversaries(adversary_id,file_id,entry_index,name,description,objective,normalized_json,normalized_sha256,original_json) VALUES (?,?,?,?,?,?,?,?,?)",
                                                     (n["id"], file_id, entry_index, n["name"], n["description"], n["objective"], normalized_json, normalized_hash, encode(record))).lastrowid
                                    conn.execute("INSERT INTO adversary_variants(adversary_record_id,file_id,entry_index,normalized_json,normalized_sha256,equivalence_sha256,original_json) VALUES (?,?,?,?,?,?,?)",
                                                 (record_id, file_id, entry_index, normalized_json, normalized_hash, equivalence, encode(record)))
            alias_path = project / "input/knowledge base/ability_aliases.json"
            if alias_path.exists():
                for alias in json.loads(alias_path.read_text())["aliases"]:
                    if conn.execute("SELECT 1 FROM abilities WHERE ability_id=?", (alias["alias_id"],)).fetchone():
                        raise ValueError(f"Alias shadows a real ability: {alias['alias_id']}")
                    matches = conn.execute("SELECT normalized_sha256 FROM ability_sources WHERE ability_id=? AND source_sha256=?", (alias["canonical_id"], alias["target_source_sha256"])).fetchall()
                    if not matches or len({row[0] for row in matches}) != 1:
                        raise ValueError(f"Alias target missing or stale: {alias['alias_id']}")
                    conn.execute("INSERT INTO ability_aliases VALUES (?,?,?,?,?)", (alias["alias_id"], alias["canonical_id"], alias["target_source_sha256"], alias["reason"], encode(alias["evidence"])))
            report["alias_count"] = conn.execute("SELECT COUNT(*) FROM ability_aliases").fetchone()[0]
            for table, id_column in (("abilities", "ability_id"), ("adversaries", "adversary_id")):
                for identifier, count, variants in conn.execute(f"SELECT {id_column},COUNT(*),COUNT(DISTINCT normalized_sha256) FROM {table} GROUP BY {id_column} HAVING COUNT(*)>1"):
                    report["issues"].append({"type": "duplicate_id", "kind": table, "id": identifier, "records": count, "normalized_variants": variants, "conflict": variants > 1})
            quarantine = project / "input/knowledge base/quarantine/custom_abilities"
            placeholders = {p.stem for p in quarantine.glob("*.yml")} if quarantine.is_dir() else set()
            registry_path = project / "input/knowledge base/unresolved_ability_references.json"
            registry = json.loads(registry_path.read_text())["references"] if registry_path.exists() else {}
            for records_table, steps_table, key in (("adversaries", "adversary_steps", "record_id"), ("adversary_variants", "adversary_variant_steps", "variant_id")):
                for record_id, normalized_json in conn.execute(f"SELECT {key},normalized_json FROM {records_table}").fetchall():
                    ordering = json.loads(normalized_json)["atomic_ordering"]
                    complete = bool(ordering)
                    for position, ability_id in enumerate(ordering, 1):
                        status, canonical_id, count = classify_reference(conn, ability_id, placeholders, registry)
                        conn.execute(f"INSERT INTO {steps_table} VALUES (?,?,?,?,?,?)", (record_id, position, ability_id, status, count, canonical_id))
                        if status not in ("resolved", "alias_resolved"):
                            complete = False
                            if records_table == "adversaries":
                                report["issues"].append({"type": "adversary_reference", "adversary_record_id": record_id, "step_index": position, "ability_id": ability_id, "status": status})
                    conn.execute(f"UPDATE {records_table} SET reference_status=? WHERE {key}=?", ("complete" if complete else "incomplete", record_id))
            report["scenario_import"] = {
                "source_files": counts.get("scenarios/adversaries", 0),
                "storage_mode": "direct",
                "source_directory": str(scenario_directory),
                "snapshot_copies_created": 0,
                "linked_variants": conn.execute("SELECT COUNT(*) FROM adversary_variant_sources WHERE source='scenarios'").fetchone()[0],
                "reference_status": dict(conn.execute("SELECT reference_status,COUNT(*) FROM adversary_variant_sources WHERE source='scenarios' GROUP BY reference_status")),
                "deduplicated_ids": sum(i["type"] == "adversary_deduplicated" for i in report["issues"]),
                "equivalent_duplicates": sum(i["type"] == "adversary_deduplicated" and i["equivalent"] for i in report["issues"]),
                "conflicting_ids": [row[0] for row in conn.execute("SELECT adversary_id FROM adversaries WHERE review_status='source_conflict'")],
                "retrieval_entities_with_complete_references": conn.execute("SELECT COUNT(*) FROM adversary_retrieval").fetchone()[0],
            }
            report["files"] = dict(counts)
            report["totals"] = {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                                for table in ("source_files", "abilities", "executors", "adversaries", "adversary_variants", "adversary_steps", "adversary_variant_steps")}
            report["unique_ids"] = {table: conn.execute(f"SELECT COUNT(DISTINCT {column}) FROM {table}").fetchone()[0]
                                    for table, column in (("abilities", "ability_id"), ("adversaries", "adversary_id"))}
            report["reference_status"] = dict(conn.execute("SELECT resolution_status,COUNT(*) FROM adversary_steps GROUP BY resolution_status"))
            report["issue_counts"] = dict(Counter(item["type"] for item in report["issues"]))
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert not conn.execute("PRAGMA foreign_key_check").fetchall()
        db_path.replace(data / "catalog.sqlite")
        (data / "catalog_manifest.json").write_text(encode({"imported_at": imported_at, "files": manifest}) + "\n")
        (data / "catalog_import_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    finally:
        db_path.unlink(missing_ok=True)
    print(json.dumps({key: value for key, value in report.items() if key != "issues"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
