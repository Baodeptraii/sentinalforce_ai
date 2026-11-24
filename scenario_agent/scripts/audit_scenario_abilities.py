#!/usr/bin/env python3
"""Audit CALDERA references, distinguishing local knowledge-base additions."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import yaml


def ability_issues(record):
    issues = []
    if not isinstance(record, dict):
        return ["ability_not_object"]
    if not isinstance(record.get("id"), str) or not record["id"].strip():
        issues.append("missing_or_invalid_id")
    if "technique" in record:
        if not isinstance(record["technique"], dict):
            issues.append("invalid_technique_object")
    elif "technique_id" not in record or "technique_name" not in record:
        issues.append("missing_flat_technique_fields")
    if "platforms" in record:
        platforms = record["platforms"]
        if not isinstance(platforms, dict) or not platforms:
            return issues + ["empty_or_invalid_platforms"]
        for platform, executors in platforms.items():
            if not isinstance(platform, str) or not platform.strip() or not isinstance(executors, dict) or not executors:
                issues.append("invalid_platform_executor_mapping")
                continue
            for executor, details in executors.items():
                if not isinstance(executor, str) or not isinstance(details, dict):
                    issues.append("invalid_executor")
                elif not details.get("command") and not details.get("code"):
                    issues.append("executor_has_no_command_or_code")
    else:
        executors = record.get("executors")
        if not isinstance(executors, list) or not executors:
            return issues + ["empty_or_invalid_executors"]
        for ex in executors:
            if not isinstance(ex, dict):
                issues.append("executor_not_object")
                continue
            if not isinstance(ex.get("platform"), str) or not isinstance(ex.get("name"), str):
                issues.append("executor_missing_platform_or_name")
            if not ex.get("command") and not ex.get("code"):
                issues.append("executor_has_no_command_or_code")
    return sorted(set(issues))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--caldera-root", type=Path, required=True,
                        help="Path to an existing CALDERA checkout; no default lab path is assumed.")
    args = parser.parse_args()
    project, root = args.project_root.resolve(), args.caldera_root.resolve()
    folder = project / "input/knowledge base/scenarios"
    if not folder.is_dir():
        raise FileNotFoundError(folder)
    conf = root / "conf/local.yml"
    if not conf.exists():
        conf = root / "conf/default.yml"
    plugins = (yaml.safe_load(conf.read_text()) or {}).get("plugins", [])
    source_dirs = [("local", root / "data/abilities", True)]
    source_dirs += [(p.name, p / "data/abilities", p.name in plugins)
                    for p in sorted((root / "plugins").iterdir())
                    if (p / "data/abilities").is_dir()]
    extra_sources = {"custom_dvwa", "stockpile_extra", "atomic_extra", "custom_placeholders"}
    for source in sorted(extra_sources - {"custom_placeholders"}):
        custom_dir = project / "input/knowledge base" / source / "abilities"
        if custom_dir.is_dir():
            source_dirs.append((source, custom_dir, False))
    quarantine = project / "input/knowledge base/quarantine/custom_abilities"
    if quarantine.is_dir():
        source_dirs.append(("custom_placeholders", quarantine, False))
    abilities = defaultdict(list)
    file_issues = []
    source_counts = {}
    for source, directory, enabled in source_dirs:
        location_kind = "quarantine" if source == "custom_placeholders" else "knowledge_base" if source in extra_sources else "caldera"
        paths = sorted(p for p in directory.rglob("*") if p.is_file() and p.suffix in (".yml", ".yaml"))
        source_counts[source] = {"files": len(paths), "configured_enabled": enabled,
                                "location_kind": location_kind}
        for path in paths:
            try:
                documents = list(yaml.safe_load_all(path.read_text()))
            except (yaml.YAMLError, UnicodeError) as error:
                file_issues.append({"path": str(path), "error": str(error)})
                continue
            for document in documents:
                if not isinstance(document, list):
                    file_issues.append({"path": str(path), "error": "Ability document must be a list for load_ability_file"})
                    continue
                for index, record in enumerate(document, 1):
                    issues = ability_issues(record)
                    if not isinstance(record, dict) or record.get("id") is None:
                        file_issues.append({"path": str(path), "entry": index, "errors": issues})
                        continue
                    identifier = str(record["id"])
                    abilities[identifier].append({"source": source, "path": str(path),
                        "configured_enabled": enabled, "name": record.get("name"),
                        "location_kind": location_kind,
                        "static_issues": issues, "extension_loadable": path.suffix == ".yml"})
    alias_path = project / "input/knowledge base/ability_aliases.json"
    aliases = {row["alias_id"]: row for row in json.loads(alias_path.read_text())["aliases"]} if alias_path.exists() else {}
    registry_path = project / "input/knowledge base/unresolved_ability_references.json"
    registry = json.loads(registry_path.read_text())["references"] if registry_path.exists() else {}
    schema = yaml.safe_load((project / "input/schema/scenario_adversary.schema.yaml").read_text())
    validator = Draft202012Validator(schema)
    scenarios = []
    refs = []
    id_files = defaultdict(list)
    for path in sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix in (".yml", ".yaml")):
        result = {"file": str(path.relative_to(project)), "name": None, "id": None,
                  "schema_errors": [], "steps": []}
        scenarios.append(result)
        try:
            record = yaml.safe_load(path.read_text())
        except (yaml.YAMLError, UnicodeError) as error:
            result["schema_errors"] = [str(error)]
            continue
        result["schema_errors"] = [{"path": list(e.path), "message": e.message}
                                    for e in validator.iter_errors(record)]
        if not isinstance(record, dict):
            continue
        result.update(name=record.get("name"), id=record.get("id") or record.get("adversary_id"))
        if result["id"]:
            id_files[str(result["id"])].append(result["file"])
        ordering = record.get("atomic_ordering")
        if not isinstance(ordering, list):
            continue
        for position, identifier in enumerate(ordering, 1):
            matches = abilities.get(identifier, []) if isinstance(identifier, str) else []
            enabled_matches = [a for a in matches if a["configured_enabled"] and a["extension_loadable"]]
            healthy = [a for a in enabled_matches if not a["static_issues"]]
            kb_matches = [a for a in matches if a["location_kind"] == "knowledge_base" and not a["static_issues"]]
            alias = aliases.get(identifier) if isinstance(identifier, str) else None
            alias_matches = []
            alias_hash_matches = []
            if alias:
                alias_hash_matches = [a for a in abilities.get(alias["canonical_id"], [])
                    if a["location_kind"] != "quarantine"
                    and (a["configured_enabled"] or a["location_kind"] == "knowledge_base")
                    and hashlib.sha256(Path(a["path"]).read_bytes()).hexdigest() == alias["target_source_sha256"]]
                alias_matches = [a for a in alias_hash_matches if not a["static_issues"]]
            status = ("invalid_reference" if not isinstance(identifier, str) or not identifier.strip()
                      else "found" if healthy
                      else "knowledge_base_only" if kb_matches
                      else "alias_resolved" if alias_matches
                      else "ability_structure_issue" if alias_hash_matches
                      else "stale_alias" if alias
                      else "placeholder_only" if matches and all(a["location_kind"] == "quarantine" for a in matches)
                      else "manual_required" if identifier in registry and registry[identifier]["status"] == "manual_required"
                      else "missing" if not matches
                      else "not_in_configured_sources" if not enabled_matches
                      else "ability_structure_issue")
            step = {"step_index": position, "ability_id": identifier, "status": status,
                    "matches": matches, "resolved_ability_id": alias["canonical_id"] if alias_matches else identifier if status in ("found", "knowledge_base_only") else None,
                    "alias_matches": alias_matches or alias_hash_matches}
            result["steps"].append(step)
            refs.append({"scenario_file": result["file"], "scenario_name": result["name"],
                         "scenario_id": result["id"], **step})
        result["repeated_ids"] = {k: v for k, v in Counter(x for x in ordering if isinstance(x, str)).items() if v > 1}
    missing = defaultdict(list)
    for row in refs:
        if row["status"] == "missing":
            missing[row["ability_id"]].append({k: row[k] for k in ("scenario_file", "scenario_name", "step_index")})
    summary = {"scenario_files": len(scenarios), "ability_files_scanned": sum(s["files"] for s in source_counts.values()),
               "caldera_ability_files_scanned": sum(s["files"] for s in source_counts.values() if s["location_kind"] == "caldera"),
               "knowledge_base_ability_files_scanned": sum(s["files"] for s in source_counts.values() if s["location_kind"] == "knowledge_base"),
               "unique_available_ability_ids": sum(any(m["location_kind"] != "quarantine" for m in records) for records in abilities.values()),
               "quarantined_ability_files_scanned": sum(s["files"] for s in source_counts.values() if s["location_kind"] == "quarantine"),
               "step_references": len(refs),
               "reference_status": dict(Counter(r["status"] for r in refs)),
               "unique_missing_ids": len(missing),
               "scenarios_with_missing_ids": sum(any(s["status"] == "missing" for s in row["steps"]) for row in scenarios),
               "scenarios_with_all_references_found": sum(bool(row["steps"]) and all(s["status"] == "found" for s in row["steps"]) for row in scenarios),
               "scenarios_with_all_references_available_including_kb": sum(bool(row["steps"]) and all(s["status"] in ("found", "knowledge_base_only", "alias_resolved") for s in row["steps"]) for row in scenarios),
               "unique_placeholder_ids_referenced": len({s["ability_id"] for row in scenarios for s in row["steps"] if s["status"] == "placeholder_only"}),
               "unique_unusable_reference_ids": len({s["ability_id"] for row in scenarios for s in row["steps"] if s["status"] not in ("found", "knowledge_base_only", "alias_resolved")}),
               "scenarios_with_unusable_references": sum(any(s["status"] not in ("found", "knowledge_base_only", "alias_resolved") for s in row["steps"]) for row in scenarios),
               "scenarios_with_kb_only_references": sum(any(s["status"] == "knowledge_base_only" for s in row["steps"]) for row in scenarios),
               "references_not_in_caldera": sum(not any(m["location_kind"] == "caldera" for m in s["matches"]) for row in scenarios for s in row["steps"]),
               "scenarios_with_schema_errors": sum(bool(row["schema_errors"]) for row in scenarios),
               "duplicate_scenario_ids": {k: v for k, v in id_files.items() if len(v) > 1},
               "ability_yaml_file_errors": len(file_issues)}
    report = {"checked_at": datetime.now(timezone.utc).isoformat(), "scope": "CALDERA plus supplemental KB definitions, hash-pinned aliases and quarantined placeholders. Alias resolution is catalog-only, not CALDERA installation. No runtime/execution checks.",
              "caldera_root": str(root), "config_file": str(conf), "sources": source_counts,
              "summary": summary, "missing_abilities": dict(sorted(missing.items())),
              "scenarios": scenarios, "ability_file_issues": file_issues,
              "duplicate_ability_ids": {k: v for k, v in abilities.items() if len(v) > 1}}
    data = project / "data"
    data.mkdir(exist_ok=True)
    (data / "scenario_ability_audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    with (data / "scenario_ability_audit.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["scenario_file", "scenario_name", "scenario_id", "step_index", "ability_id", "resolved_ability_id", "status", "ability_paths"])
        writer.writeheader()
        for row in refs:
            writer.writerow({**{k: row[k] for k in writer.fieldnames if k != "ability_paths"},
                             "ability_paths": " | ".join(m["path"] for m in row["matches"] + row["alias_matches"])})
    with (data / "scenario_ability_summary.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["scenario_file", "name", "total_steps", "found_in_caldera", "knowledge_base_only", "alias_resolved", "placeholder_only", "manual_required", "ability_structure_issue", "missing", "schema_errors", "missing_ids", "unusable_ids"])
        for row in scenarios:
            statuses = Counter(s["status"] for s in row["steps"])
            writer.writerow([row["file"], row["name"], len(row["steps"]), statuses["found"], statuses["knowledge_base_only"], statuses["alias_resolved"], statuses["placeholder_only"], statuses["manual_required"], statuses["ability_structure_issue"], statuses["missing"],
                             len(row["schema_errors"]), " | ".join(sorted(set(str(s["ability_id"]) for s in row["steps"] if s["status"] == "missing"))),
                             " | ".join(sorted(set(str(s["ability_id"]) for s in row["steps"] if s["status"] not in ("found", "knowledge_base_only", "alias_resolved"))))])
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("Missing IDs:")
    for identifier, uses in sorted(missing.items()):
        print(identifier, "references:", len(uses))
    print("Affected scenario files:")
    for row in scenarios:
        failed = [s for s in row["steps"] if s["status"] != "found"]
        if failed:
            print(Path(row["file"]).name, f"{len(failed)}/{len(row['steps'])}", ", ".join(sorted(set(str(s["ability_id"]) for s in failed))))


if __name__ == "__main__":
    main()
