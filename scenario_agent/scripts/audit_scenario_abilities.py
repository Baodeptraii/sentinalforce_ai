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


def audit(root):
    import sqlite3
    try:
        from .import_caldera_catalog import local_path, classify_reference
    except ImportError:
        from import_caldera_catalog import local_path, classify_reference
    root=Path(root).resolve()
    manifest=json.loads((root/'data/catalog_manifest.json').read_text())
    validator=Draft202012Validator(yaml.safe_load((root/'input/schema/scenario_adversary.schema.yaml').read_text()))
    placeholders={p.stem for p in (root/'input/knowledge base/quarantine/custom_abilities').glob('*.yml')}
    registry=json.loads((root/'input/knowledge base/unresolved_ability_references.json').read_text())['references']
    counts=Counter();scenarios=[];invalid=[]
    with sqlite3.connect((root/'data/catalog.sqlite').as_uri()+'?mode=ro',uri=True) as db:
        for entry in manifest['files']:
            path=local_path(root,entry['original_path']);raw=path.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=entry['sha256']:raise ValueError('YAML hash mismatch: '+entry['original_path'])
            if entry['source']!='scenarios':
                if entry['kind']=='abilities':
                    for doc in yaml.safe_load_all(raw):
                        for record in doc if isinstance(doc,list) else [doc]:
                            issues=ability_issues(record)
                            if issues:invalid.append({'source':entry['original_path'],'issues':issues})
                continue
            record=yaml.safe_load(raw);validator.validate(record)
            statuses=[classify_reference(db,ref,placeholders,registry)[0] for ref in record['atomic_ordering']]
            counts.update(statuses)
            scenarios.append({'file':entry['original_path'],'id':record['id'],'references_complete':all(status in ('resolved','alias_resolved') for status in statuses),'reference_statuses':statuses})
    return {'scenario_files':len(scenarios),'schema_valid_scenarios':len(scenarios),'complete_scenarios':sum(s['references_complete'] for s in scenarios),'incomplete_scenarios':sum(not s['references_complete'] for s in scenarios),'reference_counts':dict(counts),'ability_structure_issues':invalid,'scenarios':scenarios,'mode':'static_catalog_audit_only','execution_verified':False}


def main():
    parser=argparse.ArgumentParser(description='Audit local bundle sources and scenario references without CALDERA installation.')
    parser.add_argument('--project-root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=audit(args.project_root)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k!='scenarios'},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
