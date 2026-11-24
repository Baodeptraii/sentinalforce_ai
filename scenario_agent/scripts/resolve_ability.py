#!/usr/bin/env python3
"""Read canonical ability data using an unchanged scenario's original reference.

An alias is a catalog lookup, not an installed CALDERA ability. A future plan
export must use canonical_id and preserve original reference provenance.
"""
import argparse
import json
from pathlib import Path
import sqlite3


def resolve_ability(connection, reference_id):
    connection.row_factory = sqlite3.Row
    rows = connection.execute("SELECT * FROM ability_sources WHERE ability_id=?", (reference_id,)).fetchall()
    alias = None
    if not rows:
        alias = connection.execute("SELECT * FROM ability_aliases WHERE alias_id=?", (reference_id,)).fetchone()
        if alias is None:
            raise LookupError(f"No eligible catalog ability or alias: {reference_id}")
        rows = connection.execute("SELECT * FROM ability_sources WHERE ability_id=? AND source_sha256=?", (alias["canonical_id"], alias["target_source_sha256"])).fetchall()
    if not rows:
        raise LookupError(f"Missing or stale alias target: {reference_id}")
    if len({row["normalized_sha256"] for row in rows}) != 1:
        raise LookupError(f"Conflicting ability definitions: {reference_id}")
    row = dict(rows[0])
    if row["review_status"] in ("placeholder_only", "quarantined"):
        raise LookupError(f"Ability is not eligible for planning: {reference_id}")
    normalized = json.loads(row["normalized_json"])
    if not normalized["executors"] or not any(ex.get("command") or ex.get("code") for ex in normalized["executors"]):
        raise LookupError(f"Ability has no executable command/code: {reference_id}")
    return {"reference_id": reference_id, "canonical_id": row["ability_id"],
            "resolved_via_alias": alias is not None,
            "alias_evidence": json.loads(alias["evidence_json"]) if alias else None,
            "review_status": row["review_status"],
            "ability": normalized,
            "source": {key: row[key] for key in ("source", "original_path", "snapshot_path", "source_sha256", "git_revision", "storage_mode")},
            "execution_authorized": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference_id")
    parser.add_argument("--catalog", type=Path, default=Path(__file__).resolve().parents[1] / "data/catalog.sqlite")
    args = parser.parse_args()
    with sqlite3.connect(args.catalog.resolve().as_uri() + "?mode=ro", uri=True) as db:
        print(json.dumps(resolve_ability(db, args.reference_id), ensure_ascii=False, indent=2))
