# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Deterministic temporal, project-disjoint and advisory-disjoint split of the deduplicated pool.

Records are grouped by connected components of repositories and advisory ids (a CVE fixed in two
repositories, or a GHSA alias of a CVE, joins them), so a project or a CVE/GHSA never spans two
splits. Then, per group:

* **test**: the group's earliest known publication date is on or after ``2024-10-01`` (CVEs
  published after 2024-09-30, after the base model's release). Records without a date are dropped.
* otherwise the group is **dev** (every SVEN group, plus a seeded 10% hash slice of the other
  groups) or **train**. Records of these groups published inside the test window are dropped, so
  train and dev stay before the cutoff and test stays on projects never seen in training.

Only ids and hashes go into the manifest; nothing is evaluated here.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .licenses import classify, license_of

CUTOFF = "2024-10-01"
DEV_PERCENT = 10
SEED = "kestrixvul-split-v1"
SPLITS = ("train", "dev", "test")


class SplitError(RuntimeError):
    pass


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def nodes(record: dict[str, Any]) -> list[str]:
    return [f"repo:{r}" for r in record["repos"]] + [f"adv:{a}" for a in record["advisory_ids"]]


def group_keys(records: list[dict[str, Any]]) -> dict[str, str]:
    """{record id: group key}; the key is the smallest node of the component."""
    uf = UnionFind()
    for record in records:
        first, *rest = nodes(record)
        uf.find(first)
        for node in rest:
            uf.union(first, node)
    return {r["id"]: uf.find(nodes(r)[0]) for r in records}


def in_dev_slice(group: str, seed: str = SEED) -> bool:
    return int(hashlib.sha256(f"{seed}\x1f{group}".encode()).hexdigest()[:8], 16) % 100 < DEV_PERCENT


def assign(records: list[dict[str, Any]], seed: str = SEED) -> tuple[dict[str, str], Counter[str]]:
    """Return ({record id: split}, drop counts)."""
    keys = group_keys(records)
    members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        members[keys[record["id"]]].append(record)
    out: dict[str, str] = {}
    dropped: Counter[str] = Counter()
    for group, recs in sorted(members.items()):
        dates = [r["published"] for r in recs if r.get("published")]
        sven = any(r["source"] == "sven" for r in recs)
        if not sven and dates and min(dates) >= CUTOFF:
            for r in recs:
                if r.get("published"):
                    out[r["id"]] = "test"
                else:
                    dropped["test_group_record_without_date"] += 1
            continue
        split = "dev" if sven or in_dev_slice(group, seed) else "train"
        for r in recs:
            if r.get("published") and r["published"] >= CUTOFF:
                dropped["post_cutoff_record_in_pre_cutoff_group"] += 1
            elif not r.get("published") and r["source"] != "sven":
                dropped["record_without_date"] += 1
            else:
                out[r["id"]] = split
    return out, dropped


def check_disjoint(records: list[dict[str, Any]], assignment: dict[str, str]) -> None:
    owner: dict[str, str] = {}
    for record in records:
        split = assignment.get(record["id"])
        if split is None:
            continue
        for node in nodes(record):
            if owner.setdefault(node, split) != split:
                raise SplitError(f"{node} appears in {owner[node]} and {split}")


def ids_sha256(ids: list[str]) -> str:
    return hashlib.sha256("".join(i + "\n" for i in sorted(ids)).encode()).hexdigest()


def _licenses(root: Path) -> dict[str, str]:
    path = root / "licenses" / "licenses.csv"
    if not path.exists():
        return {}
    return {row["repo"].lower(): row["spdx_id"] for row in csv.DictReader(io.StringIO(path.read_text()))}


def manifest(
    records: list[dict[str, Any]], assignment: dict[str, str], dropped: Counter[str], table: dict[str, str]
) -> dict[str, Any]:
    splits: dict[str, Any] = {}
    for split in SPLITS:
        chosen = [r for r in records if assignment.get(r["id"]) == split]
        ids = sorted(r["id"] for r in chosen)
        by_language = Counter(r["language"] for r in chosen)
        permissive = Counter(r["language"] for r in chosen if classify(license_of(r, table)) == "permissive")
        splits[split] = {
            "records": len(ids),
            "by_language": dict(sorted(by_language.items())),
            "by_language_permissive": dict(sorted(permissive.items())) if table else None,
            "by_source": dict(sorted(Counter(r["source"] for r in chosen).items())),
            "projects": len({r["repo"] for r in chosen}),
            "with_patched_counterpart": sum(1 for r in chosen if r.get("patched")),
            "ids_sha256": ids_sha256(ids),
            "ids": ids,
        }
    body = {
        "schema_version": 1,
        "seed": SEED,
        "test_window_start": CUTOFF,
        "dev_percent_of_pre_cutoff_groups": DEV_PERCENT,
        "licenses_applied": bool(table),
        "dropped": dict(sorted(dropped.items())),
        "splits": splits,
        "evaluated": False,
    }
    body["manifest_sha256"] = hashlib.sha256(
        json.dumps({s: splits[s]["ids_sha256"] for s in SPLITS}, sort_keys=True).encode()
    ).hexdigest()
    return body


def run(root: Path) -> dict[str, Any]:
    path = root / "work" / "deduped.jsonl"
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    assignment, dropped = assign(records)
    check_disjoint(records, assignment)
    table = _licenses(root)
    out = root / "work" / "split.jsonl"
    tmp = out.with_name(out.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for record in records:
            if record["id"] in assignment:
                spdx = license_of(record, table)
                extra = {"split": assignment[record["id"]], "repo_license": spdx, "license_class": classify(spdx)}
                fh.write(json.dumps(record | extra, sort_keys=True) + "\n")
    tmp.chmod(0o600)
    tmp.replace(out)
    return manifest(records, assignment, dropped, table)
