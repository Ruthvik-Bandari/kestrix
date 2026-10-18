"""Root-grouped train / development / locked-test split (plan section 11, "Version one benchmark").

A root is a supported SigmaHQ rule with at least one verified positive event: its own SigmaHQ
regression match, or an OTRF event a reviewer labelled malicious. Roots that could leak into
each other are grouped and always land in the same split:

- the same rule family (the tool named after ``proc_creation_win_`` in the file name; after a
  category prefix such as ``susp_`` or ``hktl_``, the next token too);
- no positive event appears in two splits: a shared event stays with the highest-priority split
  (test, then development, then train) and is dropped from the roots elsewhere.

Groups are ordered by a seeded hash and assigned whole: test first, then development, then
train, until each target is met. Leftover groups stay in reserve. Splits are fixed before any
variant is generated, and ``freeze`` refuses to overwrite an existing manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from .qc import SIGMA_RULES

TARGETS = (("test", 12), ("development", 12), ("train", 36))
_PREFIX = "proc_creation_win_"


class SplitError(ValueError):
    pass


# SigmaHQ name prefixes that describe a category rather than a tool; the next token names the family.
_GENERIC = frozenset(
    {"susp", "hktl", "malware", "lolbin", "lolbas", "apt", "renamed", "uac", "pua", "remote", "office"}
)


def family(rule_path: str) -> str:
    stem = Path(rule_path).stem
    rest = stem.removeprefix(_PREFIX)
    if rest == stem:
        return stem
    tokens = rest.split("_")
    return "_".join(tokens[:2]) if tokens[0] in _GENERIC and len(tokens) > 1 else tokens[0]


def rule_paths(sigma_root: Path, rule_ids: set[str]) -> dict[str, str]:
    """Repository path of each rule id, found by the ``id:`` line (no full parse needed)."""
    out: dict[str, str] = {}
    for path in sorted((sigma_root / SIGMA_RULES).rglob("*.yml")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("id:"):
                rid = line[3:].strip().strip("'\"")
                if rid in rule_ids:
                    out[rid] = path.relative_to(sigma_root).as_posix()
                break
    return out


def roots(report: dict[str, Any], malicious: set[str]) -> dict[str, list[str]]:
    """Root rule id -> its verified positive event ids."""
    out: dict[str, list[str]] = {}
    for rule_id, entry in report["per_rule"].items():
        positives = [
            e for e in entry.get("matched_event_ids", []) if (e.startswith(f"sigma:{rule_id}:")) or e in malicious
        ]
        if positives:
            out[rule_id] = sorted(positives)
    return out


def groups(positives: dict[str, list[str]], paths: dict[str, str]) -> list[list[str]]:
    """Group roots by rule family. Shared events are not merged here: one attack event can match
    dozens of rules, and merging on events chains most roots into one group. Event-level leakage is
    resolved after assignment instead (``exclusive_events``)."""
    parent = {r: r for r in positives}

    def find(r: str) -> str:
        while parent[r] != r:
            parent[r] = parent[parent[r]]
            r = parent[r]
        return r

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    first_by_key: dict[str, str] = {}
    for rule_id in sorted(positives):
        keys = [f"family:{family(paths.get(rule_id, rule_id))}"]
        for key in keys:
            if key in first_by_key:
                union(rule_id, first_by_key[key])
            else:
                first_by_key[key] = rule_id
    members: dict[str, list[str]] = defaultdict(list)
    for rule_id in sorted(positives):
        members[find(rule_id)].append(rule_id)
    return sorted(members.values())


PRIORITY = ("test", "development", "train")


def exclusive_events(
    splits: dict[str, list[list[str]]], positives: dict[str, list[str]]
) -> tuple[dict[str, list[list[str]]], int, int]:
    """Give every positive event to exactly one split (test, then development, then train), dropping
    it from roots in the other splits. A root left with no positives moves to reserve. Returns
    the new splits, the positives dropped, and the roots moved."""
    owner: dict[str, str] = {}
    for name in PRIORITY:
        for group in splits[name]:
            for root in group:
                for event in positives[root]:
                    owner.setdefault(event, name)
    dropped = moved = 0
    out: dict[str, list[list[str]]] = {name: [] for name in splits}
    out["reserve"] = [list(g) for g in splits.get("reserve", [])]
    for name in PRIORITY:
        for group in splits[name]:
            kept = []
            for root in group:
                own = [e for e in positives[root] if owner[e] == name]
                dropped += len(positives[root]) - len(own)
                positives[root] = own
                if own:
                    kept.append(root)
                else:
                    moved += 1
                    out["reserve"].append([root])
            if kept:
                out[name].append(kept)
    return out, dropped, moved


def assign(grouped: list[list[str]], seed: str) -> dict[str, list[list[str]]]:
    order = sorted(grouped, key=lambda g: hashlib.sha256(f"{seed}:{g[0]}".encode()).hexdigest())
    splits: dict[str, list[list[str]]] = {name: [] for name, _ in (*TARGETS, ("reserve", 0))}
    targets = iter(TARGETS)
    name, target = next(targets)
    filled = 0
    for group in order:
        while name != "reserve" and filled >= target:
            name, target = next(targets, ("reserve", 0))
            filled = 0
        splits[name].append(group)
        filled += len(group)
    return splits


def build(
    sigma_root: Path,
    report: dict[str, Any],
    malicious: set[str],
    seed: str,
    extra: dict[str, list[str]] | None = None,
) -> dict[str, object]:
    """``extra``: more roots with verified positives, such as rules whose natural fixes detect pool events."""
    positives = roots(report, malicious)
    for rule_id, events in (extra or {}).items():
        positives[rule_id] = sorted(set(positives.get(rule_id, [])) | set(events))
    paths = rule_paths(sigma_root, set(positives))
    missing = sorted(set(positives) - set(paths))
    if missing:
        raise SplitError(f"{len(missing)} root rules have no file in the Sigma checkout")
    splits, dropped, moved = exclusive_events(assign(groups(positives, paths), seed), positives)
    summary = {
        name: {
            "groups": len(gs),
            "roots": sum(len(g) for g in gs),
            "roots_with_2plus_positives": sum(len(positives[r]) >= 2 for g in gs for r in g),
        }
        for name, gs in splits.items()
    }
    largest = max((len(g) for gs in splits.values() for g in gs), default=0)
    return {
        "schema_version": 1,
        "seed": seed,
        "reviewed_malicious_events": len(malicious),
        "eligible_roots": len(positives),
        "natural_roots_added": len(set(extra or {}) - set(roots(report, malicious))),
        "largest_group": largest,
        "positives_dropped_for_leakage": dropped,
        "roots_moved_to_reserve": moved,
        "summary": summary,
        "splits": {
            name: [{"rules": [{"id": r, "path": paths[r], "positive_event_ids": positives[r]} for r in g]} for g in gs]
            for name, gs in splits.items()
        },
    }


def freeze(manifest: dict[str, object], sigma_root: Path, out: Path) -> str:
    """Write the manifest with each root rule's source SHA-256; refuse to overwrite. Returns its hash."""
    if out.exists():
        raise SplitError(f"{out} exists; a frozen split is never overwritten")
    splits = manifest["splits"]
    if not isinstance(splits, dict):
        raise SplitError("manifest has no splits")
    for groups_ in splits.values():
        for group in groups_:
            for rule in group["rules"]:
                rule["source_sha256"] = hashlib.sha256((sigma_root / rule["path"]).read_bytes()).hexdigest()
    data = json.dumps(manifest, indent=2, sort_keys=True).encode()
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data + b"\n")
    return hashlib.sha256(data + b"\n").hexdigest()
