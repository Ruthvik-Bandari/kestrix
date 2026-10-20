# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Extend the frozen split with mined records, negatives and audit flags (split manifest v2).

The v1 assignment (``work/split.jsonl``, manifest ``FROZEN_MANIFEST_SHA256``) is never changed:

* Before anything else the v1 test ids and their content hashes are recomputed from
  ``work/split.jsonl`` and checked against the v1 manifest; any mismatch aborts.
* Every v1 record keeps its split. New records never enter ``test``.
* A new record joins the group (connected component of repositories and advisory ids) of the v1
  records it shares a node with. In a train or dev group it takes that split if it was published
  before the cutoff; in a test group it goes to ``test_extension`` if published on or after the
  cutoff. A record whose group spans two v1 splits, or that breaks the date rule, is dropped.
* A group made only of new records follows the v1 rules, except that its held-out part is
  ``test_extension``: earliest date on or after the cutoff, otherwise the seeded dev slice or train.
* After writing, the frozen test ids and content hashes are recomputed from ``work/split-v2.jsonl``
  and must equal the values before.

Negatives (``work/negatives.jsonl``, written by ``negatives.py``) and the AI audit verdicts
(``work/audit_verdicts.jsonl``) are listed by id beside the splits; the frozen test id list is not
touched. The manifest holds ids, counts and hashes only.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .audit import stratum
from .licenses import classify, license_of
from .split import CUTOFF, SEED, SplitError, _licenses, check_disjoint, group_keys, ids_sha256, in_dev_slice

FROZEN_MANIFEST_SHA256 = "1e52811528832d0daf42f63399734b4643bcb7cc051708bd6f077cf4ce88986a"
SPLITS_V2 = ("train", "dev", "test", "test_extension")
HELD_OUT = {"test", "test_extension"}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def content_sha256(records: list[dict[str, Any]]) -> str:
    """Hash of (id, vulnerable hash, patched hash) of the given records, sorted by id."""
    lines = sorted(f"{r['id']} {r.get('vulnerable_sha256')} {r.get('patched_sha256')}\n" for r in records)
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def frozen_test(records: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any]:
    """Check the v1 test records against the v1 manifest; return their id and content hashes."""
    if manifest.get("manifest_sha256") != FROZEN_MANIFEST_SHA256:
        raise SplitError("the v1 split manifest is not the frozen one")
    test = [r for r in records if r.get("split") == "test"]
    ids = sorted(r["id"] for r in test)
    if ids != manifest["splits"]["test"]["ids"] or ids_sha256(ids) != manifest["splits"]["test"]["ids_sha256"]:
        raise SplitError("work/split.jsonl test records differ from the frozen test manifest")
    return {"ids_sha256": ids_sha256(ids), "content_sha256": content_sha256(test), "records": len(ids)}


def assign_new(
    frozen: list[dict[str, Any]], new: list[dict[str, Any]], seed: str = SEED
) -> tuple[dict[str, str], Counter[str]]:
    """Splits for the new records only; v1 records keep theirs (see the module docstring)."""
    keys = group_keys(frozen + new)
    existing: dict[str, set[str]] = defaultdict(set)
    for r in frozen:
        existing[keys[r["id"]]].add(r["split"])
    members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in new:
        members[keys[r["id"]]].append(r)
    out: dict[str, str] = {}
    dropped: Counter[str] = Counter()
    for group, recs in sorted(members.items()):
        splits = existing.get(group, set())
        if len(splits) > 1:
            dropped["bridges_two_frozen_splits"] += len(recs)
            continue
        dates = [r["published"] for r in recs if r.get("published")]
        if splits:
            target = next(iter(splits))
        elif dates and min(dates) >= CUTOFF:
            target = "test"  # held out; new records land in test_extension below
        else:
            target = "dev" if in_dev_slice(group, seed) else "train"
        for r in recs:
            date = r.get("published")
            if not date:
                dropped["record_without_date"] += 1
            elif target == "test":
                if date >= CUTOFF:
                    out[r["id"]] = "test_extension"
                else:
                    dropped["pre_cutoff_record_in_held_out_group"] += 1
            elif date >= CUTOFF:
                dropped["post_cutoff_record_in_pre_cutoff_group"] += 1
            else:
                out[r["id"]] = target
    return out, dropped


def _split_block(chosen: list[dict[str, Any]], table: dict[str, str]) -> dict[str, Any]:
    ids = sorted(r["id"] for r in chosen)
    permissive = Counter(r["language"] for r in chosen if classify(license_of(r, table)) == "permissive")
    return {
        "records": len(ids),
        "by_language": dict(sorted(Counter(r["language"] for r in chosen).items())),
        "by_language_permissive": dict(sorted(permissive.items())) if table else None,
        "by_source": dict(sorted(Counter(r["source"] for r in chosen).items())),
        "by_rule": dict(sorted(Counter(r["label_rule"] for r in chosen).items())),
        "projects": len({r["repo"] for r in chosen}),
        "with_patched_counterpart": sum(1 for r in chosen if r.get("patched")),
        "ids_sha256": ids_sha256(ids),
        "ids": ids,
    }


def _audit_sections(
    records: list[dict[str, Any]], assignment: dict[str, str], verdicts: dict[str, dict[str, Any]], drop: set[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    audited = {
        rid: {"ai_audited": True, "verdict": v["final"], "final_by": v["final_by"]}
        for rid, v in sorted(verdicts.items())
        if rid in assignment
    }
    filtered: dict[str, list[str]] = {s: [] for s in SPLITS_V2}
    confirmed: dict[str, list[str]] = {s: [] for s in SPLITS_V2}
    for r in records:
        split = assignment.get(r["id"])
        if split is None:
            continue
        if {stratum(r), f"source:{r['source']}/{r['label_rule']}"} & drop:
            filtered[split].append(r["id"])
        if verdicts.get(r["id"], {}).get("final") == "vulnerable":
            confirmed[split].append(r["id"])
    filters = {
        "dropped_strata": sorted(drop),
        "rule": "strata (family/language/label rule, or source:<source>/<rule>) whose audited label accuracy is below 0.80 are excluded in the "
        "filtered view; the full view keeps them. Test ids stay frozen in both views.",
        "excluded_ids": {s: sorted(v) for s, v in filtered.items()},
        "excluded_ids_sha256": {s: ids_sha256(v) for s, v in filtered.items()},
        "audit_confirmed_ids": {s: sorted(v) for s, v in confirmed.items()},
    }
    return {"records": audited, "count": len(audited)}, filters


def run(root: Path) -> dict[str, Any]:
    work = root / "work"
    frozen = read_jsonl(work / "split.jsonl")
    manifest_v1 = json.loads((root / "reports" / "split-manifest.json").read_text())
    before = frozen_test(frozen, manifest_v1)
    new = read_jsonl(work / "ghsa_deduped.jsonl")
    frozen_ids = {r["id"] for r in frozen}
    if any(r["id"] in frozen_ids for r in new):
        raise SplitError("a new record reuses a frozen record id")
    assignment = {r["id"]: r["split"] for r in frozen}
    new_assignment, dropped = assign_new(frozen, new)
    assignment |= new_assignment
    records = frozen + [r for r in new if r["id"] in new_assignment]
    check_disjoint(records, {k: "held_out" if v in HELD_OUT else v for k, v in assignment.items()})
    table = _licenses(root)
    out = work / "split-v2.jsonl"
    tmp = out.with_name(out.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for r in records:
            spdx = license_of(r, table)
            extra = {"split": assignment[r["id"]], "repo_license": spdx, "license_class": classify(spdx)}
            fh.write(json.dumps(r | extra, sort_keys=True) + "\n")
    tmp.chmod(0o600)
    tmp.replace(out)
    written = [r for r in read_jsonl(out) if r["split"] == "test"]
    after = {
        "ids_sha256": ids_sha256([r["id"] for r in written]),
        "content_sha256": content_sha256(written),
        "records": len(written),
    }
    if after != before:
        raise SplitError("the frozen test split changed while extending")
    splits = {s: _split_block([r for r in records if assignment[r["id"]] == s], table) for s in SPLITS_V2}

    negatives = read_jsonl(work / "negatives.jsonl")
    neg_block: dict[str, Any] = {}
    for s in SPLITS_V2:
        ids = sorted(n["id"] for n in negatives if n["split"] == s)
        neg_block[s] = {
            "records": len(ids),
            "by_language": dict(sorted(Counter(n["language"] for n in negatives if n["split"] == s).items())),
            "ids_sha256": ids_sha256(ids),
            "ids": ids,
        }
    prevalence = {
        s: {
            "vulnerable": splits[s]["records"],
            "negative_unchanged": neg_block[s]["records"],
            "negatives_per_vulnerable": round(neg_block[s]["records"] / splits[s]["records"], 2)
            if splits[s]["records"]
            else None,
        }
        for s in SPLITS_V2
    }
    verdict_rows = read_jsonl(work / "audit_verdicts.jsonl")
    verdicts = {v["id"]: v for v in verdict_rows}
    audit_report = root / "reports" / "audit.json"
    drop = set(json.loads(audit_report.read_text()).get("filter", {}).get("dropped_strata", [])) if verdicts else set()
    audit, filters = _audit_sections(records, assignment, verdicts, drop)
    body: dict[str, Any] = {
        "schema_version": 2,
        "base_manifest_sha256": FROZEN_MANIFEST_SHA256,
        "seed": SEED,
        "test_window_start": CUTOFF,
        "frozen_test": {"before": before, "after": after, "unchanged": after == before},
        "licenses_applied": bool(table),
        "dropped_new_records": dict(sorted(dropped.items())),
        "splits": splits,
        "negatives": neg_block,
        "prevalence": prevalence,
        "ai_audit": audit,
        "filters": filters,
        "evaluated": False,
    }
    body["manifest_sha256"] = hashlib.sha256(
        json.dumps(
            {
                "splits": {s: splits[s]["ids_sha256"] for s in SPLITS_V2},
                "negatives": {s: neg_block[s]["ids_sha256"] for s in SPLITS_V2},
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return body
