# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Round 2 of the learned ranker: a new held-out set (test-v2), a project-disjoint validation split, the ship rule.

Research only (not in the wheel). Three commands, all offline and CPU-only::

    python -m kestrixvul.round2 build-test2 --root VUL2 --vul-root VUL --codebench-root CB2
    python -m kestrixvul.round2 split --root VUL2 --vul-root VUL
    python -m kestrixvul.round2 decide --report REPORT.json --system NAME [--out FILE]

**test-v2** (``build-test2``). The C6 test splits are spent, so the new held-out set is built from fix commits
that the C6 pool does not hold: reviewed GHSA advisories (refresh of 2026-10-22) whose fix commits neither
CVEfixes, MoreFixes nor the C6 GHSA extension contain, mined by ``ghsa_mine`` into the codebench2 mine folder. They
go through the same extraction, PrimeVul labelling and deduplication as the C6 pool (deduplicated against every C6
pool function, so no function is shared). A group (connected component of repositories and advisory ids) joins
test-v2 only if it shares no repository and no advisory or CVE id with any C6 record or mined target, in any C6 split
(train, dev, test, test_extension) or in a record that C6 dropped. Tiers, decided before any model saw the data:

* **A**: the group has an advisory published on or after ``CUTOFF`` (2024-10-01, after the base model's release);
  only its post-cutoff records are kept (as ``split.py`` does for the C6 test).
* **B**: every record of the group predates the cutoff.

If neither tier qualifies the fallback is used (what happened: tier A had 47 records in 36 projects, A+B 74 in 63): the
held-out set ``test2`` is a seeded, project-disjoint 50% carve-out of the C6 dev groups (biased toward the C6 teacher,
which was selected on dev), and tier A is kept apart as the small ``test2_fresh`` set. Tier B is unused.

Rule written before counting records: test-v2 is tier A if it holds at least ``MIN_RECORDS`` vulnerable records in at
least ``MIN_PROJECTS`` projects; else tier A plus B (said plainly in the report: pre-cutoff advisories may be in the
base model's pre-training); else nothing is frozen (the fallback is a carve-out of the C6 dev split, documented as
used before for checkpoint selection). Tier B is never in both test-v2 and training. Negatives are unchanged
functions of the same commits, filtered like C6 (``negatives.select``) and exact-deduplicated against the C6 negatives.
The result is frozen once: ``reports/TEST2_FROZEN.json`` is created exclusively, with the manifest hash.

**Round-2 training split** (``split``). Every C6 record (train, dev, test, test_extension: the C6 test is spent, so
its data is ordinary training data now) plus the tier-B records not used by test-v2, regrouped by repository and
advisory ids; a seeded hash slice of ``VAL_PERCENT`` percent of the groups becomes the validation split (written as
``dev`` so that ``train.py`` and ``evaluate.py`` read it unchanged; it serves checkpoint choice and thresholds only),
the rest is ``train``. Validation and training therefore share no project, and test-v2 shares none with either.

**Ship rule** (``decide``), fixed before the one evaluation on test-v2; see ``SHIP_RULE``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .dedup import deduplicate
from .negatives import select as select_negatives
from .split import CUTOFF, group_keys, ids_sha256, nodes

MIN_RECORDS = 100
MIN_PROJECTS = 50
VAL_PERCENT = 15
VAL_SEED = "kestrixvul-round2-val-v1"
TEST2_SPLIT = "test2"
FROZEN_NAME = "TEST2_FROZEN.json"
SCHEMA_VERSION = 1

SHIP_RULE = (
    "Ship the round-2 ranker as an optional 'worth a look' ranker only if, on test-v2 (full view): "
    "(1) its PR-AUC 95% repository-bootstrap interval lies entirely above the intervals of the kestrix-scan rules "
    "and of the bag-of-words baseline (non-overlapping), AND (2) its pair accuracy is at least 0.25, where pair "
    "accuracy is the share of vulnerable/patched pairs with the vulnerable version at or above and the patched "
    "version below the validation-chosen threshold ('correct' in the C6 reports: 0.322 dev, 0.147 test, 0.071 "
    "extension for the C6 teacher). Otherwise it is not shipped."
)
PAIR_MIN = 0.25


class Round2Error(RuntimeError):
    pass


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def write_json(path: Path, obj: object) -> None:
    write_private(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")


def jsonl(rows: Iterable[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)


# --- build test-v2 ----------------------------------------------------------------------------


def repo_node(repo: str) -> str:
    """``owner/name`` or ``github.com/owner/name`` to the split-module node ``repo:github.com/owner/name``."""
    key = repo.strip().lower()
    return f"repo:{key if key.startswith('github.com/') else 'github.com/' + key}"


def c6_nodes(vul_root: Path) -> set[str]:
    """Every repository and advisory/CVE node of the C6 pool, its dropped candidates and its mine targets."""
    work = vul_root / "work"
    seen: set[str] = set()
    for name in ("split-v2.jsonl", "deduped.jsonl", "ghsa_deduped.jsonl", "candidates.jsonl", "ghsa_candidates.jsonl"):
        path = work / name
        if path.is_file():
            for row in iter_jsonl(path):
                seen.update(nodes(row))
    for row in iter_jsonl(work / "mine_targets.jsonl"):
        seen.add(repo_node(row["repo"]))
        seen.update(f"adv:{a}" for a in row["advisories"])
    return seen


def prepare_extract_root(root: Path, codebench_root: Path) -> dict[str, int]:
    """Make ``root`` look like a C5 root for ``ghsa_mine.extract``: targets, advisory texts, the fetched commits."""
    from .ghsa_mine import advisory_texts

    work = root / "work"
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    targets = [t for t in iter_jsonl(codebench_root / "work" / "mine_targets.jsonl") if t["role"] == "ghsa"]
    write_private(work / "mine_targets.jsonl", jsonl(targets))
    wanted = {a for t in targets for a in t["advisories"]}
    texts = []
    for adv in advisory_texts(codebench_root / "raw" / "ghsa"):
        if adv["id"] in wanted:
            published = str(adv["published"])[:10] if adv["published"] else None
            texts.append(
                {k: adv[k] for k in ("id", "aliases", "ecosystems", "cwes", "summary", "details")}
                | {"cve_descriptions": [], "published": published}
            )
    write_private(work / "ghsa_text.jsonl", jsonl(texts))
    write_private(work / "split.jsonl", "")  # extract reads the pool's commit dates from it: none are new
    mine = root / "mine"
    if not mine.exists():
        mine.symlink_to(codebench_root / "mine")
    return {"targets": len(targets), "advisories": len(texts)}


def assign_tiers(
    records: list[dict[str, Any]], excluded: set[str]
) -> tuple[dict[str, str], dict[str, str], Counter[str]]:
    """({id: 'A'}, {id: 'B'}, drop counts): see the module docstring."""
    keys = group_keys(records)
    members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in records:
        members[keys[r["id"]]].append(r)
    a: dict[str, str] = {}
    b: dict[str, str] = {}
    dropped: Counter[str] = Counter()
    for _, recs in sorted(members.items()):
        if any(n in excluded for r in recs for n in nodes(r)):
            dropped["group_shares_a_node_with_c6"] += len(recs)
            continue
        if any(not r.get("published") for r in recs):
            dropped["record_without_date"] += sum(1 for r in recs if not r.get("published"))
        dated = [r for r in recs if r.get("published")]
        if any(r["published"] >= CUTOFF for r in dated):
            for r in dated:
                if r["published"] >= CUTOFF:
                    a[r["id"]] = "A"
                else:
                    dropped["pre_cutoff_record_in_tier_a_group"] += 1
        else:
            b.update({r["id"]: "B" for r in dated})
    return a, b, dropped


def summarize(chosen: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "records": len(chosen),
        "projects": len({r["repo"] for r in chosen}),
        "advisories": len({a for r in chosen for a in r["advisory_ids"] if a.startswith("GHSA-")}),
        "with_patched_counterpart": sum(1 for r in chosen if r.get("patched")),
        "by_language": dict(sorted(Counter(r["language"] for r in chosen).items())),
        "by_label_rule": dict(sorted(Counter(r["label_rule"] for r in chosen).items())),
    }


def meaningful(summary: dict[str, Any]) -> bool:
    return bool(summary["records"] >= MIN_RECORDS and summary["projects"] >= MIN_PROJECTS)


def choose(tier_a: list[dict[str, Any]], tier_b: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """('A' | 'A+B' | 'none', the test-v2 records) by the rule in the module docstring."""
    if meaningful(summarize(tier_a)):
        return "A", tier_a
    if meaningful(summarize(tier_a + tier_b)):
        return "A+B", tier_a + tier_b
    return "none", []


CARVE_SEED = "kestrixvul-round2-test2-carve-v1"
CARVE_PERCENT = 50
FRESH_SPLIT = "test2_fresh"
TEST2_SPLITS = frozenset({TEST2_SPLIT, FRESH_SPLIT})


def carve_dev(
    c6_records: list[dict[str, Any]], percent: int = CARVE_PERCENT, seed: str = CARVE_SEED
) -> list[dict[str, Any]]:
    """Fallback held-out: records of a seeded ``percent`` slice of the C6 dev groups (project-disjoint).

    The C6 dev split was used to choose the C6 teacher, its checkpoint and its threshold, so this carve-out is
    biased in favour of the C6 teacher; it was never used to train or select any round-2 model.
    """
    dev = [r for r in c6_records if r.get("split") == "dev"]
    keys = group_keys(dev)
    return [
        r | {"split": TEST2_SPLIT, "tier": "dev_carve", "c6_split": "dev"}
        for r in dev
        if in_val_slice(keys[r["id"]], seed, percent)
    ]


def build_test2(root: Path, vul_root: Path, codebench_root: Path, reuse_extract: bool = False) -> dict[str, Any]:
    from .ghsa_mine import extract

    work = root / "work"
    if reuse_extract and (work / "ghsa_candidates.jsonl").is_file():
        prep: dict[str, int] = {"reused_extraction": 1}
        extract_report: dict[str, Any] = {"counts": {}}
    else:
        prep = prepare_extract_root(root, codebench_root)
        extract_report = extract(root)
    c6_pool = read_jsonl(vul_root / "work" / "deduped.jsonl") + read_jsonl(vul_root / "work" / "ghsa_deduped.jsonl")
    candidates = read_jsonl(work / "ghsa_candidates.jsonl")
    kept, dedup_report = deduplicate(candidates, c6_pool)
    excluded = c6_nodes(vul_root)
    a, b, dropped = assign_tiers(kept, excluded)
    tier_a = [r | {"split": TEST2_SPLIT, "tier": "A"} for r in kept if r["id"] in a]
    tier_b = [r | {"split": "tier_b", "tier": "B"} for r in kept if r["id"] in b]
    rule, chosen = choose(tier_a, tier_b)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "stage": "build-test2",
        "prepared": prep,
        "extraction_counts": {k: v for k, v in extract_report["counts"].items() if not k.startswith("negative")},
        "dedup_against_c6_pool": {
            "candidates": len(candidates),
            "kept": len(kept),
            "dropped_by_source_pair": dedup_report["dropped_by_source_pair"],
            "per_source_language": dedup_report["per_source_language"],
        },
        "dropped": dict(sorted(dropped.items())),
        "tier_a": summarize(tier_a),
        "tier_b": summarize(tier_b),
        "thresholds": {"min_records": MIN_RECORDS, "min_projects": MIN_PROJECTS},
        "rule_outcome": rule,
        "cutoff": CUTOFF,
    }
    if rule == "none":
        # Too few new projects: the held-out set is a project-disjoint carve-out of C6 dev, and tier A (fresh,
        # post-cutoff, new projects) is kept apart as a small secondary set. Tier B (27 records) is not used.
        carve = carve_dev(read_jsonl(vul_root / "work" / "split-v2.jsonl"))
        chosen = carve + [r | {"split": FRESH_SPLIT} for r in tier_a]
        report["carve_out"] = summarize(carve)
        report["rule_outcome"] = "carve_out_fallback"
    assigned = [{**r, "split": "test_extension"} for r in tier_a]
    negatives, neg_report = select_negatives(read_jsonl(work / "negative_candidates.jsonl"), c6_pool + tier_a, assigned)
    c6_neg_hashes = {n["code_sha256"] for n in iter_jsonl(vul_root / "work" / "negatives.jsonl") if "code_sha256" in n}
    fresh_negs = [
        n | {"split": FRESH_SPLIT if rule == "none" else TEST2_SPLIT}
        for n in negatives
        if n["code_sha256"] not in c6_neg_hashes
    ]
    carve_nodes = {n for r in chosen if r["split"] == TEST2_SPLIT for n in nodes(r)}
    carve_negs = [
        n | {"split": TEST2_SPLIT}
        for n in iter_jsonl(vul_root / "work" / "negatives.jsonl")
        if n.get("split") == "dev" and set(nodes(n)) & carve_nodes
    ]
    report["negatives"] = neg_report
    freeze(root, chosen, carve_negs + fresh_negs, report)
    return report


def manifest_body(rows: list[dict[str, Any]], negatives: list[dict[str, Any]]) -> dict[str, Any]:
    ids = sorted(r["id"] for r in rows)
    neg_ids = sorted(n["id"] for n in negatives)
    return {
        "records": len(ids),
        "ids_sha256": ids_sha256(ids),
        "negatives": len(neg_ids),
        "negative_ids_sha256": ids_sha256(neg_ids),
        "content_sha256": hashlib.sha256(
            "".join(sorted(f"{r['id']} {r['vulnerable_sha256']} {r.get('patched_sha256')}\n" for r in rows)).encode()
        ).hexdigest(),
        "summary": summarize(rows),
        "by_tier": {t: summarize([r for r in rows if r["tier"] == t]) for t in sorted({r["tier"] for r in rows})},
        "negatives_by_language": dict(sorted(Counter(n["language"] for n in negatives).items())),
        "ids": ids,
    }


def freeze(root: Path, rows: list[dict[str, Any]], negatives: list[dict[str, Any]], report: dict[str, Any]) -> None:
    """Write test-v2 and claim ``reports/TEST2_FROZEN.json`` exclusively; refuse a second freeze."""
    claim = root / "reports" / FROZEN_NAME
    claim.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = manifest_body(rows, negatives)
    try:
        fd = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise Round2Error(f"{claim} exists: test-v2 is frozen and is not rebuilt") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "frozen_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "rule_outcome": report["rule_outcome"],
                "manifest_sha256": hashlib.sha256(
                    json.dumps(
                        {k: body[k] for k in ("ids_sha256", "negative_ids_sha256", "content_sha256")}, sort_keys=True
                    ).encode()
                ).hexdigest(),
                "ship_rule": SHIP_RULE,
                "trained_before_freeze": False,
            },
            fh,
            indent=2,
        )
    write_private(root / "work" / "test2.jsonl", jsonl(rows))
    write_private(root / "work" / "negatives_test2.jsonl", jsonl(negatives))
    write_json(root / "reports" / "test2-manifest.json", {"schema_version": SCHEMA_VERSION, **body})
    write_json(
        root / "reports" / "test2-build.json",
        report | {"frozen": True, "manifest": {k: body[k] for k in body if k != "ids"}},
    )


# --- round-2 training split -----------------------------------------------------------------------


def in_val_slice(group: str, seed: str = VAL_SEED, percent: int = VAL_PERCENT) -> bool:
    return int(hashlib.sha256(f"{seed}\x1f{group}".encode()).hexdigest()[:8], 16) % 100 < percent


def assign_round2(records: list[dict[str, Any]]) -> dict[str, str]:
    """{record id: 'train' | 'dev'} by group (repositories and advisory ids joined), project-disjoint."""
    keys = group_keys(records)
    return {r["id"]: "dev" if in_val_slice(keys[r["id"]]) else "train" for r in records}


def node_owner(records: list[dict[str, Any]], assignment: dict[str, str]) -> dict[str, str]:
    owner: dict[str, str] = {}
    for r in records:
        for n in nodes(r):
            if owner.setdefault(n, assignment[r["id"]]) != assignment[r["id"]]:
                raise Round2Error(f"{n} appears in two splits")
    return owner


def build_split(root: Path, vul_root: Path) -> dict[str, Any]:
    work = root / "work"
    c6 = read_jsonl(vul_root / "work" / "split-v2.jsonl")
    test2 = {r["id"] for r in read_jsonl(work / "test2.jsonl")}
    extra: list[dict[str, Any]] = []  # tier-B records (27) are not used
    if not (root / "reports" / FROZEN_NAME).is_file():
        raise Round2Error("test-v2 is not frozen yet: run build-test2 first (no training before the freeze)")
    for r in extra:
        r.setdefault("license_class", "unknown")
        r.setdefault("repo_license", None)
    pool = [r | {"c6_split": r.get("split")} for r in c6 if r["id"] not in test2] + extra
    assignment = assign_round2(pool)
    owner = node_owner(pool, assignment)
    records = [r | {"split": assignment[r["id"]]} for r in pool]
    write_private(work / "split-v2.jsonl", jsonl(records))
    counts: Counter[str] = Counter()
    out = work / "negatives.jsonl.tmp"
    with out.open("w", encoding="utf-8") as fh:
        for source in (vul_root / "work" / "negatives.jsonl", work / "negatives_tier_b.jsonl"):
            if not source.is_file():
                continue
            for n in iter_jsonl(source):
                found = {owner[x] for x in nodes(n) if x in owner}
                if len(found) != 1:
                    counts["negative_dropped"] += 1
                    continue
                split = next(iter(found))
                counts[f"negative_{split}"] += 1
                fh.write(json.dumps(n | {"split": split, "c6_split": n.get("split")}, sort_keys=True) + "\n")
    out.chmod(0o600)
    out.replace(work / "negatives.jsonl")
    keep = {r["id"] for r in records}
    c6_filters = json.loads((vul_root / "reports" / "split-manifest-v2.json").read_text()).get("filters", {})
    excluded = {i for ids in c6_filters.get("excluded_ids", {}).values() for i in ids} & keep
    confirmed = {i for ids in c6_filters.get("audit_confirmed_ids", {}).values() for i in ids} & keep
    by_split = {s: sorted(r["id"] for r in records if r["split"] == s) for s in ("train", "dev")}
    filters = {
        "excluded_ids": {s: sorted(i for i in by_split[s] if i in excluded) for s in by_split},
        "audit_confirmed_ids": {s: sorted(i for i in by_split[s] if i in confirmed) for s in by_split},
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "round2-split",
        "validation": "dev = project-disjoint validation slice of the pooled C6 data and tier-B extras; used for "
        "checkpoint choice, early stopping and thresholds only",
        "seed": VAL_SEED,
        "val_percent_of_groups": VAL_PERCENT,
        "splits": {
            s: {
                "records": len(by_split[s]),
                "projects": len({r["repo"] for r in records if r["split"] == s}),
                "ids_sha256": ids_sha256(by_split[s]),
                "by_c6_split": dict(sorted(Counter(r["c6_split"] for r in records if r["split"] == s).items())),
                "by_language": dict(sorted(Counter(r["language"] for r in records if r["split"] == s).items())),
            }
            for s in by_split
        },
        "negatives": dict(sorted(counts.items())),
        "filters": filters,
    }
    write_json(root / "reports" / "split-manifest-v2.json", manifest)
    return manifest


# --- ship decision ------------------------------------------------------------------------------


def decide(report: dict[str, Any], system: str, split: str = TEST2_SPLIT, view: str = "full") -> dict[str, Any]:
    """Apply ``SHIP_RULE`` to a finished test-v2 report; the verdict and its evidence."""
    systems = report["splits"][split]["views"][view]["systems"]
    cand, rules, bow = systems[system], systems["rules"], systems["bow"]
    lo, hi = cand["ci95"]["pr_auc"]
    rules_hi = rules["ci95"]["pr_auc"][1]
    bow_hi = bow["ci95"]["pr_auc"][1]
    pair = (cand["pairwise"] or {}).get("correct")
    beats_rules, beats_bow = lo > rules_hi, lo > bow_hi
    pair_ok = pair is not None and pair >= PAIR_MIN
    return {
        "system": system,
        "pr_auc": cand["pr_auc"],
        "pr_auc_ci95": [lo, hi],
        "rules_pr_auc_ci95": rules["ci95"]["pr_auc"],
        "bow_pr_auc_ci95": bow["ci95"]["pr_auc"],
        "ci_above_rules": beats_rules,
        "ci_above_bow": beats_bow,
        "pair_correct": pair,
        "pair_min": PAIR_MIN,
        "pair_ok": pair_ok,
        "ship": bool(beats_rules and beats_bow and pair_ok),
        "rule": SHIP_RULE,
    }


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m kestrixvul.round2", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("build-test2", "split"):
        s = sub.add_parser(name)
        s.add_argument("--root", type=Path, required=True, help="the round-2 data root (outside the repository)")
        s.add_argument("--vul-root", type=Path, required=True, help="the C6 data root")
        if name == "build-test2":
            s.add_argument("--codebench-root", type=Path, required=True)
            s.add_argument("--reuse-extract", action="store_true", help="reuse work/ghsa_candidates.jsonl")
    d = sub.add_parser("decide")
    d.add_argument("--report", type=Path, required=True)
    d.add_argument("--system", required=True)
    d.add_argument("--out", type=Path)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "decide":
            verdict = decide(json.loads(args.report.read_text()), args.system)
            text = json.dumps(verdict, indent=2, sort_keys=True)
            if args.out:
                write_private(args.out, text + "\n")
            print(text)
            return 0
        root = args.root.resolve()
        repo = Path(__file__).resolve().parents[2]
        if (repo / ".git").exists() and root.is_relative_to(repo):
            print("--root must be outside the repository working tree", file=sys.stderr)
            return 2
        if args.command == "build-test2":
            report = build_test2(root, args.vul_root.resolve(), args.codebench_root.resolve(), args.reuse_extract)
            print(json.dumps({k: report[k] for k in ("tier_a", "tier_b", "rule_outcome")}, indent=2, sort_keys=True))
            return 0
        build_split(root, args.vul_root.resolve())
    except (Round2Error, OSError, KeyError, ValueError) as exc:
        print(f"round2 {args.command}: FAILED {exc}", file=sys.stderr)
        return 1
    print(f"round2 {args.command}: done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
