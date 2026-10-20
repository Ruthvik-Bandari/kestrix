# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Realistic negatives: unchanged functions from the parent snapshot of each fix commit.

Candidates come from ``ghsa_mine.extract`` (``work/negative_candidates.jsonl``): functions identical
before and after the fix in the changed files, plus every function of up to three unchanged files
sampled from the parent snapshot. A candidate is kept only when

* its normalized text is not any pool function (vulnerable or patched, exact match),
* its MinHash similarity to every vulnerable function of the pool is below ``VULN_SIMILARITY``
  (0.7; LSH with 32 bands of 4 rows, so pairs at 0.7 collide with probability above 0.999, and each
  collision is verified on the full signature),
* it is not a near duplicate (0.9, the pool's dedup rule) of a kept negative or a pool function, and
* its commit belongs to exactly one split group of ``work/split-v2.jsonl`` and its date fits that
  split (train/dev before the cutoff, test/test_extension on or after it).

At most ``PER_COMMIT`` negatives are kept per commit, in a seeded order, which bounds the
prevalence near 1 vulnerable per 20 to 50 functions. Negatives of a frozen-test group are listed
apart (``negatives.test`` in manifest v2); the frozen test ids never change.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .dedup import PERMUTATIONS, NearIndex, minhash, shingles, similarity, tokens
from .split import CUTOFF, nodes

VULN_SIMILARITY = 0.7
VULN_BANDS = 32
VULN_ROWS = PERMUTATIONS // VULN_BANDS
PER_COMMIT = 40
SEED = "kestrixvul-negatives-v1"
VULN_BUCKET_CAP = 2000


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class LooseIndex:
    """LSH tuned for a 0.7 threshold over the vulnerable functions."""

    def __init__(self) -> None:
        self.buckets: dict[tuple[int, tuple[int, ...]], list[int]] = defaultdict(list)
        self.signatures: list[tuple[int, ...]] = []

    def add(self, signature: tuple[int, ...]) -> None:
        idx = len(self.signatures)
        self.signatures.append(signature)
        for b in range(VULN_BANDS):
            bucket = self.buckets[(b, signature[b * VULN_ROWS : (b + 1) * VULN_ROWS])]
            if len(bucket) < VULN_BUCKET_CAP:
                bucket.append(idx)

    def similar(self, signature: tuple[int, ...], threshold: float = VULN_SIMILARITY) -> bool:
        seen: set[int] = set()
        for b in range(VULN_BANDS):
            for idx in self.buckets.get((b, signature[b * VULN_ROWS : (b + 1) * VULN_ROWS]), ()):
                if idx not in seen:
                    seen.add(idx)
                    if similarity(signature, self.signatures[idx]) >= threshold:
                        return True
        return False


def order(rid: str) -> str:
    return hashlib.sha256(f"{SEED}\x1f{rid}".encode()).hexdigest()


def node_splits(records: list[dict[str, Any]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in records:
        for node in nodes(r):
            out[node] = r["split"]
    return out


def split_of(candidate: dict[str, Any], owners: dict[str, str]) -> tuple[str | None, str]:
    """(split, reason): the one split the commit's repository and advisories belong to."""
    found = {owners[n] for n in nodes(candidate) if n in owners}
    if not found:
        return None, "no_split_group"
    if len(found) > 1:
        return None, "group_in_two_splits"
    split = found.pop()
    date = candidate.get("published")
    if split in {"test", "test_extension"}:
        return (split, "") if date and date >= CUTOFF else (None, "date_outside_held_out_window")
    if date and date >= CUTOFF:
        return None, "post_cutoff_commit_in_pre_cutoff_split"
    return split, ""


def index_pool(pool: list[dict[str, Any]]) -> tuple[set[str], NearIndex, LooseIndex]:
    """Exact hashes and 0.9 index of every pool function; 0.7 index of the vulnerable ones."""
    exact: set[str] = set()
    near = NearIndex()
    loose = LooseIndex()
    for r in pool:
        for role in ("vulnerable", "patched"):
            code = r.get(role)
            if not code:
                continue
            toks = tokens(code, r["language"])
            exact.add(hashlib.sha256(" ".join(toks).encode()).hexdigest())
            sig = minhash(shingles(toks))
            near.add(sig, r["id"])
            if role == "vulnerable":
                loose.add(sig)
    return exact, near, loose


def select(
    candidates: list[dict[str, Any]], pool: list[dict[str, Any]], assigned: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stats: Counter[str] = Counter()
    exact, near, loose = index_pool(pool)
    owners = node_splits(assigned)
    by_commit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in candidates:
        by_commit[c["commit"]].append(c)
    kept: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for commit in sorted(by_commit, key=order):
        group = sorted(by_commit[commit], key=lambda c: order(c["id"]))
        stats["candidates"] += len(group)
        split, reason = split_of(group[0], owners)
        if split is None:
            stats[f"dropped:{reason}"] += len(group)
            continue
        taken = 0
        for c in group:
            if taken >= PER_COMMIT:
                stats["dropped:per_commit_cap"] += 1
                continue
            if c["id"] in seen_ids:
                stats["dropped:duplicate_id"] += 1
                continue
            toks = tokens(c["code"], c["language"])
            digest = hashlib.sha256(" ".join(toks).encode()).hexdigest()
            if digest in exact:
                stats["dropped:exact_duplicate"] += 1
                continue
            sig = minhash(shingles(toks))
            if loose.similar(sig):
                stats["dropped:similar_to_vulnerable"] += 1
                continue
            if near.find(sig) is not None:
                stats["dropped:near_duplicate"] += 1
                continue
            exact.add(digest)
            near.add(sig, c["id"])
            seen_ids.add(c["id"])
            taken += 1
            stats["kept"] += 1
            kept.append(c | {"split": split, "code_sha256": digest})
    by_split: dict[str, Counter[str]] = defaultdict(Counter)
    for n in kept:
        by_split[n["split"]][n["language"]] += 1
    report = {
        "schema_version": 1,
        "label": "negative_unchanged",
        "method": {
            "source": "functions unchanged by the fix commit (changed files) and functions of up to 3 sampled "
            "unchanged files of the parent snapshot",
            "similar_to_vulnerable": f"MinHash >= {VULN_SIMILARITY} to any vulnerable pool function (LSH "
            f"{VULN_BANDS}x{VULN_ROWS}, verified)",
            "dedup": "exact normalized hash and MinHash >= 0.9 against the pool and earlier negatives",
            "per_commit_cap": PER_COMMIT,
            "seed": SEED,
        },
        "counts": dict(sorted(stats.items())),
        "kept_by_split_and_language": {s: dict(sorted(c.items())) for s, c in sorted(by_split.items())},
        "kept_by_origin": dict(sorted(Counter(n["origin"] for n in kept).items())),
    }
    return kept, report


def run(root: Path) -> dict[str, Any]:
    work = root / "work"
    pool = read_jsonl(work / "deduped.jsonl") + read_jsonl(work / "ghsa_deduped.jsonl")
    assigned = read_jsonl(work / "split-v2.jsonl")
    kept, report = select(read_jsonl(work / "negative_candidates.jsonl"), pool, assigned)
    out = work / "negatives.jsonl"
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text("".join(json.dumps(n, sort_keys=True) + "\n" for n in kept), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(out)
    return report
