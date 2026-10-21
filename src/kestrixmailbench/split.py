# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, group-disjoint split into dev and a locked test set, made before any tuning.

A group is a source file (or Enron mailbox) plus year (see ``build``), so one phishing campaign, one
mailbox-year or one corpus file never has messages on both sides. Within each (source, label)
stratum, groups are visited in seeded-hash order and sent to test while the test share stays within
the target; a stratum with a single group stays whole in dev. Only ids, counts and hashes are
written to the manifest; nothing is evaluated here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .common import (
    SEED,
    SPLITS,
    TEST_FRACTION,
    Layout,
    MailBenchError,
    ids_sha256,
    now,
    read_jsonl,
    seeded_key,
    write_json,
    write_jsonl,
)

OVERSHOOT = 1.25


def assign(meta: list[dict[str, Any]], seed: str = SEED, test_fraction: float = TEST_FRACTION) -> dict[str, str]:
    """{group: split}. Groups never straddle; strata are (source, label)."""
    sizes: Counter[str] = Counter(m["group"] for m in meta)
    strata: dict[tuple[str, str], list[str]] = defaultdict(list)
    seen: dict[str, tuple[str, str]] = {}
    for m in meta:
        stratum = (m["source"], m["label"])
        if seen.setdefault(m["group"], stratum) != stratum:
            raise MailBenchError(f"group {m['group']!r} spans two strata")
    for group, stratum in seen.items():
        strata[stratum].append(group)
    out: dict[str, str] = {}
    for _, groups in sorted(strata.items()):
        budget = test_fraction * sum(sizes[g] for g in groups)
        taken = 0
        for group in sorted(groups, key=lambda g: seeded_key(seed, g)):
            test = len(groups) > 1 and taken < budget and taken + sizes[group] <= budget * OVERSHOOT
            out[group] = "test" if test else "dev"
            taken += sizes[group] if test else 0
    return out


def check_disjoint(meta: list[dict[str, Any]], split_of: dict[str, str]) -> None:
    owner: dict[str, str] = {}
    for m in meta:
        side = split_of[m["id"]]
        if owner.setdefault(m["group"], side) != side:
            raise MailBenchError(f"a group appears in both {owner[m['group']]} and {side}")


def run_split(
    layout: Layout, meta: list[dict[str, Any]], seed: str = SEED, test_fraction: float = TEST_FRACTION
) -> dict[str, Any]:
    """Write ``work/split.jsonl`` (id to split, private) and the aggregate ``reports/split-manifest.json``."""
    by_group = assign(meta, seed, test_fraction)
    split_of = {m["id"]: by_group[m["group"]] for m in meta}
    check_disjoint(meta, split_of)
    write_jsonl(layout.split, ({"id": i, "split": s} for i, s in sorted(split_of.items())))
    splits: dict[str, Any] = {}
    for side in SPLITS:
        chosen = [m for m in meta if split_of[m["id"]] == side]
        splits[side] = {
            "messages": len(chosen),
            "groups": len({m["group"] for m in chosen}),
            "by_source_label": dict(sorted(Counter(f"{m['source']}/{m['label']}" for m in chosen).items())),
            "by_year": dict(sorted(Counter(str(m["year"]) if m["year"] else "unknown" for m in chosen).items())),
            "ids_sha256": ids_sha256(m["id"] for m in chosen),
        }
    body = {
        "schema_version": 1,
        "created_at": now(),
        "seed": seed,
        "test_fraction_target": test_fraction,
        "unit": "group = source file or mailbox + year (one-year files whole)",
        "stratified_by": "source and label",
        "splits": splits,
        "ids_sha256_all": ids_sha256(split_of),
    }
    write_json(layout.split_manifest, body)
    return body


def read_split(layout: Layout) -> dict[str, str]:
    if not layout.split.is_file():
        raise MailBenchError(f"{layout.split} is missing; run split first")
    return {r["id"]: r["split"] for r in read_jsonl(layout.split)}
