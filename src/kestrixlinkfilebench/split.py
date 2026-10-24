# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, group-disjoint split into dev and a locked test set, made before any tuning.

A group is a registered domain (links) or a Govdocs thread (files), so one site or one thread never has
items on both sides. Within each stratum (the commonest source and label of a group's items), groups are
visited in seeded-hash order and sent to test while the test share stays within the target; a stratum with
a single group stays whole in dev. Synthetic items carry their side in the group name. Only ids, counts and
hashes are written to the manifest; nothing is evaluated here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from kestrixmailbench.split import OVERSHOOT, read_split

from .common import (
    SEED,
    SPLITS,
    SYNTHETIC,
    TEST_FRACTION,
    Layout,
    LinkFileBenchError,
    ids_sha256,
    now,
    seeded_key,
    write_json,
    write_jsonl,
)


def assign(meta: list[dict[str, Any]], seed: str = SEED, test_fraction: float = TEST_FRACTION) -> dict[str, str]:
    """{group: split}. A group never straddles; a synthetic group is named ``...|dev`` or ``...|test``."""
    sizes: Counter[str] = Counter()
    cells: dict[str, Counter[tuple[str, str]]] = defaultdict(Counter)
    for m in meta:
        sizes[m["group"]] += 1
        cells[m["group"]][(m["source"], m["label"])] += 1
    out: dict[str, str] = {}
    strata: dict[tuple[str, str], list[str]] = defaultdict(list)
    for group, counter in cells.items():
        if all(source == SYNTHETIC for source, _ in counter):
            side = group.rsplit("|", 1)[-1]
            if side not in SPLITS:
                raise LinkFileBenchError(f"synthetic group {group!r} does not end in |dev or |test")
            out[group] = side
            continue
        top = max(sorted(counter), key=lambda cell: counter[cell])  # commonest cell; ties by name
        strata[top].append(group)
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
            raise LinkFileBenchError(f"a group appears in both {owner[m['group']]} and {side}")


__all__ = ["assign", "check_disjoint", "read_split", "run_split"]

UNITS = {
    "link": "group = registered domain (offline approximation, coarser than the Public Suffix List)",
    "file": "group = Govdocs1 zip thread",
    "realurl": "group = sampled Majestic domain (top_domain) or full host (user-content platform pages)",
}


def run_split(
    layout: Layout, meta: list[dict[str, Any]], kind: str, seed: str = SEED, test_fraction: float = TEST_FRACTION
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
            "items": len(chosen),
            "groups": len({m["group"] for m in chosen}),
            "by_source_label": dict(sorted(Counter(f"{m['source']}/{m['label']}" for m in chosen).items())),
            "ids_sha256": ids_sha256(m["id"] for m in chosen),
        }
    body = {
        "schema_version": 1,
        "kind": kind,
        "created_at": now(),
        "seed": seed,
        "test_fraction_target": test_fraction,
        "unit": UNITS[kind],
        "stratified_by": "commonest source and label of the group",
        "splits": splits,
        "ids_sha256_all": ids_sha256(split_of),
    }
    write_json(layout.split_manifest, body)
    return body
