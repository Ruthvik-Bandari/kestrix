# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Collection-artifact controls for the link benchmark.

PhiUSIIL's phishing and legitimate URLs were collected differently: every legitimate URL is an ``https`` host
root (no path, no query), while phishing URLs are half ``http`` and a third carry a path. Anything that reads
the scheme, the path or the length can separate the classes because of how the URLs were gathered, not
because of risk. Majestic roots add benign hosts but share the same shape. Three controls:

* ``shape_counts``: how the classes differ in scheme, path and length (counts);
* ``probe_separability``: AUC of single shape features (length, path, query, scheme, host dots, hyphens and
  digits) for phishing against PhiUSIIL benign, on the full dev set and on the matched subset;
* ``matched_ids``: the matched subset, phishing and PhiUSIIL benign URLs drawn in equal numbers from every
  (scheme, path, query, length band) cell, deterministically by seeded hash; ``finding_gaps`` compares the
  per-finding gap between the classes on the full set and on the matched subset and flags an id whose gap
  collapses as collection-driven.

The matched subset can only hold shapes both classes have (here: https host roots), so it says nothing about
path-based signals.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

import numpy as np

from kestrixmailbench.leakage import auc
from kestrixmailbench.metrics import REPS, SEED, Frame

from .common import BENIGN, PHISHING, seeded_key
from .metrics import RANK, link_cohorts, link_rank, link_table
from .sources import PHIUSIIL

LENGTH_EDGES = (20, 30, 40, 55, 75, 100, 150)
MIN_GAP = 0.02
COLLAPSE = 0.5


def length_band(length: int) -> int:
    return sum(length >= edge for edge in LENGTH_EDGES)


def cell_of(row: dict[str, Any]) -> tuple[int, int, int, int]:
    return (row["https"], row["path"], row["query"], length_band(row["len"]))


def matched_ids(rows: list[dict[str, Any]], seed: str = "kestrixlinkfile-match") -> set[str]:
    """Ids of phishing and PhiUSIIL benign rows, equal numbers per (scheme, path, query, length band) cell."""
    pools: dict[tuple[int, int, int, int], dict[str, list[str]]] = {}
    for row in rows:
        if row["source"] != PHIUSIIL:
            continue
        pools.setdefault(cell_of(row), {PHISHING: [], BENIGN: []})[row["label"]].append(row["id"])
    chosen: set[str] = set()
    for pool in pools.values():
        n = min(len(pool[PHISHING]), len(pool[BENIGN]))
        for label in (PHISHING, BENIGN):
            chosen.update(sorted(pool[label], key=lambda i: seeded_key(seed, i))[:n])
    return chosen


def shape_counts(frame: Frame) -> dict[str, Any]:
    """Class by scheme, path and length: the raw difference in collection."""
    co = link_cohorts(frame)
    out: dict[str, Any] = {}
    for name in ("phishing", "benign_phiusiil", "benign_majestic"):
        rows = [frame.rows[int(i)] for i in np.flatnonzero(co[name])]
        n = len(rows)
        if not n:
            continue
        lens = sorted(r["len"] for r in rows)
        out[name] = {
            "n": n,
            "https": round(sum(r["https"] for r in rows) / n, 4),
            "has_path": round(sum(r["path"] for r in rows) / n, 4),
            "has_query": round(sum(r["query"] for r in rows) / n, 4),
            "median_length": lens[n // 2],
            "p90_length": lens[int(0.9 * (n - 1))],
        }
    return out


PROBES: dict[str, Callable[[dict[str, Any]], float]] = {
    "length": lambda r: float(r["len"]),
    "has_path": lambda r: float(r["path"]),
    "has_query": lambda r: float(r["query"]),
    "https": lambda r: float(r["https"]),
    "host_dots": lambda r: float(r["dots"]),
    "host_hyphens": lambda r: float(r["hyph"]),
    "host_digits": lambda r: float(r["digits"]),
}


def probe_separability(frame: Frame) -> dict[str, Any]:
    """AUC of each shape feature alone, phishing against PhiUSIIL benign (0.5 means no information)."""
    co = link_cohorts(frame)
    use = np.flatnonzero(co["phishing"] | co["benign_phiusiil"])
    positive = co["phishing"][use]
    out: dict[str, Any] = {"n_phishing": int(positive.sum()), "n_benign": int((~positive).sum())}
    for name, probe in PROBES.items():
        values = np.array([probe(frame.rows[int(i)]) for i in use])
        value = auc(values, positive)
        out[name] = None if value is None else round(value, 4)
    return out


def finding_gaps(full: Frame, matched: Frame) -> dict[str, Any]:
    """Per finding id: share of phishing minus share of PhiUSIIL benign, full and matched, and a collection flag."""

    def shares(frame: Frame) -> dict[str, tuple[float, float]]:
        co = link_cohorts(frame)
        pn, bn = max(1, int(co["phishing"].sum())), max(1, int(co["benign_phiusiil"].sum()))
        ids = sorted({f[0] for r in frame.rows for f in r["findings"]})
        out = {}
        for fid in ids:
            has = np.array([any(f[0] == fid for f in r["findings"]) for r in frame.rows], dtype=bool)
            out[fid] = (float((has & co["phishing"]).sum()) / pn, float((has & co["benign_phiusiil"]).sum()) / bn)
        return out

    f_shares, m_shares = shares(full), shares(matched)
    out: dict[str, Any] = {}
    for fid in sorted(set(f_shares) | set(m_shares)):
        fp, fb = f_shares.get(fid, (0.0, 0.0))
        mp, mb = m_shares.get(fid, (0.0, 0.0))
        gap_full, gap_matched = fp - fb, mp - mb
        flagged = abs(gap_full) >= MIN_GAP and (
            abs(gap_matched) < COLLAPSE * abs(gap_full) or gap_matched * gap_full < 0
        )
        out[fid] = {
            "phishing_full": round(fp, 4),
            "benign_full": round(fb, 4),
            "phishing_matched": round(mp, 4),
            "benign_matched": round(mb, 4),
            "gap_full": round(gap_full, 4),
            "gap_matched": round(gap_matched, 4),
            "collection_driven": flagged,
        }
    return out


def leakage_report(frame: Frame, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    ids = matched_ids(frame.rows)
    matched = Frame([r for r in frame.rows if r["id"] in ids])
    rank = link_rank(matched)
    cells = Counter(cell_of(r) for r in matched.rows if r["label"] == PHISHING)
    return {
        "shape": shape_counts(frame),
        "probes_auc_full": probe_separability(frame),
        "matched": {
            "design": "equal numbers of phishing and PhiUSIIL benign URLs per (https, path, query, length band) cell",
            "length_band_edges": list(LENGTH_EDGES),
            "n_per_class": int(sum(cells.values())),
            "cells": len(cells),
            "phishing_retained_share": round(
                sum(cells.values())
                / max(1, sum(1 for r in frame.rows if r["label"] == PHISHING and r["source"] == PHIUSIIL)),
                4,
            ),
            "shape": shape_counts(matched),
            "probes_auc_matched": probe_separability(matched),
            "metrics": link_table(matched, rank, reps, seed),
            "finding_gaps": finding_gaps(frame, matched),
        },
    }


__all__ = ["RANK", "leakage_report", "matched_ids"]
