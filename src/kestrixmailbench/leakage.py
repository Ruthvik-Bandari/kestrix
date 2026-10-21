# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Leakage and era-assumption controls for the dev results.

Ham is 1999-2005 and phishing runs to 2025, so anything that follows the mail era (authentication
headers, mailer strings, Received chains, encodings) can separate the classes without detecting
anything. This module measures that three ways:

* ``era_table``: how often each finding id fires in era cells (Enron vs SpamAssassin ham; early vs
  late Nazario phishing); an id whose frequency differs by a large ratio and a large absolute gap is
  flagged era-sensitive;
* ``probe_separability``: how well single header-era probes (auth header present, Received count,
  parts, links) separate ham from positives, overall and inside the same-era strata, as AUC;
* the stratum tables in ``metrics.strata_table`` (reported by the dev-metrics command).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

import numpy as np

from .common import POSITIVE_LABELS, SYNTHETIC
from .metrics import Frame, Stratum, cohorts, stratum_masks

EARLY_PHISHING_MAX = 2007
LATE_PHISHING_MIN = 2015
MIN_FREQ = 0.01
RATIO = 3.0
GAP = 0.10
FLOOR = 0.005


def era_cells(frame: Frame) -> dict[str, np.ndarray]:
    co = cohorts(frame)
    return {
        "ham_enron": co["ham_enron"],
        "ham_spamassassin": co["ham_spamassassin"],
        "spam_spamassassin": co["spam"],
        "phishing_early": co["phishing"] & (frame.year > 0) & (frame.year <= EARLY_PHISHING_MAX),
        "phishing_late": co["phishing"] & (frame.year >= LATE_PHISHING_MIN),
    }


def flagged_pair(a: float, b: float) -> bool:
    hi, lo = max(a, b), min(a, b)
    return hi - lo >= GAP and hi / max(lo, FLOOR) >= RATIO


def era_table(frame: Frame) -> dict[str, Any]:
    """Per finding id: frequency in each era cell and whether the id is era-sensitive."""
    cells = era_cells(frame)
    sizes = {name: int(mask.sum()) for name, mask in cells.items()}
    counts: dict[str, Counter[str]] = {name: Counter() for name in cells}
    analyzer: dict[str, str] = {}
    for name, mask in cells.items():
        for i in np.flatnonzero(mask):
            for fid, _severity, how in frame.rows[int(i)]["findings"]:
                analyzer[fid] = how
            counts[name].update({f[0] for f in frame.rows[int(i)]["findings"]})
    rows = []
    for fid in sorted({i for c in counts.values() for i in c}):
        freq = {name: (counts[name][fid] / sizes[name] if sizes[name] else None) for name in cells}
        if max(v for v in freq.values() if v is not None) < MIN_FREQ:
            continue
        pairs = (("ham_enron", "ham_spamassassin"), ("phishing_early", "phishing_late"))
        hits = [
            f"{a} vs {b}"
            for a, b in pairs
            if freq[a] is not None and freq[b] is not None and flagged_pair(freq[a], freq[b])  # type: ignore[arg-type]
        ]
        rows.append(
            {
                "id": fid,
                "analyzer": analyzer[fid],
                "frequency": {k: (round(v, 4) if v is not None else None) for k, v in freq.items()},
                "era_sensitive": bool(hits),
                "why": hits,
            }
        )
    probes = _probe_summary(frame, cells)
    return {
        "cell_sizes": sizes,
        "rule": f"flagged when two same-class cells differ by at least {GAP} and by a factor of {RATIO}",
        "findings": rows,
        "era_sensitive_ids": [r["id"] for r in rows if r["era_sensitive"]],
        "probe_means": probes,
    }


def _probe_summary(frame: Frame, cells: dict[str, np.ndarray]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, mask in cells.items():
        idx = np.flatnonzero(mask)
        if not idx.size:
            continue
        rows = [frame.rows[int(i)] for i in idx]
        out[name] = {
            "n": len(rows),
            "share_with_auth_header": round(sum(r["auth"] > 0 for r in rows) / len(rows), 4),
            "mean_received": round(sum(r["received"] for r in rows) / len(rows), 3),
            "share_with_links": round(sum(r["counts"]["links"] > 0 for r in rows) / len(rows), 4),
            "mean_parts": round(sum(r["counts"]["parts"] for r in rows) / len(rows), 3),
        }
    return out


def auc(score: np.ndarray, positive: np.ndarray) -> float | None:
    """Mann-Whitney AUC (ties averaged): probability a positive outscores a negative."""
    n_pos = int(positive.sum())
    n_neg = int(len(score) - n_pos)
    if n_pos == 0 or n_neg == 0:
        return None
    _, inverse, counts = np.unique(score, return_inverse=True, return_counts=True)
    cumulative = np.cumsum(counts)
    ranks = ((cumulative - counts + 1) + cumulative) / 2.0
    total = ranks[inverse][positive].sum()
    return float((total - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


PROBES: dict[str, Callable[[dict[str, Any]], float]] = {
    "auth_header_present": lambda r: float(r["auth"] > 0),
    "received_count": lambda r: float(r["received"]),
    "mime_parts": lambda r: float(r["counts"]["parts"]),
    "link_count": lambda r: float(r["counts"]["links"]),
}


def probe_separability(frame: Frame, strata: list[Stratum]) -> dict[str, Any]:
    """AUC of single era probes for positives against ham: overall and inside each same-era stratum.

    0.5 means the probe says nothing; far from 0.5 (either way) means the probe alone separates the
    classes, which is leakage when the real signal should come from the message itself.
    """
    real = frame.source != SYNTHETIC
    pools: dict[str, tuple[np.ndarray, np.ndarray]] = {
        "all_dev": (real & (frame.label == "ham"), real & np.isin(frame.label, POSITIVE_LABELS))
    }
    for stratum in strata:
        pools[stratum.name] = stratum_masks(frame, stratum)
    out: dict[str, Any] = {}
    for pool, (ham, pos) in pools.items():
        use = ham | pos
        idx = np.flatnonzero(use)
        out[pool] = {"n_ham": int(ham.sum()), "n_positive": int(pos.sum())}
        for name, probe in PROBES.items():
            values = np.array([probe(frame.rows[int(i)]) for i in idx])
            out[pool][name] = None if not idx.size else _round(auc(values, pos[idx]))
    return out


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)
