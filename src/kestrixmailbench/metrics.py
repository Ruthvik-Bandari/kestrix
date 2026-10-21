# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Detection metrics for any scoring of the stored features, with grouped bootstrap intervals.

Definitions (the "flagged" decision is ``verdict`` in suspicious or malicious):

* catch rate (recall): share of phishing, spam or both that is flagged;
* false-alarm rate: share of ham that is flagged (SpamAssassin ham and Enron ham separately and pooled);
* precision: flagged positives over all flagged messages, with the corpora's own class mix, so it
  depends on how much ham each corpus holds and is not a real-world precision;
* every interval is a 95% percentile bootstrap that resamples whole split groups (source file or
  mailbox plus year), the unit that must not straddle dev and test.

A baseline scoring re-derives the verdict from the stored findings with a feature set applied (for
example without the ``auth`` analyzer), using the shipped ``kestrix.mail.analyze.verdict`` rules and
severity weights. Synthetic messages are kept out of every pooled number and reported by family.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from kestrix.mail.analyze import _WEIGHTS
from kestrix.mail.analyze import verdict as derive_verdict
from kestrix.mail.models import Finding
from kestrixvul.evaluate import bootstrap_ci

from .common import POSITIVE_LABELS, SYNTHETIC
from .sources import ENRON, SPAMASSASSIN

REPS = 1000
SEED = 0
MIN_YEAR_N = 30
MIN_GROUPS_FOR_CI = 8
TOP = 15
VERDICTS = ("malicious", "suspicious", "insufficient_evidence", "clean")
# Findings read from headers whose presence tracks the mail era more than the message.
HEADER_ERA_IDS = ("mail.sender.outdated_mailer", "mail.sender.return_path_mismatch")


@dataclass(frozen=True)
class FeatureSet:
    """Which stored findings count: all, or without some analyzers and finding ids."""

    name: str
    exclude_analyzers: tuple[str, ...] = ()
    exclude_ids: tuple[str, ...] = ()

    def keep(self, finding_id: str, analyzer: str) -> bool:
        return analyzer not in self.exclude_analyzers and finding_id not in self.exclude_ids

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "exclude_analyzers": list(self.exclude_analyzers),
            "exclude_ids": list(self.exclude_ids),
        }

    @staticmethod
    def from_json(data: dict[str, Any]) -> FeatureSet:
        return FeatureSet(data["name"], tuple(data["exclude_analyzers"]), tuple(data["exclude_ids"]))


ALL = FeatureSet("all")
CONTENT = FeatureSet("content", ("auth",))
CONTENT_STRICT = FeatureSet("content_strict", ("auth",), HEADER_ERA_IDS)
FEATURE_SETS = {fs.name: fs for fs in (ALL, CONTENT, CONTENT_STRICT)}


def kept_findings(row: dict[str, Any], fset: FeatureSet) -> list[list[str]]:
    return [f for f in row["findings"] if fset.keep(f[0], f[2])]


_VERDICT_CACHE: dict[tuple[tuple[str, ...], ...], tuple[str, int]] = {}


def restricted_verdict(findings: list[list[str]]) -> tuple[str, int]:
    """Verdict and heuristic score of ``findings`` under the shipped analyzer rules."""
    key = tuple(tuple(f) for f in findings)
    hit = _VERDICT_CACHE.get(key)
    if hit is None:
        models = [Finding(id=f[0], analyzer=f[2], severity=f[1], title="", explanation="") for f in findings]  # type: ignore[arg-type]
        hit = (derive_verdict(models), min(100, sum(_WEIGHTS[m.severity] for m in models)))
        _VERDICT_CACHE[key] = hit
    return hit


class Frame:
    """Feature rows as aligned numpy arrays, plus the group index used by the bootstrap."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.group_names = sorted({r["group"] for r in rows})
        index = {g: i for i, g in enumerate(self.group_names)}
        self.group = np.array([index[r["group"]] for r in rows], dtype=np.int64)
        self.label = np.array([r["label"] for r in rows], dtype=object)
        self.source = np.array([r["source"] for r in rows], dtype=object)
        self.subset = np.array([r["subset"] for r in rows], dtype=object)
        self.year = np.array([r["year"] if r["year"] else -1 for r in rows], dtype=np.int64)

    def __len__(self) -> int:
        return len(self.rows)


@dataclass
class Scoring:
    """One verdict per row: ``malicious``, ``suspicious``, ``insufficient_evidence`` or ``clean``."""

    verdict: np.ndarray
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def flagged(self) -> np.ndarray:
        return np.asarray((self.verdict == "malicious") | (self.verdict == "suspicious"), dtype=bool)

    @property
    def malicious(self) -> np.ndarray:
        return np.asarray(self.verdict == "malicious", dtype=bool)


def baseline_scoring(frame: Frame, fset: FeatureSet) -> Scoring:
    return Scoring(np.array([restricted_verdict(kept_findings(r, fset))[0] for r in frame.rows], dtype=object))


def cohorts(frame: Frame) -> dict[str, np.ndarray]:
    real = frame.source != SYNTHETIC
    ham = real & (frame.label == "ham")
    return {
        "phishing": real & (frame.label == "phishing"),
        "spam": real & (frame.label == "spam"),
        "all_positive": real & np.isin(frame.label, POSITIVE_LABELS),
        "ham_spamassassin": ham & (frame.source == SPAMASSASSIN),
        "ham_enron": ham & (frame.source == ENRON),
        "ham_all": ham,
    }


def ratio_entry(frame: Frame, num: np.ndarray, den: np.ndarray, reps: int, seed: int) -> dict[str, Any]:
    """Point estimate and intervals of sum(num) / sum(den) (per-group count vectors).

    ``ci95`` resamples whole groups, the honest interval; it is None below ``MIN_GROUPS_FOR_CI`` groups, where
    a group bootstrap says nothing (one group has no spread at all). ``ci95_message`` treats messages as
    independent (binomial), always exists and understates the uncertainty when messages in a group correlate.
    """
    present = np.flatnonzero(den > 0)
    if present.size == 0:
        return {"n": 0, "k": 0, "rate": None, "ci95": None, "ci95_message": None, "groups": 0}
    names = [frame.group_names[g] for g in present]

    def statistic(idx: list[int]) -> float | None:
        chosen = present[np.asarray(idx)]
        total = float(den[chosen].sum())
        return float(num[chosen].sum()) / total if total else None

    ci = bootstrap_ci(names, statistic, reps, seed) if present.size >= MIN_GROUPS_FOR_CI else None
    n, k = int(den.sum()), int(num.sum())
    draws = np.random.default_rng(seed).binomial(n, k / n, size=reps) / n
    low, high = np.percentile(draws, [2.5, 97.5])
    return {
        "n": n,
        "k": k,
        "rate": round(k / n, 6),
        "ci95": [round(ci[0], 6), round(ci[1], 6)] if ci else None,
        "ci95_message": [round(float(low), 6), round(float(high), 6)],
        "groups": int(present.size),
    }


def _counts(frame: Frame, mask: np.ndarray, event: np.ndarray | None = None) -> np.ndarray:
    weights = None if event is None else event[mask].astype(float)
    return np.bincount(frame.group[mask], weights=weights, minlength=len(frame.group_names)).astype(float)


def rate(frame: Frame, mask: np.ndarray, event: np.ndarray, reps: int = REPS, seed: int = SEED) -> dict[str, Any]:
    """Share of the rows in ``mask`` where ``event`` holds."""
    return ratio_entry(frame, _counts(frame, mask, event), _counts(frame, mask), reps, seed)


def precision(
    frame: Frame, positive: np.ndarray, event: np.ndarray, reps: int = REPS, seed: int = SEED
) -> dict[str, Any]:
    """Flagged positives over every flagged message among ``positive`` and ham."""
    ham = cohorts(frame)["ham_all"]
    true_pos = _counts(frame, positive & event)
    false_pos = _counts(frame, ham & event)
    return ratio_entry(frame, true_pos, true_pos + false_pos, reps, seed)


def table(
    frame: Frame, scoring: Scoring, reps: int = REPS, seed: int = SEED, min_year_n: int = MIN_YEAR_N
) -> dict[str, Any]:
    """Catch rates, false-alarm rates, precision, verdict shares, per source and per year, with intervals."""
    co = cohorts(frame)
    flagged, malicious = scoring.flagged, scoring.malicious
    real = frame.source != SYNTHETIC
    out: dict[str, Any] = {
        "n": {name: int(mask.sum()) for name, mask in co.items()},
        "groups": len({int(g) for g in frame.group[real]}),
        "flagged_rate": {name: rate(frame, mask, flagged, reps, seed) for name, mask in co.items()},
        "malicious_rate": {name: rate(frame, mask, malicious, reps, seed) for name, mask in co.items()},
        "verdict_share": {
            name: {v: rate(frame, mask, scoring.verdict == v, reps, seed) for v in VERDICTS}
            for name, mask in co.items()
        },
        "precision_flagged": {
            name: precision(frame, co[name], flagged, reps, seed) for name in ("phishing", "spam", "all_positive")
        },
        "precision_malicious_only": {
            name: precision(frame, co[name], malicious, reps, seed) for name in ("phishing", "spam", "all_positive")
        },
    }
    out["by_source"] = {
        f"{source}/{label}": {
            "flagged_rate": rate(frame, mask, flagged, reps, seed),
            "malicious_rate": rate(frame, mask, malicious, reps, seed),
        }
        for source, label in sorted({(s, lb) for s, lb in zip(frame.source[real], frame.label[real], strict=True)})
        for mask in [real & (frame.source == source) & (frame.label == label)]
    }
    out["by_subset"] = {
        f"{source}/{subset}/{label}": {
            "flagged_rate": rate(frame, mask, flagged, reps, seed),
            "malicious_rate": rate(frame, mask, malicious, reps, seed),
        }
        for source, subset, label in sorted(
            {(s, ss, lb) for s, ss, lb in zip(frame.source[real], frame.subset[real], frame.label[real], strict=True)}
        )
        for mask in [real & (frame.source == source) & (frame.subset == subset) & (frame.label == label)]
    }
    by_year: dict[str, Any] = {}
    for name in ("phishing", "spam", "ham_all"):
        by_year[name] = {}
        for year in sorted({int(y) for y in frame.year[co[name]]}):
            mask = co[name] & (frame.year == year)
            if mask.sum() >= min_year_n:
                by_year[name]["unknown" if year < 0 else str(year)] = {
                    "flagged_rate": rate(frame, mask, flagged, reps, seed),
                    "malicious_rate": rate(frame, mask, malicious, reps, seed),
                }
    out["by_year"] = by_year
    return out


@dataclass(frozen=True)
class Stratum:
    """A same-era comparison: ham in one year window against positives in another (sources optional)."""

    name: str
    ham_years: tuple[int, int]
    pos_years: tuple[int, int]
    ham_sources: tuple[str, ...] | None = None
    pos_sources: tuple[str, ...] | None = None


def default_strata(
    ham_years: tuple[int, int] = (2002, 2005), pos_years: tuple[int, int] = (2005, 2007)
) -> list[Stratum]:
    return [
        Stratum("same_corpus_spamassassin_2002_2005", (2002, 2005), (2002, 2005), (SPAMASSASSIN,), (SPAMASSASSIN,)),
        Stratum(f"ham_{ham_years[0]}_{ham_years[1]}_vs_positives_{pos_years[0]}_{pos_years[1]}", ham_years, pos_years),
    ]


def stratum_masks(frame: Frame, stratum: Stratum) -> tuple[np.ndarray, np.ndarray]:
    real = frame.source != SYNTHETIC
    ham = real & (frame.label == "ham") & (frame.year >= stratum.ham_years[0]) & (frame.year <= stratum.ham_years[1])
    pos = (
        real
        & np.isin(frame.label, POSITIVE_LABELS)
        & (frame.year >= stratum.pos_years[0])
        & (frame.year <= stratum.pos_years[1])
    )
    if stratum.ham_sources:
        ham &= np.isin(frame.source, stratum.ham_sources)
    if stratum.pos_sources:
        pos &= np.isin(frame.source, stratum.pos_sources)
    return ham, pos


def strata_table(
    frame: Frame, scoring: Scoring, strata: list[Stratum], reps: int = REPS, seed: int = SEED
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for stratum in strata:
        ham, pos = stratum_masks(frame, stratum)
        entry: dict[str, Any] = {
            "ham_years": list(stratum.ham_years),
            "positive_years": list(stratum.pos_years),
            "n_ham": int(ham.sum()),
            "n_positive": int(pos.sum()),
            "positives_by_label": {
                label: int((pos & (frame.label == label)).sum())
                for label in POSITIVE_LABELS
                if (pos & (frame.label == label)).any()
            },
        }
        if ham.any() and pos.any():
            entry["catch_rate_flagged"] = rate(frame, pos, scoring.flagged, reps, seed)
            entry["catch_rate_malicious"] = rate(frame, pos, scoring.malicious, reps, seed)
            entry["false_alarm_flagged"] = rate(frame, ham, scoring.flagged, reps, seed)
            entry["false_alarm_malicious"] = rate(frame, ham, scoring.malicious, reps, seed)
            tp, fp = _counts(frame, pos & scoring.flagged), _counts(frame, ham & scoring.flagged)
            entry["precision_flagged"] = ratio_entry(frame, tp, tp + fp, reps, seed)
        out[stratum.name] = entry
    return out


def _top(counter: Counter[str], n: int, top: int = TOP) -> list[dict[str, Any]]:
    return [{"id": i, "messages": c, "share": round(c / n, 4)} for i, c in counter.most_common(top)] if n else []


def causes(frame: Frame, fset: FeatureSet, scoring: Scoring, top: int = TOP) -> dict[str, Any]:
    """Why the baseline fails: finding ids among missed positives and among false alarms on ham."""
    co = cohorts(frame)
    flagged = scoring.flagged
    out: dict[str, Any] = {"missed": {}, "false_alarms": {}}
    for name in ("phishing", "spam"):
        idx = np.flatnonzero(co[name] & ~flagged)
        ids: Counter[str] = Counter()
        empty = 0
        for i in idx:
            found = {f[0] for f in kept_findings(frame.rows[i], fset)}
            ids.update(found)
            empty += not found
        total = int(co[name].sum())
        out["missed"][name] = {
            "cohort_size": total,
            "missed": len(idx),
            "miss_rate": round(len(idx) / total, 4) if total else None,
            "with_no_finding": empty,
            "ids_among_missed": _top(ids, len(idx), top),
        }
    for name in ("ham_spamassassin", "ham_enron"):
        idx = np.flatnonzero(co[name] & flagged)
        ids = Counter()
        for i in idx:
            ids.update({f[0] for f in kept_findings(frame.rows[i], fset) if f[1] in ("medium", "high")})
        total = int(co[name].sum())
        out["false_alarms"][name] = {
            "cohort_size": total,
            "flagged": len(idx),
            "false_alarm_rate": round(len(idx) / total, 4) if total else None,
            "medium_or_high_ids_among_flagged": _top(ids, len(idx), top),
        }
    return out


def synthetic_table(frame: Frame, scoring: Scoring) -> dict[str, Any]:
    """Per synthetic family: size, flagged and malicious counts (no interval: the templates are fixed)."""
    out: dict[str, Any] = {}
    mask = frame.source == SYNTHETIC
    for family in sorted({str(s) for s in frame.subset[mask]}):
        sel = mask & (frame.subset == family)
        out[family] = {
            "label": str(frame.label[sel][0]),
            "n": int(sel.sum()),
            "flagged": int((scoring.flagged & sel).sum()),
            "malicious": int((scoring.malicious & sel).sum()),
        }
    return out
