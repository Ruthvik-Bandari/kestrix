# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Learn explainable signal weights on dev only: non-negative L2 logistic regression over finding ids.

* Features: one 0/1 indicator per finding id of the chosen feature set (``content`` by default: no
  ``auth`` findings), plus optional products of documented pairs (default random_host x plain_http).
  Ids seen in fewer than ``min_support`` training messages get no weight and are listed.
* Model: ``logit = intercept + sum of weights of the findings present``, weights >= 0 so a finding can
  only raise risk. Sample weights balance the classes and, by default, every source/label cell inside a class; the L2 strength is chosen by grouped cross-validated
  log-loss. Fitted by accelerated projected gradient (FISTA), deterministic, numpy only.
* Thresholds for suspicious and malicious are picked on the out-of-fold dev scores so that the
  false-alarm rate on ham is at most the stated target (for each ham source by default).
* Everything comes from dev: the locked test split is never opened here.

Thresholds are chosen on the same out-of-fold scores they are then reported on, so the dev numbers
are optimistic for the learned scorer; the locked test is the unbiased comparison.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass
from typing import Any

import numpy as np

from kestrixvul.train import git_sha

from .common import POSITIVE_LABELS, SYNTHETIC, Layout, MailBenchError, file_sha256, now
from .metrics import (
    REPS,
    SEED,
    FeatureSet,
    Frame,
    Scoring,
    Stratum,
    baseline_scoring,
    cohorts,
    kept_findings,
    rate,
    strata_table,
    table,
)

DEFAULT_INTERACTIONS = (("mail.links.random_host", "mail.links.plain_http"),)
L2_GRID = (1e-5, 1e-4, 1e-3, 1e-2, 1e-1)
FOLDS = 5
MIN_SUPPORT = 5
FAR_SUSPICIOUS = 0.05
FAR_MALICIOUS = 0.01
MAX_ITER = 20_000
TOL = 1e-9


@dataclass(frozen=True)
class Design:
    ids: tuple[str, ...]
    interactions: tuple[tuple[str, str], ...]
    unlearned: tuple[str, ...]

    @property
    def names(self) -> list[str]:
        return [*self.ids, *(f"{a}+{b}" for a, b in self.interactions)]


def finding_sets(frame: Frame, fset: FeatureSet) -> list[frozenset[str]]:
    return [frozenset(f[0] for f in kept_findings(r, fset)) for r in frame.rows]


def make_design(sets: list[frozenset[str]], min_support: int, interactions: tuple[tuple[str, str], ...]) -> Design:
    support: Counter[str] = Counter()
    for s in sets:
        support.update(s)
    ids = tuple(sorted(i for i, c in support.items() if c >= min_support))
    unlearned = tuple(sorted(i for i, c in support.items() if c < min_support))
    usable = tuple((a, b) for a, b in interactions if a in ids and b in ids)
    return Design(ids, usable, unlearned)


def matrix(sets: list[frozenset[str]], design: Design) -> np.ndarray:
    index = {i: k for k, i in enumerate(design.ids)}
    x = np.zeros((len(sets), len(design.names)))
    for row, s in enumerate(sets):
        for fid in s:
            if fid in index:
                x[row, index[fid]] = 1.0
        for k, (a, b) in enumerate(design.interactions):
            if a in s and b in s:
                x[row, len(design.ids) + k] = 1.0
    return x


def balanced_weights(y: np.ndarray, cells: np.ndarray | None = None) -> np.ndarray:
    """Sample weights: positives and negatives carry half each. With ``cells`` (for example ``source/label``) every
    cell of a class carries an equal share of its half, so a large easy corpus cannot drown a small hard one."""
    names = np.where(y > 0, "positive", "negative") if cells is None else cells
    out = np.zeros(len(y))
    for cls in (1.0, 0.0):
        in_class = y == cls
        present = np.unique(names[in_class])
        for name in present:
            chosen = in_class & (names == name)
            out[chosen] = 0.5 / len(present) / chosen.sum()
    return out


def fit_lr(
    x: np.ndarray, y: np.ndarray, sample_weight: np.ndarray, l2: float, nonneg: bool = True
) -> tuple[np.ndarray, float]:
    """Minimize the weighted logistic loss plus ``l2/2 * |w|^2`` with ``w >= 0`` when ``nonneg``.

    Duplicate rows are merged first (exact, and makes binary features cheap). Returns (weights, intercept).
    """
    keys = np.concatenate([x, y[:, None]], axis=1)
    unique, inverse = np.unique(keys, axis=0, return_inverse=True)
    weights = np.bincount(inverse.ravel(), weights=sample_weight, minlength=len(unique))
    weights = weights / weights.sum()
    xu, yu = unique[:, :-1], unique[:, -1]
    lipschitz = 0.25 * float(weights @ (np.einsum("ij,ij->i", xu, xu) + 1.0)) + l2
    d = xu.shape[1]

    def objective(w: np.ndarray, b: float) -> float:
        z = xu @ w + b
        return float(weights @ (np.logaddexp(0.0, z) - yu * z)) + 0.5 * l2 * float(w @ w)

    w, b = np.zeros(d), 0.0
    zw, zb, t = w.copy(), b, 1.0
    best = objective(w, b)
    for _ in range(MAX_ITER):
        p = 1.0 / (1.0 + np.exp(-(xu @ zw + zb)))
        r = weights * (p - yu)
        nw = zw - (xu.T @ r + l2 * zw) / lipschitz
        if nonneg:
            nw = np.maximum(nw, 0.0)
        nb = zb - float(r.sum()) / lipschitz
        moved = math.sqrt(float(((nw - zw) ** 2).sum()) + (nb - zb) ** 2) * lipschitz
        value = objective(nw, nb)
        if value > best:  # momentum overshot: restart from the best point without momentum
            zw, zb, t = w.copy(), b, 1.0
            continue
        nt = (1.0 + math.sqrt(1.0 + 4.0 * t * t)) / 2.0
        coef = (t - 1.0) / nt
        zw, zb = nw + coef * (nw - w), nb + coef * (nb - b)
        w, b, t, best = nw, nb, nt, value
        if moved < TOL:
            break
    return w, b


def grouped_folds(group_names: list[str], k: int, sizes: dict[str, int]) -> dict[str, int]:
    """Assign whole groups to ``k`` folds: largest first, each to the currently smallest fold (deterministic)."""
    load = [0] * k
    fold: dict[str, int] = {}
    for g in sorted(group_names, key=lambda g: (-sizes[g], g)):
        target = min(range(k), key=lambda i: (load[i], i))
        fold[g] = target
        load[target] += sizes[g]
    return fold


def far_threshold(pairs: list[tuple[np.ndarray, float]]) -> float:
    """Smallest score threshold t (flag when z >= t) whose false-alarm rate is within the cap for every ham array."""
    candidates = np.unique(np.concatenate([z for z, _ in pairs])) if pairs else np.array([0.0])
    ordered = [(np.sort(z), cap) for z, cap in pairs if len(z)]
    for t in candidates:
        if all((len(z) - np.searchsorted(z, t, side="left")) / len(z) <= cap for z, cap in ordered):
            return float(t)
    return float(np.nextafter(candidates.max(), np.inf))


def verdicts(z: np.ndarray, suspicious: float, malicious: float) -> np.ndarray:
    out = np.full(len(z), "clean", dtype=object)
    out[z >= suspicious] = "suspicious"
    out[z >= malicious] = "malicious"
    return out


def model_scores(sets: list[frozenset[str]], model: dict[str, Any]) -> np.ndarray:
    weights: dict[str, float] = model["weights"]
    pairs = [(p["ids"][0], p["ids"][1], p["weight"]) for p in model["interactions"]]
    z = np.empty(len(sets))
    for k, s in enumerate(sets):
        value = model["intercept"] + sum(weights[i] for i in s if i in weights)
        value += sum(w for a, b, w in pairs if a in s and b in s)
        z[k] = value
    return z


def model_scoring(frame: Frame, model: dict[str, Any]) -> Scoring:
    fset = FeatureSet.from_json(model["feature_set"])
    z = model_scores(finding_sets(frame, fset), model)
    return Scoring(verdicts(z, model["thresholds"]["suspicious"], model["thresholds"]["malicious"]), {"z": z})


def _ham_caps(frame: Frame, mask: np.ndarray, basis: str) -> list[np.ndarray]:
    ham = mask & (frame.label == "ham")
    if basis == "pooled":
        return [np.flatnonzero(ham)]
    return [np.flatnonzero(ham & (frame.source == s)) for s in sorted({str(s) for s in frame.source[ham]})]


def thresholds_for(
    z: np.ndarray, frame: Frame, mask: np.ndarray, far_suspicious: float, far_malicious: float, basis: str
) -> tuple[float, float]:
    parts = _ham_caps(frame, mask, basis)
    suspicious = far_threshold([(z[idx], far_suspicious) for idx in parts])
    malicious = max(suspicious, far_threshold([(z[idx], far_malicious) for idx in parts]))
    return suspicious, malicious


def oof_scores(
    x: np.ndarray, y: np.ndarray, frame: Frame, folds: int, l2: float, cells: np.ndarray | None = None
) -> np.ndarray:
    sizes = Counter(frame.group_names[g] for g in frame.group)
    fold_of = grouped_folds(frame.group_names, folds, dict(sizes))
    fold = np.array([fold_of[frame.group_names[g]] for g in frame.group])
    z = np.zeros(len(y))
    for k in range(folds):
        train, test = fold != k, fold == k
        if y[train].sum() == 0 or y[train].sum() == train.sum() or not test.any():
            raise MailBenchError(f"fold {k} has only one class; too few groups for {folds}-fold grouped CV")
        w, b = fit_lr(x[train], y[train], balanced_weights(y[train], None if cells is None else cells[train]), l2)
        z[test] = x[test] @ w + b
    return z


def log_loss(z: np.ndarray, y: np.ndarray, cells: np.ndarray | None = None) -> float:
    sw = balanced_weights(y, cells)
    return float(sw @ (np.logaddexp(0.0, z) - y * z))


def learn(
    layout: Layout,
    dev_rows: list[dict[str, Any]],
    fset: FeatureSet,
    *,
    interactions: tuple[tuple[str, str], ...] = DEFAULT_INTERACTIONS,
    far_suspicious: float = FAR_SUSPICIOUS,
    far_malicious: float = FAR_MALICIOUS,
    far_basis: str = "each_source",
    balance: str = "cell",
    folds: int = FOLDS,
    grid: tuple[float, ...] = L2_GRID,
    min_support: int = MIN_SUPPORT,
    strata: list[Stratum] | None = None,
    reps: int = REPS,
    seed: int = SEED,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fit on dev, return (weights JSON, cross-validated report). Never reads the test split."""
    if any(r["split"] != "dev" for r in dev_rows):
        raise MailBenchError("learning accepts dev rows only")
    frame = Frame([r for r in dev_rows if r["source"] != SYNTHETIC])
    sets = finding_sets(frame, fset)
    design = make_design(sets, min_support, interactions)
    x = matrix(sets, design)
    y = np.isin(frame.label, POSITIVE_LABELS).astype(float)
    everything = np.ones(len(frame), dtype=bool)
    cells = (
        np.array([f"{s}/{lb}" for s, lb in zip(frame.source, frame.label, strict=True)]) if balance == "cell" else None
    )

    search: dict[str, Any] = {}
    chosen_l2, chosen_z, best = grid[0], np.zeros(0), math.inf
    for l2 in grid:
        z = oof_scores(x, y, frame, folds, l2, cells)
        loss = log_loss(z, y, cells)
        search[f"{l2:g}"] = round(loss, 6)
        if loss < best:
            chosen_l2, chosen_z, best = l2, z, loss
    suspicious, malicious = thresholds_for(chosen_z, frame, everything, far_suspicious, far_malicious, far_basis)
    w, b = fit_lr(x, y, balanced_weights(y, cells), chosen_l2)
    k = len(design.ids)
    model: dict[str, Any] = {
        "schema_version": 1,
        "kind": "kestrix-mail-weights-candidate",
        "note": "Candidate only: not wired into kestrix.mail. Score is a logit-scale sum, not a probability.",
        "feature_set": fset.to_json(),
        "score": "intercept + sum of the weights of the finding ids present + interaction weights when both ids are present",
        "intercept": round(float(b), 6),
        "weights": {i: round(float(w[n]), 6) for n, i in enumerate(design.ids)},
        "interactions": [
            {"ids": [a, c], "weight": round(float(w[k + n]), 6)} for n, (a, c) in enumerate(design.interactions)
        ],
        "thresholds": {"suspicious": round(suspicious, 6), "malicious": round(malicious, 6)},
        "targets": {"far_suspicious": far_suspicious, "far_malicious": far_malicious, "basis": far_basis},
        "l2": chosen_l2,
        "unlearned_ids": list(design.unlearned),
        "training": {**_training(layout, frame, len(design.names), folds, grid, min_support, seed), "balance": balance},
    }
    sc = Scoring(verdicts(chosen_z, suspicious, malicious), {"z": chosen_z})
    base = baseline_scoring(frame, fset)
    strata = strata or []
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": now(),
        "feature_set": fset.to_json(),
        "protocol": (
            f"{folds}-fold cross-validation grouped by split group on dev (synthetic excluded); thresholds chosen on "
            "the out-of-fold scores, so learned dev numbers are optimistic. Compare with the locked test for an unbiased result."
        ),
        "l2_search_log_loss": search,
        "n_features": len(design.names),
        "learned": table(frame, sc, reps, seed),
        "baseline": table(frame, base, reps, seed),
        "matched_false_alarm": matched(frame, chosen_z, base, far_basis, reps, seed),
        "strata_learned": strata_table(frame, sc, strata, reps, seed),
        "strata_baseline": strata_table(frame, base, strata, reps, seed),
        "in_sample_final_model": _in_sample(frame, x, w, b, suspicious, malicious),
        "weights_top": [
            {"id": n, "weight": round(float(v), 4)}
            for n, v in sorted(zip(design.names, w, strict=True), key=lambda p: -float(p[1]))[:20]
        ],
    }
    return model, report


def _training(
    layout: Layout, frame: Frame, n_features: int, folds: int, grid: tuple[float, ...], min_support: int, seed: int
) -> dict[str, Any]:
    ids_digest = hashlib.sha256("".join(sorted(r["id"] + "\n" for r in frame.rows)).encode()).hexdigest()
    dev_files = [layout.feature_file(s, "dev") for s in range(layout.shards) if layout.feature_file(s, "dev").is_file()]
    return {
        "dev_training_ids_sha256": ids_digest,
        "split_manifest_sha256": file_sha256(layout.split_manifest) if layout.split_manifest.is_file() else None,
        "dev_feature_files_sha256": hashlib.sha256("".join(file_sha256(p) for p in dev_files).encode()).hexdigest(),
        "messages": len(frame),
        "positives": int(np.isin(frame.label, POSITIVE_LABELS).sum()),
        "ham": int((frame.label == "ham").sum()),
        "groups": len(frame.group_names),
        "n_features": n_features,
        "cv_folds": folds,
        "l2_grid": list(grid),
        "min_support": min_support,
        "seed": seed,
        "code_sha": git_sha(),
        "trained_at": now(),
    }


def matched(frame: Frame, z: np.ndarray, base: Scoring, basis: str, reps: int, seed: int) -> dict[str, Any]:
    """Learned catch rate at a threshold whose false-alarm rate does not exceed the baseline's, per level."""
    co = cohorts(frame)
    everything = np.ones(len(frame), dtype=bool)
    out: dict[str, Any] = {}
    for level, base_event in (("flagged", base.flagged), ("malicious", base.malicious)):
        parts = _ham_caps(frame, everything, basis)
        caps = [(z[idx], float(base_event[idx].mean()) if len(idx) else 0.0) for idx in parts]
        threshold = far_threshold(caps)
        event = z >= threshold
        out[level] = {
            "threshold": round(threshold, 6),
            "baseline_false_alarm": {
                name: rate(frame, co[name], base_event, reps, seed)
                for name in ("ham_spamassassin", "ham_enron", "ham_all")
            },
            "learned_false_alarm": {
                name: rate(frame, co[name], event, reps, seed) for name in ("ham_spamassassin", "ham_enron", "ham_all")
            },
            "baseline_catch_rate": {
                name: rate(frame, co[name], base_event, reps, seed) for name in ("phishing", "spam", "all_positive")
            },
            "learned_catch_rate": {
                name: rate(frame, co[name], event, reps, seed) for name in ("phishing", "spam", "all_positive")
            },
        }
    return out


def _in_sample(
    frame: Frame, x: np.ndarray, w: np.ndarray, b: float, suspicious: float, malicious: float
) -> dict[str, Any]:
    z = x @ w + b
    co = cohorts(frame)
    flagged, mal = z >= suspicious, z >= malicious
    return {
        name: {
            "flagged": round(float(flagged[m].mean()), 4),
            "malicious": round(float(mal[m].mean()), 4),
            "n": int(m.sum()),
        }
        for name, m in co.items()
    }
