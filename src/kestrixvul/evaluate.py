# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Evaluation of the learned vulnerability ranker and its baselines (ADR 0005, slice C6).

``python -m kestrixvul.evaluate --root VUL [--teacher-run ID ...] [--student-run ID] [--zero-shot]``
scores **dev** (all dev negatives by default, so at the manifest's realistic prevalence).
``--split test --locked`` adds ``test`` and ``test_extension``: it first claims
``reports/LOCKED_EVAL.json`` (exclusive create) and refuses when the marker exists, so the held-out
splits are evaluated once. Thresholds and Platt calibration always come from dev.

Systems: the teacher runs, zero-shot Qwen2.5-Coder-7B-Instruct (the teacher's scorer without
adapters), the student (fp32 on the GPU for the metrics; int8 and fp32 CPU latency, size and int8
agreement measured on a dev sample), and the baselines:

* ``rules``: kestrix-scan on the function text alone (Python dedented); a function with at least one
  finding is positive (fixed threshold 1, the engine's own decision); the score is the finding
  count, a heuristic;
* ``bow``: logistic regression (SGD, hashed token unigrams and bigrams) trained on the train split;
* ``length``: number of non-blank lines (heuristic); ``random``: a seeded uniform score.

Metrics (plan, "Evaluation protocol"), per split and per view (``full``; ``filtered``, without the
audit strata below 0.80 accuracy; on dev also ``audit_confirmed``, positives limited to the records
the audit confirmed): PR-AUC; precision, recall and F1 at the dev threshold (best dev F1); macro
precision@k and recall@k per repository; VD-S (miss rate at FPR <= 0.5%, 1%, 5%); pairwise outcomes
on vulnerable/patched pairs; CWE top-1/top-3 on true positives; ECE (10 bins) raw and after Platt;
rules plus model against rules alone; 95% bootstrap intervals resampled by repository.
Scores of probability systems are logits; heuristic scores are never reported as probabilities.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import random
import re
import sys
import textwrap
import time
import zlib
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .train import (
    DATA_SEED,
    HELD_OUT,
    STUDENT_REPO,
    STUDENT_REVISION,
    TEACHER_REPO,
    TEACHER_REVISION,
    DataError,
    TeacherConfig,
    assemble,
    examples_from,
    file_sha256,
    git_sha,
    manifest_path,
    negatives_path,
    normalize_cwe,
    read_filters,
    seeded_key,
    stream_rows,
    subsample,
    write_json,
    write_jsonl,
)

FPR_CAPS = (0.005, 0.01, 0.05)
KS = (1, 5, 10)
LOCK_NAME = "LOCKED_EVAL.json"


class EvalError(RuntimeError):
    pass


class LockedEvalError(EvalError):
    """The one-time locked test evaluation was already claimed."""


# --- metrics (pure) -------------------------------------------------------------------------


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


def _groups_desc(scores: list[float], labels: list[int]) -> list[tuple[float, int, int]]:
    """(score, positives, negatives) per distinct score, highest first."""
    by: dict[float, list[int]] = defaultdict(lambda: [0, 0])
    for s, y in zip(scores, labels, strict=True):
        by[s][0 if y else 1] += 1
    return [(s, by[s][0], by[s][1]) for s in sorted(by, reverse=True)]


def average_precision(scores: list[float], labels: list[int]) -> float | None:
    """Area under the precision-recall curve as the step sum over distinct thresholds (ties together)."""
    pos = sum(labels)
    if pos == 0:
        return None
    tp = fp = 0
    ap = prev_recall = 0.0
    for _, p, n in _groups_desc(scores, labels):
        tp, fp = tp + p, fp + n
        recall = tp / pos
        ap += (recall - prev_recall) * tp / (tp + fp)
        prev_recall = recall
    return ap


def confusion_at(scores: list[float], labels: list[int], threshold: float) -> dict[str, Any]:
    tp = sum(1 for s, y in zip(scores, labels, strict=True) if s >= threshold and y)
    fp = sum(1 for s, y in zip(scores, labels, strict=True) if s >= threshold and not y)
    fn = sum(labels) - tp
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def best_threshold(scores: list[float], labels: list[int]) -> float | None:
    """The score threshold (predict >= t) with the best F1; the highest such threshold on ties."""
    pos = sum(labels)
    if pos == 0:
        return None
    best, best_f1, tp, fp = None, -1.0, 0, 0
    for s, p, n in _groups_desc(scores, labels):
        tp, fp = tp + p, fp + n
        f1 = 2 * tp / (tp + fp + pos)
        if f1 > best_f1:
            best, best_f1 = s, f1
    return best


def fnr_at_fpr(scores: list[float], labels: list[int], cap: float) -> dict[str, Any] | None:
    """VD-S: the miss rate at the lowest threshold whose false-positive rate is at most ``cap``."""
    pos, neg = sum(labels), len(labels) - sum(labels)
    if not pos or not neg:
        return None
    tp = fp = 0
    chosen: dict[str, Any] = {"fnr": 1.0, "fpr": 0.0, "threshold": None}
    for s, p, n in _groups_desc(scores, labels):
        tp, fp = tp + p, fp + n
        if fp / neg > cap:
            break
        chosen = {"fnr": 1 - tp / pos, "fpr": fp / neg, "threshold": s}
    return chosen


def at_k_per_group(
    scores: list[float], labels: list[int], groups: list[str], ks: tuple[int, ...] = KS
) -> dict[str, Any]:
    """Macro precision@k and recall@k over the groups (repositories) holding at least one positive."""
    members: dict[str, list[int]] = defaultdict(list)
    for i, g in enumerate(groups):
        members[g].append(i)
    ranked = {
        g: sorted(idx, key=lambda i: (-scores[i], i)) for g, idx in members.items() if any(labels[i] for i in idx)
    }
    out: dict[str, Any] = {}
    for k in ks:
        if not ranked:
            out[str(k)] = None
            continue
        prec, rec = [], []
        for idx in ranked.values():
            hits = sum(labels[i] for i in idx[:k])
            prec.append(hits / min(k, len(idx)))
            rec.append(hits / sum(labels[i] for i in idx))
        out[str(k)] = {"precision": sum(prec) / len(prec), "recall": sum(rec) / len(rec), "repos": len(ranked)}
    return out


def pairwise(pairs: list[tuple[float, float]], threshold: float) -> dict[str, Any] | None:
    """Vulnerable/patched pair outcomes at a threshold, and how often the vulnerable one scores higher."""
    if not pairs:
        return None
    counts: Counter[str] = Counter()
    higher = 0.0
    for v, p in pairs:
        kind = {(True, False): "correct", (True, True): "both_vulnerable", (False, False): "both_benign"}
        counts[kind.get((v >= threshold, p >= threshold), "reversed")] += 1
        higher += 1.0 if v > p else 0.5 if v == p else 0.0
    n = len(pairs)
    shares = {k: counts[k] / n for k in ("correct", "both_vulnerable", "both_benign", "reversed")}
    return {"n": n, **shares, "vulnerable_scores_higher": higher / n}


def cwe_topk(rows: list[tuple[set[str], tuple[str, ...]]], ks: tuple[int, ...] = (1, 3)) -> dict[str, Any] | None:
    """Share of rows whose gold CWE set meets the top-k predictions."""
    if not rows:
        return None
    out: dict[str, Any] = {"n": len(rows)}
    for k in ks:
        out[f"top{k}"] = sum(1 for gold, preds in rows if gold & set(preds[:k])) / len(rows)
    return out


def ece(probs: list[float], labels: list[int], bins: int = 10) -> float | None:
    if not probs:
        return None
    sums: dict[int, list[float]] = defaultdict(lambda: [0.0, 0.0, 0.0])
    for p, y in zip(probs, labels, strict=True):
        b = sums[min(int(p * bins), bins - 1)]
        b[0] += 1
        b[1] += p
        b[2] += y
    return sum(abs(s[1] - s[2]) for s in sums.values()) / len(probs)


def platt_fit(scores: list[float], labels: list[int], iterations: int = 100) -> tuple[float, float]:
    """(a, b) minimizing log loss of sigmoid(a * score + b) with Platt's smoothed targets (Newton's method)."""
    pos = sum(labels)
    neg = len(labels) - pos
    hi, lo = (pos + 1) / (pos + 2), 1 / (neg + 2)
    targets = [hi if y else lo for y in labels]
    a, b = 1.0, 0.0
    for _ in range(iterations):
        gaa = gab = gbb = ga = gb = 0.0
        for s, t in zip(scores, targets, strict=True):
            p = sigmoid(a * s + b)
            w = p * (1 - p)
            ga += (p - t) * s
            gb += p - t
            gaa += w * s * s
            gab += w * s
            gbb += w
        gaa += 1e-9
        gbb += 1e-9
        det = gaa * gbb - gab * gab
        if det <= 0:
            break
        da, db = (gbb * ga - gab * gb) / det, (gaa * gb - gab * ga) / det
        a, b = a - da, b - db
        if abs(da) < 1e-10 and abs(db) < 1e-10:
            break
    return a, b


def quantile(sorted_values: list[float], q: float) -> float:
    pos = q * (len(sorted_values) - 1)
    lo = math.floor(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def bootstrap_ci(
    groups: list[str], statistic: Callable[[list[int]], float | None], n: int, seed: int
) -> tuple[float, float] | None:
    """95% percentile interval of ``statistic`` over resamples of whole groups (with replacement)."""
    if n <= 0 or not groups:
        return None
    members: dict[str, list[int]] = defaultdict(list)
    for i, g in enumerate(groups):
        members[g].append(i)
    keys = sorted(members)
    rng = random.Random(seed)
    values = []
    for _ in range(n):
        idx = [i for _ in keys for i in members[rng.choice(keys)]]
        v = statistic(idx)
        if v is not None:
            values.append(v)
    if not values:
        return None
    values.sort()
    return quantile(values, 0.025), quantile(values, 0.975)


# --- the locked test ------------------------------------------------------------------------


@dataclass(frozen=True)
class LockedClaim:
    path: Path


def claim_locked(root: Path, info: dict[str, Any]) -> LockedClaim:
    """Create ``reports/LOCKED_EVAL.json`` exclusively, or refuse: the held-out splits are evaluated once."""
    path = root / "reports" / LOCK_NAME
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            prev = json.loads(path.read_text())
        except (OSError, ValueError):
            prev = {}
        raise LockedEvalError(
            f"the locked test evaluation already ran (started {prev.get('started')}, name {prev.get('name')}); "
            f"it runs once per model version. {path} records it."
        ) from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"started": datetime.now(timezone.utc).isoformat(timespec="seconds"), **info}, fh, indent=2)
    return LockedClaim(path)


def finish_claim(claim: LockedClaim, report: Path) -> None:
    body = json.loads(claim.path.read_text())
    body |= {
        "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "report": report.name,
        "report_sha256": file_sha256(report),
    }
    write_json(claim.path, body)


def read_held_out(root: Path, claim: LockedClaim) -> dict[str, list[dict[str, Any]]]:
    """``test`` and ``test_extension`` examples (all their negatives); needs a claimed lock."""
    if not isinstance(claim, LockedClaim) or not claim.path.is_file():
        raise LockedEvalError("held-out splits are read only under a claimed LOCKED_EVAL.json")
    records = list(stream_rows(manifest_path(root), HELD_OUT))
    negatives = list(stream_rows(negatives_path(root), HELD_OUT))
    out = {}
    for split in sorted(HELD_OUT):
        recs = [r for r in records if r["split"] == split]
        if recs:
            out[split] = examples_from(recs, [n for n in negatives if n["split"] == split], neg_ratio=None)
    return out


# --- systems --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Scored:
    score: float
    cwes: tuple[str, ...] = ()


@dataclass
class System:
    name: str
    kind: str  # "probability" (scores are logits) or "heuristic"
    scored: dict[str, list[Scored]]
    fixed_threshold: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def rule_system(splits: dict[str, list[dict[str, Any]]]) -> System:
    from kestrix_scan.analyze import PYTHON_SUFFIXES, scan_text
    from kestrix_scan.js_rules import JS_SUFFIXES
    from kestrix_scan.walk import Candidate

    default = {"python": ".py", "javascript": ".js", "typescript": ".ts"}
    skipped: Counter[str] = Counter()
    scored: dict[str, list[Scored]] = {}
    for split, examples in splits.items():
        rows = []
        for e in examples:
            suffix = Path(e["path"]).suffix.lower()
            if suffix not in PYTHON_SUFFIXES | JS_SUFFIXES:
                suffix = default[e["language"]]
            text = textwrap.dedent(e["code"]) if suffix in PYTHON_SUFFIXES else e["code"]
            name = f"function{suffix}"
            findings, _, _, skip = scan_text(text, Candidate(path=Path("/kestrix-eval") / name, rel=name))
            if skip is not None:
                skipped[split] += 1
            cwes = Counter(c for c in (normalize_cwe(f.cwe) for f in findings) if c)
            rows.append(Scored(float(len(findings)), tuple(c for c, _ in cwes.most_common())))
        scored[split] = rows
    return System("rules", "heuristic", scored, fixed_threshold=1.0, extra={"unparsed_functions": dict(skipped)})


TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]")


def bow_features(code: str, dim: int) -> list[int]:
    toks = TOKEN.findall(code)[:5000]
    grams = toks + [f"{a} {b}" for a, b in itertools.pairwise(toks)]
    return sorted({zlib.crc32(g.encode()) % dim for g in grams})


class BagOfWords:
    """Logistic regression on L2-normalized binary hashed features, plain SGD with a decaying rate."""

    def __init__(self, dim: int = 1 << 18, epochs: int = 5, rate: float = 0.5, seed: int = 0) -> None:
        self.dim, self.epochs, self.rate, self.seed = dim, epochs, rate, seed
        self.weights = [0.0] * dim
        self.bias = 0.0

    def logit(self, feats: list[int]) -> float:
        if not feats:
            return self.bias
        return self.bias + sum(self.weights[j] for j in feats) / math.sqrt(len(feats))

    def fit(self, codes: list[str], labels: list[int]) -> BagOfWords:
        feats = [bow_features(c, self.dim) for c in codes]
        rng = random.Random(self.seed)
        order = list(range(len(feats)))
        for epoch in range(self.epochs):
            rng.shuffle(order)
            rate = self.rate / (1 + epoch)
            for i in order:
                g = rate * (sigmoid(self.logit(feats[i])) - labels[i])
                self.bias -= g
                if feats[i]:
                    step = g / math.sqrt(len(feats[i]))
                    for j in feats[i]:
                        self.weights[j] -= step
        return self

    def score(self, code: str) -> float:
        return self.logit(bow_features(code, self.dim))


def baseline_systems(
    root: Path, splits: dict[str, list[dict[str, Any]]], seed: int, bow_neg_ratio: float
) -> list[System]:
    train = assemble(root, "train", neg_ratio=bow_neg_ratio)
    bow = BagOfWords(seed=seed).fit([e["code"] for e in train], [e["label"] for e in train])
    bow_scored = {s: [Scored(bow.score(e["code"])) for e in ex] for s, ex in splits.items()}
    lengths = {
        s: [Scored(float(sum(1 for ln in e["code"].splitlines() if ln.strip()))) for e in ex]
        for s, ex in splits.items()
    }
    rand = {
        s: [Scored(int(seeded_key(f"random-{seed}", e["id"])[:12], 16) / 16**12) for e in ex]
        for s, ex in splits.items()
    }
    return [
        rule_system(splits),
        System("bow", "probability", bow_scored, extra={"train_examples": len(train), "neg_ratio": bow_neg_ratio}),
        System("length", "heuristic", lengths),
        System("random", "heuristic", rand),
    ]


def _run_meta(root: Path, run_id: str, kind: str) -> tuple[Path, dict[str, Any]]:
    run = root / "runs" / run_id
    try:
        meta: dict[str, Any] = json.loads((run / "run.json").read_text())
    except OSError as exc:
        raise EvalError(f"run {run_id}: {exc}") from None
    if meta.get("kind") != kind or meta.get("status") != "done":
        raise EvalError(f"run {run_id} is not a finished {kind} run")
    return run, meta


def teacher_systems(
    root: Path, models: Path, splits: dict[str, list[dict[str, Any]]], runs: list[str], zero_shot: bool, batch: int
) -> list[System]:
    import torch

    from .train import load_teacher, score_teacher, snapshot_dir

    metas = [_run_meta(root, r, "teacher") for r in runs]
    cfg = metas[0][1]["config"] if metas else {}
    max_tokens = cfg.get("max_tokens", TeacherConfig.max_tokens)
    context = cfg.get("context_chars", TeacherConfig.context_chars)
    base, tokenizer = load_teacher(snapshot_dir(models, TEACHER_REPO, TEACHER_REVISION), None)
    out = []

    def scored(model: Any, head: Any, vocab: list[str]) -> dict[str, list[Scored]]:
        return {
            s: [
                Scored(r["logit"], tuple(r["cwes"]))
                for r in score_teacher(model, tokenizer, head, vocab, ex, max_tokens, context, batch)
            ]
            for s, ex in splits.items()
        }

    if zero_shot:
        out.append(System("zero_shot_qwen7b", "probability", scored(base, None, []), extra={"cwe": "not produced"}))
    model: Any = None
    for run, meta in metas:
        if model is None:
            from peft import PeftModel

            model = PeftModel.from_pretrained(base, run / "best", adapter_name=run.name, is_trainable=False)
        else:
            model.load_adapter(run / "best", adapter_name=run.name, is_trainable=False)
        model.set_adapter(run.name)
        vocab = meta["cwe_vocab"]
        head = torch.nn.Linear(base.config.hidden_size, len(vocab))
        head.load_state_dict(torch.load(run / "best" / "cwe_head.pt", weights_only=True, map_location="cpu"))
        head.to(base.lm_head.weight.device)
        out.append(
            System(f"teacher:{run.name}", "probability", scored(model, head, vocab), extra={"best": meta["best"]})
        )
    return out


def _timed(
    model: Any, tokenizer: Any, examples: list[dict[str, Any]], max_tokens: int
) -> tuple[list[float], list[float]]:
    """(milliseconds, probabilities) per example, batch 1 on the CPU."""
    import torch

    from .train import _student_batch

    times, probs = [], []
    cpu = torch.device("cpu")
    with torch.no_grad():
        for e in examples[:5]:
            model(*_student_batch(tokenizer, [e], max_tokens, cpu))
        for e in examples:
            ids, mask = _student_batch(tokenizer, [e], max_tokens, cpu)
            t0 = time.perf_counter()
            logit, _ = model(ids, mask)
            times.append((time.perf_counter() - t0) * 1000)
            probs.append(sigmoid(float(logit[0])))
    return times, probs


def student_system(
    root: Path, models: Path, splits: dict[str, list[dict[str, Any]]], run_id: str, latency_n: int
) -> System:
    import torch

    from .train import load_student, score_student, snapshot_dir

    run, meta = _run_meta(root, run_id, "student")
    snapshot = snapshot_dir(models, STUDENT_REPO, STUDENT_REVISION)
    vocab, max_tokens = meta["cwe_vocab"], meta["config"]["max_tokens"]
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model, tokenizer = load_student(run, snapshot, int8=False)
    model.to(device)
    scored = {
        s: [
            Scored(r["logit"], tuple(r["cwes"]))
            for r in score_student(model, tokenizer, vocab, ex, max_tokens, 64, device)
        ]
        for s, ex in splits.items()
    }
    threads = int(os.environ.get("SLURM_CPUS_PER_TASK", "4"))
    torch.set_num_threads(threads)
    sample = subsample(splits["dev"], latency_n, seed="latency")
    int8, _ = load_student(run, snapshot, int8=True)
    fp32, _ = load_student(run, snapshot, int8=False)
    t8, p8 = _timed(int8, tokenizer, sample, max_tokens)
    t32, p32 = _timed(fp32, tokenizer, sample, max_tokens)
    diffs = [abs(a - b) for a, b in zip(p8, p32, strict=True)]

    def ms(values: list[float]) -> dict[str, float] | None:
        if not values:
            return None
        v = sorted(values)
        return {"median": round(quantile(v, 0.5), 2), "p95": round(quantile(v, 0.95), 2)}

    deployment = {
        "cpu_threads": threads,
        "sample": len(sample),
        "int8_ms": ms(t8),
        "fp32_ms": ms(t32),
        "int8_vs_fp32_prob_abs_diff": {"max": max(diffs), "mean": sum(diffs) / len(diffs)} if diffs else None,
        "bytes": {name: (run / name).stat().st_size for name in ("student_fp32.pt", "student_int8.pt")},
        "max_tokens": max_tokens,
        "metrics_from": "fp32 weights on the GPU (bf16 autocast)",
    }
    return System(f"student:{run_id}", "probability", scored, extra={"best": meta["best"], "deployment": deployment})


# --- report ---------------------------------------------------------------------------------


def views(split: str, examples: list[dict[str, Any]], filters: dict[str, Any]) -> dict[str, list[int] | str]:
    out: dict[str, list[int] | str] = {"full": list(range(len(examples)))}
    excluded = set(filters.get("excluded_ids", {}).get(split, []))
    out["filtered"] = [i for i, e in enumerate(examples) if e["record_id"] not in excluded]
    if split == "dev":
        confirmed = set(filters.get("audit_confirmed_ids", {}).get("dev", []))
        if confirmed:
            out["audit_confirmed"] = [
                i for i, e in enumerate(examples) if e["role"] == "negative" or e["record_id"] in confirmed
            ]
        else:
            out["audit_confirmed"] = "unavailable: no audit-confirmed dev ids in reports/split-manifest-v2.json yet"
    return out


def _pairs(examples: list[dict[str, Any]], idx: list[int]) -> list[tuple[int, int]]:
    by: dict[str, dict[str, int]] = defaultdict(dict)
    for j, i in enumerate(idx):
        if examples[i]["role"] in {"vulnerable", "patched"}:
            by[examples[i]["record_id"]][examples[i]["role"]] = j
    return [(d["vulnerable"], d["patched"]) for d in by.values() if len(d) == 2]


def system_metrics(
    examples: list[dict[str, Any]],
    idx: list[int],
    system: System,
    split: str,
    threshold: float | None,
    platt: tuple[float, float] | None,
    n_boot: int,
    seed: int,
) -> dict[str, Any]:
    scores = [system.scored[split][i].score for i in idx]
    labels = [examples[i]["label"] for i in idx]
    groups = [examples[i]["repo"] for i in idx]
    thr = math.inf if threshold is None else threshold

    def sub(j: list[int]) -> tuple[list[float], list[int]]:
        return [scores[k] for k in j], [labels[k] for k in j]

    def ap(j: list[int]) -> float | None:
        return average_precision(*sub(j))

    def f1(j: list[int]) -> float | None:
        value: float | None = confusion_at(*sub(j), thr)["f1"]
        return value

    def miss(j: list[int]) -> float | None:
        r = fnr_at_fpr(*sub(j), 0.01)
        return None if r is None else float(r["fnr"])

    tps = [
        ({*examples[i]["cwes"]}, system.scored[split][i].cwes)
        for i in idx
        if examples[i]["label"] and examples[i]["cwes"] and system.scored[split][i].score >= thr
    ]
    has_cwe = any(s.cwes for s in system.scored[split])
    calibration: dict[str, Any] | None = None
    if system.kind == "probability":
        calibration = {"raw": ece([sigmoid(s) for s in scores], labels)}
        if platt is not None:
            a, b = platt
            calibration["platt"] = ece([sigmoid(a * s + b) for s in scores], labels)
            calibration["platt_fit_on"] = "dev (in-sample for the dev report)"
    return {
        "n": len(idx),
        "positives": sum(labels),
        "prevalence": sum(labels) / len(idx) if idx else None,
        "score_kind": "logit" if system.kind == "probability" else "heuristic score (not a probability)",
        "pr_auc": average_precision(scores, labels),
        "threshold": threshold,
        "at_threshold": confusion_at(scores, labels, thr),
        "per_repo_at_k": at_k_per_group(scores, labels, groups),
        "vd_s": {str(c): fnr_at_fpr(scores, labels, c) for c in FPR_CAPS},
        "pairwise": pairwise([(scores[v], scores[p]) for v, p in _pairs(examples, idx)], thr),
        "cwe_on_true_positives": cwe_topk(tps) if has_cwe else None,
        "ece": calibration,
        "ci95": {
            "pr_auc": bootstrap_ci(groups, ap, n_boot, seed),
            "f1": bootstrap_ci(groups, f1, n_boot, seed),
            "fnr_at_fpr_0.01": bootstrap_ci(groups, miss, n_boot, seed),
        },
    }


def _pr(flags: list[bool], labels: list[int]) -> tuple[float | None, float | None]:
    tp = sum(1 for f, y in zip(flags, labels, strict=True) if f and y)
    flagged, pos = sum(flags), sum(labels)
    return (tp / flagged if flagged else None), (tp / pos if pos else None)


def rules_gain(
    examples: list[dict[str, Any]], idx: list[int], rules: list[bool], model: list[bool], n_boot: int, seed: int
) -> dict[str, Any]:
    """Rules alone against rules OR model (union) and rules AND model (the model filters rule hits)."""
    labels = [examples[i]["label"] for i in idx]
    r = [rules[i] for i in idx]
    m = [model[i] for i in idx]
    union = [a or b for a, b in zip(r, m, strict=True)]
    inter = [a and b for a, b in zip(r, m, strict=True)]

    def delta(combined: list[bool]) -> Callable[[list[int]], float | None]:
        def stat(j: list[int]) -> float | None:
            y = [labels[k] for k in j]
            base, comb = _pr([r[k] for k in j], y)[0], _pr([combined[k] for k in j], y)[0]
            return None if base is None or comb is None else comb - base

        return stat

    groups = [examples[i]["repo"] for i in idx]
    out: dict[str, Any] = {}
    p_rules, rec_rules = _pr(r, labels)
    out["rules"] = {"precision": p_rules, "recall": rec_rules, "flagged": sum(r)}
    for name, combined in (("union", union), ("intersection", inter)):
        p, rec = _pr(combined, labels)
        out[name] = {
            "precision": p,
            "recall": rec,
            "flagged": sum(combined),
            "precision_gain": None if p is None or p_rules is None else p - p_rules,
            "precision_gain_ci95": bootstrap_ci(groups, delta(combined), n_boot, seed),
        }
    return out


def build_report(
    splits: dict[str, list[dict[str, Any]]], systems: list[System], filters: dict[str, Any], n_boot: int, seed: int
) -> dict[str, Any]:
    dev = splits["dev"]
    dev_labels = [e["label"] for e in dev]
    thresholds: dict[str, float | None] = {}
    platt: dict[str, tuple[float, float] | None] = {}
    for s in systems:
        dev_scores = [x.score for x in s.scored["dev"]]
        thresholds[s.name] = (
            s.fixed_threshold if s.fixed_threshold is not None else best_threshold(dev_scores, dev_labels)
        )
        fit_ok = s.kind == "probability" and 0 < sum(dev_labels) < len(dev_labels)
        platt[s.name] = platt_fit(dev_scores, dev_labels) if fit_ok else None
    rules = next(s for s in systems if s.name == "rules")
    out: dict[str, Any] = {}
    for split, examples in splits.items():
        block: dict[str, Any] = {"examples": dict(Counter(e["role"] for e in examples)), "views": {}}
        rule_flags = [x.score >= 1.0 for x in rules.scored[split]]
        for view, idx in views(split, examples, filters).items():
            if isinstance(idx, str):
                block["views"][view] = idx
                continue
            per_system = {
                s.name: system_metrics(examples, idx, s, split, thresholds[s.name], platt[s.name], n_boot, seed)
                for s in systems
            }
            gains = {}
            for s in systems:
                thr = thresholds[s.name]
                if s.name != "rules" and s.kind == "probability" and thr is not None:
                    flags = [x.score >= thr for x in s.scored[split]]
                    gains[s.name] = rules_gain(examples, idx, rule_flags, flags, n_boot, seed)
            block["views"][view] = {"n": len(idx), "systems": per_system, "rules_plus_model": gains}
        out[split] = block
    return {
        "thresholds_from_dev": thresholds,
        "platt_from_dev": {k: (None if v is None else {"a": v[0], "b": v[1]}) for k, v in platt.items()},
        "splits": out,
        "systems": {s.name: {"kind": s.kind, **s.extra} for s in systems},
    }


# --- command line ----------------------------------------------------------------------------


@dataclass(frozen=True)
class EvalOptions:
    split: str = "dev"
    locked: bool = False
    name: str = ""
    teacher_runs: tuple[str, ...] = ()
    student_run: str | None = None
    zero_shot: bool = False
    limit: int = 0
    dev_neg_ratio: float | None = None
    bootstrap: int = 1000
    seed: int = 0
    batch: int = 8
    latency_n: int = 200
    bow_neg_ratio: float = TeacherConfig.neg_ratio


def evaluate(root: Path, models: Path, opts: EvalOptions) -> Path:
    """Score every system, write the scores (``eval/<name>/``, 0600) and ``reports/vul-eval-<name>.json``."""
    if opts.split not in {"dev", "test"}:
        raise EvalError("--split is dev or test")
    if (opts.split == "test") != opts.locked:
        raise EvalError("the held-out splits need --split test --locked, and --locked only applies to --split test")
    name = opts.name or f"{opts.split}-{os.environ.get('SLURM_JOB_ID', int(time.time()))}"
    for run in opts.teacher_runs:
        _run_meta(root, run, "teacher")
    if opts.student_run:
        _run_meta(root, opts.student_run, "student")
    manifest = manifest_path(root)
    splits = {"dev": assemble(root, "dev", neg_ratio=opts.dev_neg_ratio, limit=opts.limit)}
    claim = None
    if opts.locked:
        info = {
            "name": name,
            "teacher_runs": list(opts.teacher_runs),
            "student_run": opts.student_run,
            "git_sha": git_sha(),
            "manifest_sha256": file_sha256(manifest),
        }
        claim = claim_locked(root, info)
        splits |= read_held_out(root, claim)
    started = time.time()
    systems = baseline_systems(root, splits, opts.seed, opts.bow_neg_ratio)
    if opts.zero_shot or opts.teacher_runs:
        systems += teacher_systems(root, models, splits, list(opts.teacher_runs), opts.zero_shot, opts.batch)
    if opts.student_run:
        systems.append(student_system(root, models, splits, opts.student_run, opts.latency_n))
    for s in systems:
        for split, rows in s.scored.items():
            ids = [e["id"] for e in splits[split]]
            write_jsonl(
                root / "eval" / name / f"{split}-{s.name.replace(':', '_')}.jsonl",
                [{"id": i, "score": r.score, "cwes": list(r.cwes)} for i, r in zip(ids, rows, strict=True)],
            )
    body = build_report(splits, systems, read_filters(root), opts.bootstrap, opts.seed)
    report = {
        "schema_version": 1,
        "name": name,
        "split": opts.split,
        "locked": opts.locked,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_sha": git_sha(),
        "data": {
            "manifest": manifest.name,
            "manifest_sha256": file_sha256(manifest),
            "data_seed": DATA_SEED,
            "dev_neg_ratio": opts.dev_neg_ratio,
            "dev_limit": opts.limit,
        },
        "bootstrap": {"resamples": opts.bootstrap, "seed": opts.seed, "unit": "repository"},
        "seconds": round(time.time() - started, 1),
        **body,
    }
    out = root / "reports" / f"vul-eval-{name}.json"
    write_json(out, report)
    if claim is not None:
        finish_claim(claim, out)
    return out


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m kestrixvul.evaluate", description=__doc__.splitlines()[0])
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--models", type=Path, help="model snapshots (default: <root>/../models)")
    p.add_argument("--split", choices=("dev", "test"), default="dev")
    p.add_argument("--locked", action="store_true", help="evaluate test and test_extension, once")
    p.add_argument("--name", default="")
    p.add_argument("--teacher-run", action="append", default=[])
    p.add_argument("--student-run")
    p.add_argument("--zero-shot", action="store_true", help="also score Qwen2.5-Coder-7B-Instruct without adapters")
    p.add_argument("--limit", type=int, default=0, help="at most this many dev examples (smoke)")
    p.add_argument("--dev-neg-ratio", type=float, help="dev negatives per vulnerable record (default: all)")
    p.add_argument("--bootstrap", type=int, default=1000)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--batch", type=int, default=8)
    p.add_argument("--latency-n", type=int, default=200)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root: Path = args.root.resolve()
    if (args.split == "test") != args.locked:
        print(
            "evaluate: the held-out splits need --split test --locked (and --locked needs --split test)",
            file=sys.stderr,
        )
        return 2
    opts = EvalOptions(
        split=args.split,
        locked=args.locked,
        name=args.name,
        teacher_runs=tuple(args.teacher_run),
        student_run=args.student_run,
        zero_shot=args.zero_shot,
        limit=args.limit,
        dev_neg_ratio=args.dev_neg_ratio,
        bootstrap=args.bootstrap,
        seed=args.seed,
        batch=args.batch,
        latency_n=args.latency_n,
    )
    os.umask(0o077)
    try:
        out = evaluate(root, (args.models or root.parent / "models").resolve(), opts)
    except (EvalError, DataError, OSError) as exc:
        print(f"evaluate: FAILED {exc}", file=sys.stderr)
        return 1
    print(f"evaluate: done {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
