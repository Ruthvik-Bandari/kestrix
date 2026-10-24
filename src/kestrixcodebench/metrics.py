# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Detection and noise metrics for any tool's findings, with repository-bootstrap intervals.

Unit: a *pair* is one changed file of a CVE fix, before and after. Ground truth is approximate and file-level.

* **in scope**: the pair's CVE has a CWE that maps to a family (``families.py``); detection and fix-aware rates use only
  these pairs;
* **detection**: a finding on the before-file whose family is one of the pair's families and whose lines come within
  ``MARGIN`` lines of a line the fix changed (a pure insertion counts as the two lines around it);
* **fix-aware detection**: a detection whose rule no longer fires near the same place in the after-file (the place is
  found through the diff), so the finding went away with the fix;
* **any finding near the change**: a before-file finding of any family near the changed lines, over all pairs (family
  agnostic, so it also covers CVEs with no mapped CWE);
* **alerts**: findings that map to a family (``families.py``); the rest (assert statements, import checks, style rules)
  are lint-level findings that the existing ``kestrixscanbench`` scoring also ignores and are reported separately;
* **false alarms**: alerts on after-files and on unchanged files, per KLOC. Approximate on purpose: a fixed file may
  still hold another weakness, and an unchanged file may be vulnerable;
* **precision**: true detections over true detections plus alerts on after-files and unchanged files (a proxy that
  depends on the one-before to one-after mix, not a real-world precision);
* **fix-weighted detection**: the detection rate with every fix commit counted once (each of its files weighs
  1 / the commit's file count), so a commit that changes hundreds of files does not dominate the rate.

Every interval is a 95% percentile bootstrap that resamples whole repositories (the same resamples for every tool, so
differences between tools have their own interval).
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from numpy.typing import NDArray

from .common import LANGUAGES, CodeBenchError, Layout, read_jsonl
from .diff import map_old_line, near

MARGIN = 3
REPS = 1000
SEED = 0
MIN_FAMILY_PAIRS = 12
TOP = 12
SUBSETS: dict[str, tuple[str, ...]] = {
    "all": LANGUAGES,
    "python": ("python",),
    "javascript": ("javascript",),
    "typescript": ("typescript",),
    "js_ts": ("javascript", "typescript"),
    "web": ("web",),  # .vue, .svelte, .html, .css: only kestrix-scan reads them
    "php": ("php",),  # .php, .phtml
}

Finding = tuple[str, int, int, tuple[str, ...]]  # rule, line, end line, families
FloatArray = NDArray[np.float64]


@dataclass
class PairEval:
    matched: set[str] = field(default_factory=set)  # families of the pair matched by a finding near the change
    fixed: set[str] = field(default_factory=set)  # of those, families whose finding went away in the after-file
    tp_findings: int = 0
    any_near: bool = False
    after_alerts: int = 0  # findings on the after-file that map to a family
    after_all: int = 0  # every finding on the after-file
    rule_tp: Counter[str] = field(default_factory=Counter)


def evaluate_pair(row: dict[str, Any], before: list[Finding], after: list[Finding]) -> PairEval:
    ranges = [(lo, hi) for lo, hi in row["old_ranges"]]
    ops = [(a, b, c, d) for a, b, c, d in row["ops"]]
    families = set(row["families"])
    result = PairEval(after_alerts=sum(1 for *_, f in after if f), after_all=len(after))
    for rule, line, end, fams in before:
        if not near(ranges, line, end, MARGIN):
            continue
        result.any_near = True
        hit = families & set(fams)
        if not hit:
            continue
        result.tp_findings += 1
        result.rule_tp[rule] += 1
        result.matched |= hit
        lo, hi = map_old_line(ops, line)[0], map_old_line(ops, end)[1]
        survives = any(r == rule and near([(lo, hi)], al, ae, MARGIN) for r, al, ae, _ in after)
        if not survives:
            result.fixed |= hit
    return result


def read_findings(layout: Layout, run: str, tool: str, shards: int) -> dict[tuple[str, str], list[Finding]]:
    out: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for shard in range(shards):
        path = layout.findings_file(run, tool, shard)
        if not path.is_file():
            raise CodeBenchError(f"{path} is missing; the scan job for this shard did not finish")
        for item in read_jsonl(path):
            out[(item["k"], item["i"])].append((item["r"], item["l"], item["e"], tuple(item["f"])))
    return out


def read_reports(layout: Layout, run: str, tool: str, shards: int) -> list[dict[str, Any]]:
    paths = [layout.scan_report(run, tool, s) for s in range(shards)]
    for path in paths:
        if not path.is_file():
            raise CodeBenchError(f"{path} is missing; the scan job for this shard did not finish")
    return [json.loads(path.read_text(encoding="utf-8")) for path in paths]


class Frame:
    """Pairs and unchanged files of one split as aligned arrays; the group is the repository."""

    def __init__(
        self, pairs: list[dict[str, Any]], unchanged: list[dict[str, Any]], reps: int = REPS, seed: int = SEED
    ):
        self.pairs, self.unchanged = pairs, unchanged
        self.n_pairs, self.n_unch = len(pairs), len(unchanged)
        names = sorted({r["repos"][0] for r in pairs} | {r["repo"] for r in unchanged})
        index = {n: i for i, n in enumerate(names)}
        self.groups = len(names)
        self.group = np.array(
            [index[r["repos"][0]] for r in pairs] + [index[r["repo"]] for r in unchanged], dtype=np.int64
        )
        self.language = np.array([r["language"] for r in pairs] + [r["language"] for r in unchanged], dtype=object)
        self.is_pair = np.array([True] * self.n_pairs + [False] * self.n_unch)
        commits = Counter((r["repos"][0], r["commits"][0]) for r in pairs)
        self.fix_weight = np.array(
            [1.0 / commits[(r["repos"][0], r["commits"][0])] for r in pairs] + [0.0] * self.n_unch
        )
        self.scope = np.array([bool(r["families"]) for r in pairs] + [False] * self.n_unch)
        self.after_kloc = np.array([r["after_lines"] / 1000 for r in pairs] + [0.0] * self.n_unch)
        self.unch_kloc = np.array([0.0] * self.n_pairs + [r["lines"] / 1000 for r in unchanged])
        rng = np.random.default_rng(seed)
        self.weights = np.stack(
            [np.bincount(rng.integers(0, self.groups, self.groups), minlength=self.groups) for _ in range(reps)]
        ).astype(np.float64)

    def mask(self, languages: tuple[str, ...]) -> NDArray[np.bool_]:
        return np.asarray(np.isin(self.language, languages), dtype=bool)

    def sums(self, values: FloatArray) -> FloatArray:
        return np.asarray(np.bincount(self.group, weights=values, minlength=self.groups), dtype=np.float64)

    def ratio(self, num: FloatArray, den: FloatArray, scale: float = 1.0) -> dict[str, Any]:
        """Point estimate and bootstrap interval of sum(num) / sum(den) * scale."""
        ns, ds = self.sums(num), self.sums(den)
        total = float(ds.sum())
        if total <= 0:
            return {"k": float(ns.sum()), "n": total, "rate": None, "ci95": None}
        boot_den = self.weights @ ds
        ok = boot_den > 0
        boot = (self.weights @ ns)[ok] / boot_den[ok] * scale
        low, high = np.percentile(boot, [2.5, 97.5]) if boot.size else (np.nan, np.nan)
        return {
            "k": float(ns.sum()),
            "n": total,
            "rate": round(float(ns.sum()) / total * scale, 6),
            "ci95": [round(float(low), 6), round(float(high), 6)],
        }

    def difference(self, a: tuple[FloatArray, FloatArray], b: tuple[FloatArray, FloatArray]) -> dict[str, Any]:
        """Point estimate and bootstrap interval of ratio(a) - ratio(b) on the same resamples."""
        (an, ad), (bn, bd) = (tuple(self.sums(x) for x in a), tuple(self.sums(x) for x in b))
        if ad.sum() <= 0 or bd.sum() <= 0:
            return {"delta": None, "ci95": None}
        pa, pb = (
            (self.weights @ an) / np.maximum(self.weights @ ad, 1e-9),
            (self.weights @ bn) / np.maximum(self.weights @ bd, 1e-9),
        )
        low, high = np.percentile(pa - pb, [2.5, 97.5])
        return {
            "delta": round(float(an.sum() / ad.sum() - bn.sum() / bd.sum()), 6),
            "ci95": [round(float(low), 6), round(float(high), 6)],
        }


@dataclass
class ToolEval:
    """One tool's evaluation of a frame, as arrays aligned with the frame's entities."""

    name: str
    pair_evals: list[PairEval]
    detected: FloatArray
    fixaware: FloatArray
    any_near: FloatArray
    tp: FloatArray
    alerts_after: FloatArray
    alerts_unchanged: FloatArray
    findings_after: FloatArray  # every finding, mapped or not
    findings_unchanged: FloatArray
    alert_rules: dict[str, Counter[str]]  # per language: alerts on after-files and unchanged files by rule
    unmapped_rules: dict[str, Counter[str]]  # per language: findings with no family, by rule


def evaluate_tool(frame: Frame, name: str, findings: dict[tuple[str, str], list[Finding]]) -> ToolEval:
    evals: list[PairEval] = []
    size = frame.n_pairs + frame.n_unch
    det, fix, near_any, tp, after_n, after_all, unch_n, unch_all = (np.zeros(size) for _ in range(8))
    alert_rules: dict[str, Counter[str]] = defaultdict(Counter)
    unmapped: dict[str, Counter[str]] = defaultdict(Counter)

    def count(language: str, found: list[Finding]) -> None:
        for rule, _, _, fams in found:
            (alert_rules if fams else unmapped)[language][rule] += 1

    for i, row in enumerate(frame.pairs):
        before, after = findings.get(("b", row["id"]), []), findings.get(("a", row["id"]), [])
        ev = evaluate_pair(row, before, after)
        evals.append(ev)
        scope = bool(row["families"])
        det[i] = 1.0 if scope and ev.matched else 0.0
        fix[i] = 1.0 if scope and ev.fixed else 0.0
        near_any[i] = 1.0 if ev.any_near else 0.0
        tp[i] = ev.tp_findings if scope else 0
        after_n[i], after_all[i] = ev.after_alerts, ev.after_all
        count(row["language"], after)
    for j, row in enumerate(frame.unchanged):
        found = findings.get(("u", row["id"]), [])
        unch_n[frame.n_pairs + j] = sum(1 for *_, f in found if f)
        unch_all[frame.n_pairs + j] = len(found)
        count(row["language"], found)
    return ToolEval(name, evals, det, fix, near_any, tp, after_n, unch_n, after_all, unch_all, alert_rules, unmapped)


def drop_rules(
    findings: dict[tuple[str, str], list[Finding]], rules: frozenset[str]
) -> dict[tuple[str, str], list[Finding]]:
    """The same findings without some rules (a tool run the way users often configure it)."""
    return {key: [f for f in found if f[0] not in rules] for key, found in findings.items()}


def metrics_for(frame: Frame, ev: ToolEval, languages: tuple[str, ...]) -> dict[str, Any]:
    lang = frame.mask(languages)
    pair = lang & frame.is_pair
    scope = (pair & frame.scope).astype(np.float64)
    pairs_all = pair.astype(np.float64)
    unch = (lang & ~frame.is_pair).astype(np.float64)
    after_alerts = ev.alerts_after * pair
    unch_alerts = ev.alerts_unchanged * unch
    tp = ev.tp * pair
    all_findings = ev.findings_after * pair + ev.findings_unchanged * unch
    kloc = frame.after_kloc * pair + frame.unch_kloc * unch
    return {
        "pairs": int(pair.sum()),
        "pairs_in_scope": int(scope.sum()),
        "unchanged_files": int(unch.sum()),
        "detection": frame.ratio(ev.detected * pair, scope),
        "fix_aware_detection": frame.ratio(ev.fixaware * pair, scope),
        "detection_fix_weighted": frame.ratio(ev.detected * pair * frame.fix_weight, scope * frame.fix_weight),
        "any_finding_near_change": frame.ratio(ev.any_near * pair, pairs_all),
        "false_alarms_per_kloc_after": frame.ratio(after_alerts, frame.after_kloc * pair),
        "false_alarms_per_kloc_unchanged": frame.ratio(unch_alerts, frame.unch_kloc * unch),
        "precision": frame.ratio(tp, tp + after_alerts + unch_alerts),
        "all_findings_per_kloc_after_and_unchanged": frame.ratio(all_findings, kloc),
    }


def family_metrics(frame: Frame, ev: ToolEval, languages: tuple[str, ...]) -> dict[str, Any]:
    lang = frame.mask(languages)
    counts: Counter[str] = Counter()
    for i, row in enumerate(frame.pairs):
        if lang[i]:
            counts.update(row["families"])
    out: dict[str, Any] = {}
    for family, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        member = np.zeros(frame.n_pairs + frame.n_unch)
        hit, fixed = np.zeros_like(member), np.zeros_like(member)
        for i, row in enumerate(frame.pairs):
            if lang[i] and family in row["families"]:
                member[i] = 1.0
                hit[i] = 1.0 if family in ev.pair_evals[i].matched else 0.0
                fixed[i] = 1.0 if family in ev.pair_evals[i].fixed else 0.0
        entry: dict[str, Any] = {"pairs": n}
        if n >= MIN_FAMILY_PAIRS:
            entry["detection"] = frame.ratio(hit, member)
            entry["fix_aware_detection"] = frame.ratio(fixed, member)
        else:
            entry["detection"] = {
                "k": float(hit.sum()),
                "n": float(member.sum()),
                "rate": round(float(hit.sum() / n), 6),
            }
            entry["fix_aware_detection"] = {
                "k": float(fixed.sum()),
                "n": float(member.sum()),
                "rate": round(float(fixed.sum() / n), 6),
            }
            entry["note"] = f"fewer than {MIN_FAMILY_PAIRS} pairs, no interval"
        out[family] = entry
    return out


def error_analysis(frame: Frame, ev: ToolEval, languages: tuple[str, ...]) -> dict[str, Any]:
    """Aggregate-only: which families are missed most, and which rules make the noise and the true hits."""
    lang = frame.mask(languages)
    missed: Counter[str] = Counter()
    total: Counter[str] = Counter()
    wrong_family: Counter[str] = Counter()
    hits: Counter[str] = Counter()
    for i, row in enumerate(frame.pairs):
        if not lang[i]:
            continue
        pe = ev.pair_evals[i]
        for family in row["families"]:
            total[family] += 1
            if family not in pe.matched:
                missed[family] += 1
                if pe.any_near:
                    wrong_family[family] += 1
        hits.update(pe.rule_tp)
    kloc = float((frame.after_kloc * (lang & frame.is_pair)).sum() + (frame.unch_kloc * (lang & ~frame.is_pair)).sum())
    noisy: Counter[str] = Counter()
    unmapped: Counter[str] = Counter()
    for language in languages:
        noisy.update(ev.alert_rules.get(language, Counter()))
        unmapped.update(ev.unmapped_rules.get(language, Counter()))
    return {
        "missed_by_family": [
            {"family": f, "missed": n, "pairs": total[f], "missed_with_other_finding_near": wrong_family[f]}
            for f, n in missed.most_common(TOP)
        ],
        "alert_rules_on_fixed_and_unchanged_files": [
            {"rule": r, "alerts": n, "per_kloc": round(n / kloc, 3) if kloc else None, "true_hits": hits[r]}
            for r, n in noisy.most_common(TOP)
        ],
        "rules_with_true_hits": [{"rule": r, "true_hits": n} for r, n in hits.most_common(TOP)],
        "unmapped_findings_top_rules": [{"rule": r, "findings": n} for r, n in unmapped.most_common(5)],
    }


def overlap(
    frame: Frame, evals: dict[str, ToolEval], first: str, second: str, languages: tuple[str, ...]
) -> dict[str, Any]:
    pair = frame.mask(languages) & frame.is_pair
    scope = (pair & frame.scope).astype(np.float64)
    a, b = evals[first].detected * pair, evals[second].detected * pair
    both, either = a * b, np.maximum(a, b)
    return {
        "pairs_in_scope": int(scope.sum()),
        "both": int(both.sum()),
        f"only_{first}": int((a - both).sum()),
        f"only_{second}": int((b - both).sum()),
        "neither": int(scope.sum() - either.sum()),
        "union_detection": frame.ratio(either, scope),
        "intersection_detection": frame.ratio(both, scope),
        f"{first}_minus_{second}": frame.difference((a, scope), (b, scope)),
    }
