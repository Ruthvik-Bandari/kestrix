# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Dev metrics, the one-time locked test, and Markdown tables for the benchmark page. Aggregates only."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np

from kestrixvul.evaluate import claim_locked, finish_claim

from .common import SHARDS, CodeBenchError, Layout, file_sha256, now, read_jsonl, write_json
from .metrics import (
    MARGIN,
    REPS,
    SEED,
    SUBSETS,
    Frame,
    ToolEval,
    drop_rules,
    error_analysis,
    evaluate_tool,
    family_metrics,
    metrics_for,
    overlap,
    read_findings,
    read_reports,
)
from .scan import TOOLS, TUNING, base_tool, scan_shard

# eslint-plugin-security without detect-object-injection (47k findings, the rule most projects switch off)
VARIANT = "eslint-no-object-injection"
VARIANT_DROPS = frozenset({"security/detect-object-injection"})

P4_SUBSETS = ("go", "java", "kotlin", "jvm", "csharp", "ruby", "erb", "rails", "p4")
P5_SUBSETS = ("c", "cpp", "c_cpp", "rust", "swift", "p5")
# Which language subsets a tool is run on (a baseline is scored only where it applies).
TOOL_SUBSETS: dict[str, tuple[str, ...]] = {
    "kestrix": ("all", "python", "javascript", "typescript", "js_ts", "web", "php", *P4_SUBSETS, *P5_SUBSETS),
    "bandit": ("python",),
    "psalm": ("php",),
    "gosec": ("go",),
    "opengrep": ("go", "java", "kotlin", "jvm", "csharp", "ruby", "p4"),  # it does not read ERB
    "flawfinder": ("c", "cpp", "c_cpp"),
    "opengrep-sys": P5_SUBSETS,
    "eslint": ("javascript", "typescript", "js_ts"),
    VARIANT: ("javascript", "typescript", "js_ts"),
}
OVERLAPS = (
    ("kestrix", "bandit", "python"),
    ("kestrix", "eslint", "js_ts"),
    ("kestrix", "psalm", "php"),
    ("kestrix", "gosec", "go"),
    ("kestrix", "opengrep", "go"),
    ("kestrix", "opengrep", "jvm"),
    ("kestrix", "opengrep", "csharp"),
    ("kestrix", "opengrep", "ruby"),
    ("kestrix", "opengrep", "p4"),
    ("kestrix", "flawfinder", "c_cpp"),
    ("kestrix", "opengrep-sys", "c_cpp"),
    ("kestrix", "opengrep-sys", "rust"),
    ("kestrix", "opengrep-sys", "swift"),
    ("kestrix", "opengrep-sys", "p5"),
)
FAMILY_SUBSETS = ("python", "js_ts", "php", "go", "jvm", "csharp", "ruby", "rails", "c_cpp", "rust", "swift")
DEV_REPORT = "codebench-dev-{label}.json"
LOCKED_REPORT = "codebench-locked-{name}.json"


def load_frame(
    layout: Layout, split: str, reps: int = REPS, seed: int = SEED, only: Callable[[dict[str, Any]], bool] | None = None
) -> Frame:
    sides = {"dev", "test"} if split == TUNING else {split}
    keep = only or (lambda row: True)
    pairs = [r for r in read_jsonl(layout.pairs) if r["split"] in sides and keep(r)]
    unchanged = [r for r in read_jsonl(layout.unchanged) if r["split"] in sides and keep(r)]
    if not pairs:
        raise CodeBenchError(f"no {split} pairs; run build first")
    return Frame(pairs, unchanged, reps, seed)


def tool_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    seconds = sum(r["seconds"] for r in reports)
    files = sum(sum(r["files"].values()) for r in reports)
    unparsed: dict[str, int] = {}
    for r in reports:
        for kind, n in r["unparsed"].items():
            unparsed[kind] = unparsed.get(kind, 0) + n
    return {
        "version": reports[0]["tool_version"],
        "code_sha": reports[0]["code_sha"],
        "files_scanned": files,
        "scan_seconds_summed_over_shards": round(seconds, 1),
        "files_per_second": round(files / seconds, 1) if seconds else None,
        "files_not_parsed_by_kind": dict(sorted(unparsed.items())),
        "findings": sum(r["findings"] for r in reports),
    }


def evaluate_report(
    layout: Layout, frame: Frame, runs: dict[str, str], split: str, shards: int = SHARDS
) -> dict[str, Any]:
    evals: dict[str, ToolEval] = {}
    tools: dict[str, Any] = {}
    for tool, run in runs.items():
        reports = read_reports(layout, run, tool, shards)
        if {r["split"] for r in reports} != {split}:
            raise CodeBenchError(f"run {run}/{tool} was not scanned on the {split} split")
        findings = read_findings(layout, run, tool, shards)
        variants = {tool: findings}
        if tool == "eslint":
            variants[VARIANT] = drop_rules(findings, VARIANT_DROPS)
        for name, found in variants.items():
            ev = evaluate_tool(frame, name, found)
            evals[name] = ev
            wanted = TOOL_SUBSETS[base_tool(name)]
            subsets = {sub: metrics_for(frame, ev, SUBSETS[sub]) for sub in wanted}
            errors = {sub: error_analysis(frame, ev, SUBSETS[sub]) for sub in wanted if sub != "js_ts"}
            families = {sub: family_metrics(frame, ev, SUBSETS[sub]) for sub in FAMILY_SUBSETS if sub in wanted}
            tools[name] = {
                **tool_summary(reports),
                "run": run,
                "derived_from": None if name == tool else tool,
                "subsets": subsets,
                "families": families,
                "error_analysis": errors,
            }
    overlaps = {
        f"{a}+{b}:{lang}": overlap(frame, evals, a, b, SUBSETS[lang])
        for a, b, lang in OVERLAPS
        if a in evals and b in evals
    }
    return {"tools": tools, "overlap": overlaps}


TUNING_NOTE = "round-1 dev plus the round-1 test (spent: LOCKED_EVAL.json); tuning data, not a held-out measurement"


def dev_report(layout: Layout, runs: dict[str, str], label: str, reps: int = REPS, split: str = "dev") -> Path:
    frame = load_frame(layout, split, reps)
    manifest = json.loads(layout.split_manifest.read_text(encoding="utf-8"))
    sides = ("dev", "test") if split == TUNING else (split,)
    body = {
        "schema_version": 1,
        "split": split,
        "note": TUNING_NOTE if split == TUNING else "development data",
        "label": label,
        "generated_at": now(),
        "bootstrap": {"resamples": reps, "seed": SEED, "unit": "repository", "margin_lines": MARGIN},
        "split_manifest_sha256": manifest["manifest_sha256"],
        "dev_data": {side: manifest["splits"][side] for side in sides}
        if split == TUNING
        else manifest["splits"]["dev"],
        **evaluate_report(layout, frame, runs, split),
    }
    out = layout.reports / DEV_REPORT.format(label=label)
    write_json(out, body)
    return out


def locked_test(layout: Layout, name: str, runs: dict[str, str], code_sha: str, reps: int = REPS) -> Path:
    """Scan the test split with every tool and score it, once. The lock is claimed before any test file is read.

    The scoring code is first exercised on dev findings of the same runs (it needs them), so a typo cannot burn the
    one evaluation; after the claim the lock stays even if the run fails.
    """
    if not layout.split_manifest.is_file():
        raise CodeBenchError("build has not run")
    evaluate_report(layout, load_frame(layout, "dev", 2), runs, "dev")
    manifest = json.loads(layout.split_manifest.read_text(encoding="utf-8"))
    claim = claim_locked(
        layout.root,
        {
            "name": name,
            "code_sha": code_sha,
            "dev_runs": runs,
            "split_manifest_sha256": manifest["manifest_sha256"],
            "pairs_sha256": file_sha256(layout.pairs),
        },
    )
    run = f"locked-{name}"
    for tool in runs:
        for shard in range(SHARDS):
            scan_shard(layout, tool, "test", shard, run=run, code_sha=code_sha, locked=True)
    frame = load_frame(layout, "test", reps)
    body = {
        "schema_version": 1,
        "split": "test",
        "name": name,
        "generated_at": now(),
        "code_sha": code_sha,
        "bootstrap": {"resamples": reps, "seed": SEED, "unit": "repository", "margin_lines": MARGIN},
        "split_manifest_sha256": manifest["manifest_sha256"],
        "test_data": manifest["splits"]["test"],
        **evaluate_report(layout, frame, dict.fromkeys(runs, run), "test"),
    }
    out = layout.reports / LOCKED_REPORT.format(name=name)
    write_json(out, body)
    finish_claim(claim, out)
    return out


def _change_parts(frame: Frame, ev: ToolEval, languages: tuple[str, ...]) -> dict[str, tuple[Any, Any]]:
    """(numerator, denominator) arrays of the metrics that ``compare_runs`` differences."""
    lang = frame.mask(languages)
    pair, unch = lang & frame.is_pair, lang & ~frame.is_pair
    scope = (pair & frame.scope).astype(np.float64)
    return {
        "detection": (ev.detected * pair, scope),
        "fix_aware_detection": (ev.fixaware * pair, scope),
        "detection_fix_weighted": (ev.detected * pair * frame.fix_weight, scope * frame.fix_weight),
        "alerts_per_kloc": (
            ev.alerts_after * pair + ev.alerts_unchanged * unch,
            frame.after_kloc * pair + frame.unch_kloc * unch,
        ),
    }


def paired_change(frame: Frame, base: ToolEval, new: ToolEval) -> dict[str, Any]:
    """Paired change of ``new`` against ``base`` per language subset: the same repository resamples for both, so each
    difference has its own interval. ``alerts_per_kloc`` pools alerts on after-files and unchanged files."""
    out: dict[str, Any] = {}
    for name, languages in SUBSETS.items():
        first = _change_parts(frame, base, languages)
        second = _change_parts(frame, new, languages)
        out[name] = {
            metric: {
                **frame.difference(second[metric], first[metric]),
                "base": round(float(first[metric][0].sum() / max(first[metric][1].sum(), 1e-9)), 6),
                "new": round(float(second[metric][0].sum() / max(second[metric][1].sum(), 1e-9)), 6),
                "k_base": float(first[metric][0].sum()),
                "k_new": float(second[metric][0].sum()),
            }
            for metric in first
        }
    return out


def compare_runs(layout: Layout, base: str, new: str, label: str, *, reps: int = REPS, split: str = "dev") -> Path:
    """Paired change between two kestrix runs on dev (or on the tuning data)."""
    frame = load_frame(layout, split, reps)
    evals = {run: evaluate_tool(frame, "kestrix", read_findings(layout, run, "kestrix", SHARDS)) for run in (base, new)}
    path = layout.reports / f"codebench-compare-{label}.json"
    bootstrap = {"resamples": reps, "unit": "repository"}
    out = paired_change(frame, evals[base], evals[new])
    write_json(
        path, {"schema_version": 1, "split": split, "base": base, "new": new, "bootstrap": bootstrap, "subsets": out}
    )
    return path


def _cell(metric: dict[str, Any], pct: bool = True, digits: int = 1) -> str:
    rate = metric.get("rate")
    if rate is None:
        return "n/a"
    scale = 100 if pct else 1
    ci = metric.get("ci95")
    text = f"{rate * scale:.{digits}f}"
    return f"{text} [{ci[0] * scale:.{digits}f}, {ci[1] * scale:.{digits}f}]" if ci else text


def markdown(report: dict[str, Any]) -> str:
    """Tables of the headline metrics per tool and language subset (percent, 95% interval in brackets)."""
    lines = [
        "| Tool | Subset | Pairs (in scope) | Detection % | Fix-aware % | Fix-weighted detection % | "
        "False alarms/KLOC after | False alarms/KLOC unchanged | Precision % | All findings/KLOC |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for tool, entry in report["tools"].items():
        for name, m in entry["subsets"].items():
            lines.append(
                f"| {tool} | {name} | {m['pairs']} ({m['pairs_in_scope']}) | {_cell(m['detection'])} | "
                f"{_cell(m['fix_aware_detection'])} | {_cell(m['detection_fix_weighted'])} | "
                f"{_cell(m['false_alarms_per_kloc_after'], False, 2)} | "
                f"{_cell(m['false_alarms_per_kloc_unchanged'], False, 2)} | {_cell(m['precision'])} | "
                f"{_cell(m['all_findings_per_kloc_after_and_unchanged'], False, 2)} |"
            )
    return "\n".join(lines) + "\n"


__all__ = ["TOOLS", "compare_runs", "dev_report", "locked_test", "markdown"]
