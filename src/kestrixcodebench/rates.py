# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Per-rule firing rates of a kestrix run, for rules whose findings the family metrics do not score.

``html.*``, ``css.*`` and most ``web.*`` findings carry CWEs outside the benchmark's families (319, 1022), so they are
lint-level in ``metrics.py`` and never count as alerts. This report counts every finding of a rule instead: on the
before-files near a changed line (what a fix touched), on the before-files anywhere, and on the after-files and
unchanged files (the clean corpus: files the fix did not make vulnerable and files it never touched), per KLOC. Also
the in-scope pairs a rule detects alone (a finding of a family of the pair near a changed line) and its family-mapped
alerts on the clean files, which is what the keep rule compares. Counts and rates only; no code and no paths.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .common import SHARDS, Layout, write_json
from .diff import near
from .metrics import MARGIN, read_findings
from .report import load_frame


def rule_rates(layout: Layout, run: str, split: str, label: str, languages: tuple[str, ...] | None = None) -> Any:
    """Write ``reports/codebench-rates-LABEL.json``: per rule and language the counts and rates described above."""
    frame = load_frame(layout, split)
    findings = read_findings(layout, run, "kestrix", SHARDS)
    pairs, unchanged = frame.pairs, frame.unchanged
    count: dict[str, Counter[str]] = defaultdict(Counter)
    kloc: Counter[str] = Counter()
    files: Counter[str] = Counter()
    for row in pairs:
        lang = row["language"]
        if languages and lang not in languages:
            continue
        ranges = [(lo, hi) for lo, hi in row["old_ranges"]]
        kloc[f"{lang}:after"] += row["after_lines"] / 1000
        kloc[f"{lang}:before"] += row["before_lines"] / 1000
        files[f"{lang}:after"] += 1
        files[f"{lang}:before"] += 1
        matched: set[str] = set()
        for rule, line, end, fams in findings.get(("b", row["id"]), []):
            count[f"{lang}:{rule}"]["before_any"] += 1
            if near(ranges, line, end, MARGIN):
                count[f"{lang}:{rule}"]["before_near_change"] += 1
                if set(fams) & set(row["families"]):
                    matched.add(rule)
        for rule in matched:
            count[f"{lang}:{rule}"]["detected_pairs"] += 1
        for rule, _, _, fams in findings.get(("a", row["id"]), []):
            count[f"{lang}:{rule}"]["after"] += 1
            if fams:
                count[f"{lang}:{rule}"]["after_alerts"] += 1
    for row in unchanged:
        lang = row["language"]
        if languages and lang not in languages:
            continue
        kloc[f"{lang}:unchanged"] += row["lines"] / 1000
        files[f"{lang}:unchanged"] += 1
        for rule, _, _, fams in findings.get(("u", row["id"]), []):
            count[f"{lang}:{rule}"]["unchanged"] += 1
            if fams:
                count[f"{lang}:{rule}"]["unchanged_alerts"] += 1
    rows = []
    for key, c in sorted(count.items()):
        lang, _, rule = key.partition(":")
        clean_kloc = kloc[f"{lang}:after"] + kloc[f"{lang}:unchanged"]
        clean = c["after"] + c["unchanged"]
        rows.append(
            {
                "language": lang,
                "rule": rule,
                **{
                    k: c[k]
                    for k in (
                        "before_any",
                        "before_near_change",
                        "detected_pairs",
                        "after",
                        "after_alerts",
                        "unchanged",
                        "unchanged_alerts",
                    )
                },
                "clean_alerts_per_kloc": round(clean / clean_kloc, 4) if clean_kloc else None,
            }
        )
    out = {
        "schema_version": 1,
        "run": run,
        "split": split,
        "kloc": {k: round(v, 1) for k, v in sorted(kloc.items())},
        "files": dict(sorted(files.items())),
        "rules": rows,
    }
    path = layout.reports / f"codebench-rates-{label}.json"
    write_json(path, out)
    return path


__all__ = ["rule_rates"]
