# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Alerts per KLOC of kestrix-scan on a corpus of web files that no CVE fix touched (aggregates only).

The CVE-fix data holds few web files, and the mined unchanged files are all Python, JavaScript and TypeScript, so the
false-alarm rate of the web rules is measured here on whole directory trees instead: third-party packages installed on
the cluster (Python site-packages, node_modules), which hold real ``.html``, ``.css``, ``.vue`` and ``.svelte`` files.
They are library files, partly vendored and built, not application code, and a finding in them may be real; the number
is an upper bound on false alarms for hand-written code, not a measured false-alarm rate. Each file goes through
``scan_text`` as one file (no directory walk, so ``node_modules`` and ``site-packages`` are not skipped); files over
1 MiB and minified files are counted as skipped, as the scanner does, and a file whose text was already seen is
counted once.
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from pathlib import Path
from typing import Any

from kestrix_scan.analyze import scan_text
from kestrix_scan.walk import MAX_FILE_BYTES, Candidate, Unreadable, read_text

from .common import P4_EXTENSIONS, PHP_EXTENSIONS, WEB_EXTENSIONS, Layout, write_json

MAX_FILES = 200_000


def web_corpus(layout: Layout, roots: list[Path], label: str) -> Path:
    """Scan every web file under ``roots`` and write ``reports/codebench-webcorpus-LABEL.json``."""
    return corpus_scan(layout, roots, label, WEB_EXTENSIONS, "webcorpus")


def php_corpus(layout: Layout, roots: list[Path], label: str) -> Path:
    """Scan every PHP, PHTML and SQL file under ``roots`` (third-party libraries, no CVE fix touched them) and write
    ``reports/codebench-phpcorpus-LABEL.json``: findings per KLOC per rule, an upper bound on false alarms."""
    return corpus_scan(layout, roots, label, (*PHP_EXTENSIONS, ".sql"), "phpcorpus")


def p4_corpus(layout: Layout, roots: list[Path], label: str) -> Path:
    """Scan every Go, Java, Kotlin, C#, Ruby and ERB file under ``roots`` (shallow clones of popular projects, no CVE
    fix touched them) and write ``reports/codebench-p4corpus-LABEL.json``: findings per KLOC per rule and extension."""
    return corpus_scan(layout, roots, label, P4_EXTENSIONS, "p4corpus")


def corpus_scan(layout: Layout, roots: list[Path], label: str, extensions: tuple[str, ...], prefix: str) -> Path:
    files: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    lines: Counter[str] = Counter()
    rules: dict[str, Counter[str]] = {}
    total = 0
    seen: set[str] = set()
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                ext = Path(name).suffix.lower()
                if ext not in extensions or total >= MAX_FILES:
                    continue
                path = Path(dirpath) / name
                total += 1
                candidate = Candidate(path=path, rel=name)
                try:
                    text = read_text(candidate, MAX_FILE_BYTES)
                except Unreadable as exc:
                    skipped[f"{ext}:{exc.reason}"] += 1
                    continue
                digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
                if digest in seen:
                    skipped[f"{ext}:duplicate"] += 1
                    continue
                seen.add(digest)
                findings, _, _, skip = scan_text(text, candidate)
                if skip is not None:
                    skipped[f"{ext}:{skip.reason}"] += 1
                    continue
                files[ext] += 1
                lines[ext] += text.count("\n") + 1
                for finding in findings:
                    if not finding.rule_id.startswith("secret."):
                        rules.setdefault(finding.rule_id, Counter())[ext] += 1
    kloc = {ext: round(n / 1000, 1) for ext, n in sorted(lines.items())}
    total_kloc = sum(lines.values()) / 1000
    body: dict[str, Any] = {
        "schema_version": 1,
        "label": label,
        "roots": [root.name for root in roots],
        "files_scanned": dict(sorted(files.items())),
        "files_skipped": dict(sorted(skipped.items())),
        "kloc": kloc,
        "rules": {
            rule: {
                "findings": sum(per_ext.values()),
                "per_kloc": round(sum(per_ext.values()) / total_kloc, 4) if total_kloc else None,
                "by_extension": dict(sorted(per_ext.items())),
            }
            for rule, per_ext in sorted(rules.items())
        },
        "all_rules_per_kloc": round(sum(sum(c.values()) for c in rules.values()) / total_kloc, 4)
        if total_kloc
        else None,
    }
    path = layout.reports / f"codebench-{prefix}-{label}.json"
    write_json(path, body)
    return path
