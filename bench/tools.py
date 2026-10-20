# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Run each scanner on a directory and reduce its JSON report to ``Finding`` records.

Every tool scans the same root with that root as its working directory, so report paths are relative to it. Raw
reports stay in the cache next to the results; only the reduced records are scored. Bandit and Semgrep CE run from
an isolated virtual environment in the cache, never from the project environment.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .mapping import bandit_categories, categories_for_cwes, kestrix_categories, security_guidance_categories
from .scoring import Finding

TOOL_TIMEOUT_S = 1800
_CWE = re.compile(r"CWE-(\d+)")


@dataclass(frozen=True)
class ToolRun:
    tool: str
    version: str
    seconds: float
    findings: list[Finding]
    reports_cwe: bool  # False: the tool reports no CWEs, so it has no strict-CWE score
    rule_hits: dict[str, int] = field(default_factory=dict)  # findings per rule that maps to a category


class ToolError(RuntimeError):
    pass


def _run(args: list[str], cwd: Path, ok: tuple[int, ...] = (0,)) -> float:
    start = time.perf_counter()
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        args, cwd=cwd, capture_output=True, text=True, timeout=TOOL_TIMEOUT_S, check=False
    )
    seconds = time.perf_counter() - start
    if proc.returncode not in ok:
        raise ToolError(f"{Path(args[0]).name} exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")
    return seconds


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _clean(path: str) -> str:
    return path[2:] if path.startswith("./") else path


def _hits(findings: list[Finding]) -> dict[str, int]:
    return dict(sorted(Counter(f.rule for f in findings if f.categories).items()))


def kestrix(root: Path, report: Path) -> ToolRun:
    """kestrix-scan from the project environment (the checked-out HEAD), with its configuration ignored."""
    args = [sys.executable, "-m", "kestrix_scan", "scan", ".", "--no-config", "--fail-on", "none"]
    seconds = _run([*args, "--format", "json", "--output", str(report)], root)
    from kestrix_scan import __version__

    findings = []
    for item in _load(report)["findings"]:
        cwes = frozenset(int(c) for c in _CWE.findall(item.get("cwe") or ""))
        findings.append(Finding(item["path"], item["rule_id"], cwes, kestrix_categories(item["rule_id"], cwes)))
    return ToolRun("kestrix", __version__, seconds, findings, True, _hits(findings))


def bandit(venv: Path, root: Path, report: Path) -> ToolRun:
    """Bandit with its defaults (every test, every severity and confidence), recursively."""
    exe = venv / "bin" / "bandit"
    seconds = _run([str(exe), "-r", ".", "-f", "json", "-o", str(report), "-q", "--exit-zero"], root)
    version = subprocess.run(  # noqa: S603
        [str(exe), "--version"], capture_output=True, text=True, check=True
    ).stdout.split()[1]
    findings = []
    for item in _load(report)["results"]:
        cwe = (item.get("issue_cwe") or {}).get("id")
        cwes = frozenset({int(cwe)}) if cwe else frozenset()
        findings.append(
            Finding(_clean(item["filename"]), item["test_id"], cwes, bandit_categories(item["test_id"], cwes))
        )
    return ToolRun("bandit", version, seconds, findings, True, _hits(findings))


def semgrep(venv: Path, rules: Path, root: Path, report: Path) -> ToolRun:
    """Semgrep CE on a local copy of the ``p/python`` ruleset, with metrics and version checks off."""
    exe = venv / "bin" / "semgrep"
    args = [str(exe), "scan", "--config", str(rules), "--json", "--output", str(report)]
    seconds = _run([*args, "--metrics=off", "--disable-version-check", "--quiet", "."], root)
    version = subprocess.run(  # noqa: S603
        [str(exe), "--version", "--disable-version-check"], capture_output=True, text=True, check=True
    ).stdout.strip()
    findings = []
    for item in _load(report)["results"]:
        meta = (item.get("extra") or {}).get("metadata") or {}
        raw = meta.get("cwe") or []
        cwes = frozenset(int(c) for c in _CWE.findall(" ".join(raw) if isinstance(raw, list) else str(raw)))
        findings.append(Finding(_clean(item["path"]), item["check_id"], cwes, categories_for_cwes(cwes)))
    return ToolRun("semgrep", version, seconds, findings, True, _hits(findings))


def security_guidance(patterns: Path, version: str, root: Path, report: Path) -> ToolRun:
    """The regex layer of Anthropic's security-guidance plugin, applied to every file as one Write of its content."""
    adapter = Path(__file__).with_name("sg_regex.py")
    seconds = _run([sys.executable, "-I", str(adapter), str(patterns), ".", str(report)], root)
    findings = [
        Finding(item["path"], item["rule"], frozenset(), security_guidance_categories(item["rule"]))
        for item in _load(report)
    ]
    return ToolRun("security-guidance", version, seconds, findings, False, _hits(findings))
