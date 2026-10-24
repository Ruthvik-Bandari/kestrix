# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Benchmark kestrix-scan, Bandit, Semgrep CE and the security-guidance regex layer.

``uv run python -m kestrixscanbench.run [--suite benchmarkpython|owned|heldout|all] [--tools LIST] [--cache DIR] [--out DIR]
[--publish DIR]`` and ``uv run python -m kestrixscanbench.run --print-mapping``.

Everything third-party is downloaded into the cache (default ``research/scanbench/.cache/``, git-ignored), never into the repo:

- OWASP BenchmarkPython (GPL-3.0) at a pinned commit, by a shallow ``git fetch`` of that commit;
- Bandit and Semgrep CE at pinned versions, into their own virtual environment made with ``uv``;
- Semgrep's ``p/python`` ruleset (Semgrep Rules License: internal use), saved once and hashed;
- the security-guidance plugin's ``hooks/patterns.py`` (Apache-2.0) at a pinned commit, checked by SHA-256.

``--out`` gets ``<suite>.json`` (every tool) and ``<suite>.md`` (tables). ``--publish DIR`` also writes
``DIR/<suite>.json`` and ``<out>/<suite>.public.md`` restricted to the tools in ``PUBLISHABLE``: Semgrep's numbers
stay out of committed results (see the scorecard).
Results hold only test-case names, categories, CWEs, booleans, counts, rates, versions and timings. Published results
also carry ``research/scanbench/history.json``: earlier Kestrix results for the suite and the disclosure that later rule changes
were informed by the BenchmarkPython gap analysis.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import tools
from .mapping import CATEGORIES, markdown_tables
from .scoring import Case, Scorecard, case_of, parse_expected, score

REPO = Path(__file__).resolve().parents[2]
DATA = REPO / "research" / "scanbench"  # owned cases and history; downloads go to its git-ignored .cache
DEFAULT_CACHE = DATA / ".cache"
OWNED_CASES = DATA / "cases"
HELDOUT_CASES = OWNED_CASES / "heldout"  # written before the gap-analysis rule changes were measured
HISTORY = DATA / "history.json"  # earlier published Kestrix results and the tuning disclosure

BENCHMARK_PYTHON = {
    "repository": "https://github.com/OWASP-Benchmark/BenchmarkPython",
    "commit": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",  # main on 2026-05-19, v0.1 test suite
    "license": "GPL-3.0",
    "expected": "expectedresults-0.1.csv",
    "scanned": "testcode",
}
BANDIT_VERSION = "1.9.4"
SEMGREP_VERSION = "1.178.0"
SEMGREP_RULESET_URL = "https://semgrep.dev/c/p/python"
TOOLS_PYTHON = "3.12"
SECURITY_GUIDANCE = {
    "repository": "https://github.com/anthropics/claude-plugins-official",
    "commit": "a0b04d9ddccaabe1976645f68b0eda50f74e7022",  # main on 2026-10-20; plugin version 2.0.14
    "path": "plugins/security-guidance/hooks/patterns.py",
    "sha256": "8cd874aa113801f869679045e0b38b669988b6a7d33b611b10ef01f474ca1eef",
    "version": "2.0.14",
    "license": "Apache-2.0",
}
ALL_TOOLS = ("kestrix", "bandit", "semgrep", "security-guidance")
PUBLISHABLE = ("kestrix", "bandit", "security-guidance")
NET_TIMEOUT_S = 120


class BenchError(RuntimeError):
    pass


def _cmd(args: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)  # noqa: S603
    if proc.returncode != 0:
        raise BenchError(f"{' '.join(args[:3])} failed: {proc.stderr.strip()[-1000:]}")
    return proc.stdout.strip()


def _download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise BenchError(f"refusing a non-HTTPS download: {url}")
    with urllib.request.urlopen(url, timeout=NET_TIMEOUT_S) as response:  # noqa: S310 - https only, checked above
        data: bytes = response.read()
    return data


def fetch_benchmark_python(cache: Path) -> Path:
    """A detached checkout of the pinned commit; refetched only if the checkout is missing or moved."""
    git = shutil.which("git") or "git"
    dest = cache / "BenchmarkPython"
    commit = BENCHMARK_PYTHON["commit"]
    if (dest / ".git").is_dir() and _cmd([git, "rev-parse", "HEAD"], dest) == commit:
        return dest
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    _cmd([git, "init", "-q"], dest)
    _cmd([git, "fetch", "-q", "--depth", "1", BENCHMARK_PYTHON["repository"], commit], dest)
    _cmd([git, "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"], dest)
    if _cmd([git, "rev-parse", "HEAD"], dest) != commit:
        raise BenchError("BenchmarkPython checkout does not match the pinned commit")
    return dest


def ensure_tool_venv(cache: Path) -> Path:
    """Bandit and Semgrep CE at pinned versions in ``<cache>/tools``, made with uv; reused while the pins match."""
    venv = cache / "tools"
    pins = [f"bandit=={BANDIT_VERSION}", f"semgrep=={SEMGREP_VERSION}"]
    marker = venv / "kestrix-bench-pins.txt"
    if marker.is_file() and marker.read_text() == "\n".join(pins):
        return venv
    uv = shutil.which("uv")
    if uv is None:
        raise BenchError("uv is required to build the tool environment")
    shutil.rmtree(venv, ignore_errors=True)
    _cmd([uv, "venv", "-q", "--python", TOOLS_PYTHON, str(venv)])
    _cmd([uv, "pip", "install", "-q", "--python", str(venv / "bin" / "python"), *pins])
    marker.write_text("\n".join(pins))
    return venv


def tool_freeze(venv: Path) -> list[str]:
    uv = shutil.which("uv") or "uv"
    return _cmd([uv, "pip", "freeze", "--python", str(venv / "bin" / "python")]).splitlines()


def ensure_semgrep_rules(cache: Path) -> Path:
    """The ``p/python`` ruleset, downloaded once. The registry is not versioned, so its SHA-256 is recorded."""
    path = cache / "semgrep" / "p-python.yml"
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_download(SEMGREP_RULESET_URL))
    return path


def ensure_security_guidance(cache: Path) -> Path:
    path = cache / "security-guidance" / SECURITY_GUIDANCE["commit"] / "patterns.py"
    if not path.is_file():
        repo = SECURITY_GUIDANCE["repository"].replace("https://github.com/", "https://raw.githubusercontent.com/")
        data = _download(f"{repo}/{SECURITY_GUIDANCE['commit']}/{SECURITY_GUIDANCE['path']}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if _sha256(path) != SECURITY_GUIDANCE["sha256"]:
        raise BenchError("security-guidance patterns.py does not match the pinned SHA-256")
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class Suite:
    name: str
    root: Path  # scanned directory; report paths are relative to it
    cases: list[Case]
    source: dict[str, Any]


def benchmark_python_suite(cache: Path) -> Suite:
    checkout = fetch_benchmark_python(cache)
    expected = checkout / BENCHMARK_PYTHON["expected"]
    cases = parse_expected(expected.read_text(encoding="utf-8"))
    return Suite("benchmarkpython", checkout / BENCHMARK_PYTHON["scanned"], cases, dict(BENCHMARK_PYTHON))


def owned_suite() -> Suite:
    cases = parse_expected((OWNED_CASES / "expected.csv").read_text(encoding="utf-8"))
    source = {
        "path": "research/scanbench/cases",
        "license": "Apache-2.0",
        "expected": "research/scanbench/cases/expected.csv",
    }
    return Suite("owned", OWNED_CASES, cases, source)


def heldout_suite() -> Suite:
    cases = parse_expected((HELDOUT_CASES / "expected.csv").read_text(encoding="utf-8"))
    source = {
        "path": "research/scanbench/cases/heldout",
        "license": "Apache-2.0",
        "expected": "research/scanbench/cases/heldout/expected.csv",
    }
    return Suite("heldout", HELDOUT_CASES, cases, source)


def _git_head() -> dict[str, Any]:
    git = shutil.which("git") or "git"
    try:
        commit = _cmd([git, "rev-parse", "HEAD"], REPO)
        dirty = bool(_cmd([git, "status", "--porcelain", "--", "packages/kestrix-scan"], REPO))
    except (BenchError, OSError):
        return {"commit": None, "scanner_dirty": None}
    return {"commit": commit, "scanner_dirty": dirty}


def machine() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": _cpu_name(),
        "cpus": os.cpu_count(),
        "python": platform.python_version(),
    }


def _cpu_name() -> str:
    if sys.platform == "darwin":
        try:
            return _cmd(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"])
        except (BenchError, OSError):
            pass
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor()


def _r(x: float) -> float:
    return round(x, 4)


def card_json(card: Scorecard) -> dict[str, Any]:
    cats = {
        name: {
            "tp": c.tp,
            "fn": c.fn,
            "fp": c.fp,
            "tn": c.tn,
            "tpr": _r(c.tpr),
            "fpr": _r(c.fpr),
            "score": _r(c.score),
        }
        for name, c in card.categories.items()
    }
    overall = {"tpr": _r(card.tpr), "fpr": _r(card.fpr), "score": _r(card.score), "precision": _r(card.precision)}
    return {"overall": overall, "categories": cats}


def evaluate(suite: Suite, runs: list[tools.ToolRun]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for run in runs:
        primary = score(suite.cases, run.findings, "category")
        strict = score(suite.cases, run.findings, "strict") if run.reports_cwe else None
        in_cases = {c.name for c in suite.cases}
        out[run.tool] = {
            "version": run.version,
            "seconds": round(run.seconds, 2),
            "findings": len(run.findings),
            "rule_hits": run.rule_hits,
            "category": card_json(primary),
            "strict_cwe": card_json(strict) if strict else None,
            "flagged": sorted(primary.flagged & in_cases),
        }
    return out


def _pct(x: float) -> str:
    return f"{100 * x:.1f}"


def tables(result: dict[str, Any]) -> str:
    """Markdown summary and per-category tables for one suite's result."""
    names = list(result["tools"])
    lines = [
        "| Tool | Version | TPR % | FPR % | Score (TPR-FPR) | Precision % | Strict-CWE score | Runtime s |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in names:
        t = result["tools"][name]
        o = t["category"]["overall"]
        strict = _pct(t["strict_cwe"]["overall"]["score"]) if t["strict_cwe"] else "n/a"
        row = [name, f"`{t['version']}`", _pct(o["tpr"]), _pct(o["fpr"]), _pct(o["score"])]
        lines.append("| " + " | ".join([*row, _pct(o["precision"]), strict, f"{t['seconds']:.1f}"]) + " |")
    header = "| Category | Cases (vuln/safe) | " + " | ".join(names) + " |"
    lines += ["", header, "| --- | --- |" + " ---: |" * len(names)]
    for cat, total in result["cases_per_category"].items():
        cells = []
        for name in names:
            c = result["tools"][name]["category"]["categories"][cat]
            cells.append(f"{_pct(c['score'])} ({c['tp']}/{c['fn']}/{c['fp']}/{c['tn']})")
        label = CATEGORIES.get(cat, cat)
        lines.append(f"| {label} (`{cat}`) | {total['vulnerable']}/{total['safe']} | " + " | ".join(cells) + " |")
    lines += ["", "Cells: score in percentage points, then (TP/FN/FP/TN)."]
    return "\n".join(lines) + "\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def run_suite(suite: Suite, selected: list[str], cache: Path) -> dict[str, Any]:
    reports = cache / "reports" / suite.name
    reports.mkdir(parents=True, exist_ok=True)
    venv = ensure_tool_venv(cache) if {"bandit", "semgrep"} & set(selected) else None
    runners: dict[str, Callable[[], tools.ToolRun]] = {
        "kestrix": lambda: tools.kestrix(suite.root, reports / "kestrix.json"),
        "bandit": lambda: tools.bandit(_need(venv), suite.root, reports / "bandit.json"),
        "semgrep": lambda: tools.semgrep(
            _need(venv), ensure_semgrep_rules(cache), suite.root, reports / "semgrep.json"
        ),
        "security-guidance": lambda: tools.security_guidance(
            ensure_security_guidance(cache), SECURITY_GUIDANCE["version"], suite.root, reports / "sg.json"
        ),
    }
    runs = []
    names = {case.name: case for case in suite.cases}
    for name in selected:
        print(f"[{suite.name}] running {name} ...", file=sys.stderr, flush=True)
        run = runners[name]()
        # The owned suite's directory also holds the held-out cases; count only findings in this suite's cases.
        kept = [f for f in run.findings if case_of(f.path, names) is not None]
        runs.append(dataclasses.replace(run, findings=kept, rule_hits=tools.count_rule_hits(kept)))
    per_cat: dict[str, dict[str, int]] = {}
    for case in suite.cases:
        entry = per_cat.setdefault(case.category, {"vulnerable": 0, "safe": 0})
        entry["vulnerable" if case.real else "safe"] += 1
    environment: dict[str, Any] = {
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "machine": machine(),
        "kestrix": _git_head(),
    }
    if venv is not None:
        environment["tool_environment"] = tool_freeze(venv)
    if "semgrep" in selected:
        environment["semgrep_ruleset"] = {
            "url": SEMGREP_RULESET_URL,
            "sha256": _sha256(cache / "semgrep" / "p-python.yml"),
        }
    if "security-guidance" in selected:
        environment["security_guidance"] = {k: SECURITY_GUIDANCE[k] for k in ("repository", "commit", "path", "sha256")}
    return {
        "schema_version": 1,
        "generated_by": "Kestrix by Ruthvik Bandari",
        "suite": suite.name,
        "source": suite.source,
        "cases": len(suite.cases),
        "cases_per_category": dict(sorted(per_cat.items())),
        "modes": {
            "category": "primary: findings map to categories through src/kestrixscanbench/mapping.py",
            "strict_cwe": "BenchmarkUtils rule: a reported CWE must equal the case CWE; null if the tool reports none",
        },
        "environment": environment,
        "tools": evaluate(suite, runs),
    }


def _need(venv: Path | None) -> Path:
    if venv is None:
        raise BenchError("tool environment missing")
    return venv


def publishable(result: dict[str, Any], history: dict[str, Any] | None = None) -> dict[str, Any]:
    """The result without Semgrep, with this suite's earlier Kestrix results and the disclosure from ``history``."""
    out = dict(result)
    if history is not None:
        out["disclosure"] = history["disclosure"]
        out["history"] = history.get(result["suite"], [])
    out["tools"] = {k: v for k, v in result["tools"].items() if k in PUBLISHABLE}
    env = dict(result["environment"])
    env.pop("semgrep_ruleset", None)
    # The shared venv's full freeze would list Semgrep's dependencies too; publish only the published tools' pins.
    env["tool_environment"] = [
        line for line in env.get("tool_environment", []) if line.split("==")[0].lower() in PUBLISHABLE
    ]
    out["environment"] = env
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kestrixscanbench.run", description=__doc__.split("\n\n")[0])
    parser.add_argument("--suite", choices=["benchmarkpython", "owned", "heldout", "all"], default="all")
    parser.add_argument("--tools", default=",".join(ALL_TOOLS), help=f"comma-separated subset of {ALL_TOOLS}")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--out", type=Path, default=None, help="default: <cache>/results")
    parser.add_argument("--publish", type=Path, default=None, help="also write publishable results here")
    parser.add_argument("--print-mapping", action="store_true", help="print the mapping tables and exit")
    args = parser.parse_args(argv)
    if args.print_mapping:
        print(markdown_tables(), end="")
        return 0
    selected = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = sorted(set(selected) - set(ALL_TOOLS))
    if unknown or not selected:
        parser.error(f"unknown tools {unknown}; choose from {ALL_TOOLS}")
    cache = args.cache.resolve()
    out_dir = (args.out or cache / "results").resolve()
    suites = []
    if args.suite in ("benchmarkpython", "all"):
        suites.append(benchmark_python_suite(cache))
    if args.suite in ("owned", "all"):
        suites.append(owned_suite())
    if args.suite in ("heldout", "all"):
        suites.append(heldout_suite())
    for suite in suites:
        result = run_suite(suite, selected, cache)
        _write(out_dir / f"{suite.name}.json", json.dumps(result, indent=2) + "\n")
        _write(out_dir / f"{suite.name}.md", tables(result))
        print(tables(result))
        if args.publish is not None:
            history = json.loads(HISTORY.read_text(encoding="utf-8")) if HISTORY.is_file() else None
            public = publishable(result, history)
            _write(args.publish / f"{suite.name}.json", json.dumps(public, indent=2) + "\n")
            _write(out_dir / f"{suite.name}.public.md", tables(public))
    return 0


if __name__ == "__main__":
    sys.exit(main())
