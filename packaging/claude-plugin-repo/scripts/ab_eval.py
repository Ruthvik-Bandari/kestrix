# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Run the paired A/B eval of the Kestrix plugin and turn its results into the report.

    python3 scripts/ab_eval.py run [--runs 5] [--model MODEL] [--max-cost-usd 40] [--out DIR] [--dry-run]
    python3 scripts/ab_eval.py report DIR/results.json [--out docs/benchmarks/plugin-ab.md] [--scan]

``run`` calls ``claude plugin eval`` on the 13 cases in ``evals/ab`` (tag ``ab``), each with and without the
plugin (``--ablation with-without``). Every run is a real model call on your account; the cost estimate is in
``evals/README.md``. ``--dry-run`` prints the command and calls nothing.

``report`` reads the eval's result document and computes, for each arm:

- vulnerable-code-shipped rate: runs whose final file fails the case's ``final-clean`` grader, of the runs that
  wrote the file;
- fix-after-finding rate: of the runs whose Write already held the vulnerable code (``no-vulnerable-write``
  failed), the share whose final file is clean. With the plugin this is the hook's finding being acted on; the
  same figure without the plugin is how often Claude fixes its own code unprompted;
- false-interruption rate on the two safe control tasks: runs that wrote the file twice or edited it;
- tokens and turns per task, when the result document carries them.

With ``--scan`` it also runs ``kestrix-scan`` on each run's final file (deterministic) when the results carry the
run's workspace directory (``run`` passes ``--keep-temp``), and reports the scanner's vulnerable-shipped rate next
to the regex graders'.

The result document's schema is documented only in part (``schemaVersion`` 1: ``cases[].name``,
``cases[].arms.with[]`` and ``arms.without[]``, ``costUsd``). The per-run keys read here (grader results with
``name`` and ``passed``, token and turn counts, a workspace directory) are looked up by name and anything not
found is reported as ``n/a``, never guessed. Confirm them on a one-case run first (see ``evals/README.md``).
Standard library only; Python 3.9 or later.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARMS = ("with", "without")
MARK_START, MARK_END = "<!-- results:start -->", "<!-- results:end -->"
TOKEN_KEYS = ("totaltokens", "tokens")
TURN_KEYS = ("turns", "numturns", "num_turns")
DIR_HINTS = ("workdir", "workspace", "sandbox", "tempdir", "temp_dir", "cwd", "path", "dir")
SEVERE = ("medium", "high", "critical")


def command(runs: int, model: str | None, max_cost: float, out: Path) -> list[str]:
    """The ``claude plugin eval`` argument list for the full paired suite."""
    argv = ["claude", "plugin", "eval", ".", "--tag", "ab", "--runs", str(runs), "--ablation", "with-without"]
    argv += ["--allow-tools", "Write", "Edit", "--trust-plugin", "--keep-temp", "--no-publish"]
    argv += ["--max-cost-usd", f"{max_cost:g}", "--output-dir", str(out), "--json", str(out / "results.json")]
    if model:
        argv += ["--model", model]
    return argv


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def graders(run: dict[str, Any]) -> dict[str, bool]:
    """Grader name -> passed for one run, from any list of ``{name, passed}`` objects in it."""
    found: dict[str, bool] = {}
    for node in _walk(run):
        name = node.get("name") or node.get("grader") or node.get("id")
        if isinstance(name, str) and isinstance(node.get("passed"), bool):
            found[name.removesuffix(".md")] = node["passed"]
    return found


def _number(run: dict[str, Any], keys: tuple[str, ...]) -> float | None:
    for node in _walk(run):
        for key, value in node.items():
            if key.lower() in keys and isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value)
    return None


def tokens(run: dict[str, Any]) -> float | None:
    total = _number(run, TOKEN_KEYS)
    if total is not None:
        return total
    parts = [_number(run, (key,)) for key in ("inputtokens", "outputtokens")]
    return sum(p for p in parts if p is not None) if any(p is not None for p in parts) else None


def workdir(run: dict[str, Any]) -> Path | None:
    for node in _walk(run):
        for key, value in node.items():
            if isinstance(value, str) and any(hint in key.lower() for hint in DIR_HINTS) and Path(value).is_dir():
                return Path(value)
    return None


def scanner_severe(directory: Path, filename: str) -> bool | None:
    """True when kestrix-scan reports a medium-or-worse finding in ``filename``; None when it cannot say."""
    exe = shutil.which("kestrix-scan")
    target = directory / filename
    if exe is None or not target.is_file():
        return None
    done = subprocess.run(  # noqa: S603  (the resolved kestrix-scan, an argument list, no shell)
        [exe, str(target), "--format", "json", "--fail-on", "none"], capture_output=True, text=True, check=False
    )
    try:
        findings = json.loads(done.stdout)["findings"]
    except (ValueError, KeyError, TypeError):
        return None
    return any(f.get("severity") in SEVERE for f in findings)


def _rate(hits: int, total: int) -> str:
    return f"{hits}/{total} ({100 * hits / total:.0f}%)" if total else "n/a"


def _mean(values: list[float]) -> str:
    return f"{sum(values) / len(values):,.1f}" if values else "n/a"


def summarize(results: dict[str, Any], *, scan: bool, files: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Per-arm counts. ``files`` maps case name to the file its graders read (for ``--scan``)."""
    out: dict[str, dict[str, Any]] = {}
    for arm in ARMS:
        a = {"runs": 0, "written": 0, "shipped": 0, "wrote_vuln": 0, "fixed": 0, "ctl_runs": 0, "ctl_bad": 0}
        a.update(scan_n=0, scan_shipped=0, tokens=[], turns=[], per_case={})
        for case in results.get("cases", []):
            control = "control" in case["name"] or "safe" in case["name"]
            for run in case.get("arms", {}).get(arm, []):
                g = graders(run)
                a["runs"] += 1
                if (t := tokens(run)) is not None:
                    a["tokens"].append(t)
                if (n := _number(run, TURN_KEYS)) is not None:
                    a["turns"].append(n)
                if control:
                    a["ctl_runs"] += 1
                    a["ctl_bad"] += (not g.get("no-edit", True)) or (not g.get("single-write", True))
                    continue
                if not g.get("file-written", False):
                    continue
                a["written"] += 1
                dirty = not g.get("final-clean", True)
                a["shipped"] += dirty
                cell = a["per_case"].setdefault(case["name"], [0, 0])
                cell[0] += dirty
                cell[1] += 1
                if "no-vulnerable-write" in g and not g["no-vulnerable-write"]:
                    a["wrote_vuln"] += 1
                    a["fixed"] += not dirty
                directory = workdir(run) if scan else None
                verdict = scanner_severe(directory, files[case["name"]]) if directory else None
                if verdict is not None:
                    a["scan_n"] += 1
                    a["scan_shipped"] += verdict
        out[arm] = a
    return out


def render(results: dict[str, Any], summary: dict[str, dict[str, Any]], *, scan: bool) -> str:
    w, wo = summary["with"], summary["without"]
    rows = [
        ("Runs", str(w["runs"]), str(wo["runs"])),
        ("Vulnerable code shipped", _rate(w["shipped"], w["written"]), _rate(wo["shipped"], wo["written"])),
        (
            "Fix after finding (Write held the vulnerable code, final file clean)",
            _rate(w["fixed"], w["wrote_vuln"]),
            _rate(wo["fixed"], wo["wrote_vuln"]),
        ),
        ("False interruption on safe tasks", _rate(w["ctl_bad"], w["ctl_runs"]), _rate(wo["ctl_bad"], wo["ctl_runs"])),
        ("Tokens per task (mean)", _mean(w["tokens"]), _mean(wo["tokens"])),
        ("Turns per task (mean)", _mean(w["turns"]), _mean(wo["turns"])),
    ]
    if scan:
        rows.insert(
            2,
            (
                "Vulnerable code shipped, by `kestrix-scan` on the final file",
                _rate(w["scan_shipped"], w["scan_n"]),
                _rate(wo["scan_shipped"], wo["scan_n"]),
            ),
        )
    lines = [
        f"Run on {results.get('claudeVersion', 'an unknown Claude Code version')}; "
        f"estimated cost {results.get('costUsd', 'n/a')} USD; partial: {results.get('partial', False)}.",
        "",
        "| Metric | With plugin | Without plugin |",
        "| --- | ---: | ---: |",
        *(f"| {name} | {a} | {b} |" for name, a, b in rows),
        "",
        "Vulnerable code shipped, per task (runs whose final file failed the grader, of runs that wrote it):",
        "",
        "| Task | With plugin | Without plugin |",
        "| --- | ---: | ---: |",
    ]
    for case in sorted(set(w["per_case"]) | set(wo["per_case"])):
        cells = [w["per_case"].get(case, [0, 0]), wo["per_case"].get(case, [0, 0])]
        lines.append(f"| `{case}` | {_rate(*cells[0])} | {_rate(*cells[1])} |")
    return "\n".join(lines)


def write_report(path: Path, body: str) -> None:
    """Put ``body`` between the result markers of the report template at ``path``."""
    text = path.read_text(encoding="utf-8")
    head, _, rest = text.partition(MARK_START)
    _, _, tail = rest.partition(MARK_END)
    if not rest:
        raise SystemExit(f"{path} has no {MARK_START} marker")
    path.write_text(f"{head}{MARK_START}\n\n{body}\n\n{MARK_END}{tail}", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run", help="run the paired suite with claude plugin eval")
    run.add_argument("--runs", type=int, default=5, help="runs per case per arm (default 5)")
    run.add_argument("--model", help="pin the model for the agent under test")
    run.add_argument("--max-cost-usd", type=float, default=40.0, help="stop starting runs past this estimate")
    run.add_argument("--out", type=Path, default=ROOT / "evals" / "results" / "ab", help="output directory")
    run.add_argument("--dry-run", action="store_true", help="print the command and call nothing")
    report = sub.add_parser("report", help="compute the metrics from a results document")
    report.add_argument("results", type=Path)
    report.add_argument("--out", type=Path, help="report template to fill in (docs/benchmarks/plugin-ab.md)")
    report.add_argument("--scan", action="store_true", help="also grade final files with kestrix-scan")
    args = parser.parse_args(argv)
    if args.action == "run":
        argv_eval = command(args.runs, args.model, args.max_cost_usd, args.out)
        print(" ".join(argv_eval))
        if args.dry_run:
            return 0
        args.out.mkdir(parents=True, exist_ok=True)
        return subprocess.run(argv_eval, cwd=ROOT, check=False).returncode  # noqa: S603
    results = json.loads(args.results.read_text(encoding="utf-8"))
    files = {}
    for prompt in (ROOT / "evals" / "ab").glob("*/prompt.md"):
        for grader in (prompt.parent / "graders").glob("file-written.md"):
            files[prompt.parent.name] = next(
                line.split(":", 1)[1].strip() for line in grader.read_text().splitlines() if line.startswith("path:")
            )
    body = render(results, summarize(results, scan=args.scan, files=files), scan=args.scan)
    if args.out:
        write_report(args.out, body)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
