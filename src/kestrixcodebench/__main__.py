# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``python -m kestrixcodebench COMMAND --root DIR``: kestrix-scan accuracy on CVE-fix file pairs (offline).

``build`` reads the data ``kestrixvul`` acquired (CVEfixes working database, mined advisory commits), filters, splits
into dev and a locked test and writes the files. ``scan`` runs one tool on dev shards (a Slurm array task);
``dev-metrics`` writes the dev report; ``compare`` writes the paired change between two kestrix runs; ``examples`` lists ids of missed pairs for hand analysis on the cluster;
``table`` prints Markdown tables from a report; ``locked-test`` claims the lock and evaluates the test split once.
Reports hold counts, rates, intervals and rule ids only. Exit status is 1 on failure.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .common import SHARDS, CodeBenchError, Layout

COMMANDS = ("build", "scan", "dev-metrics", "compare", "examples", "table", "locked-test")


def _runs(items: list[str] | None, default: str, tools: tuple[str, ...]) -> dict[str, str]:
    runs = dict.fromkeys(tools, default)
    for item in items or []:
        tool, _, run = item.partition("=")
        if tool not in runs or not run:
            raise CodeBenchError(f"--run expects TOOL=RUN with TOOL in {', '.join(runs)}")
        runs[tool] = run
    return runs


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kestrixcodebench", description=__doc__)
    p.add_argument("command", choices=COMMANDS)
    p.add_argument("--root", type=Path, help="benchmark root, for example /scratch/$USER/kestrix/codebench")
    p.add_argument("--cvefixes-db", type=Path, help="build: kestrixvul's work/cvefixes.sqlite")
    p.add_argument("--vul-root", type=Path, help="build: kestrixvul's root (work/ghsa.jsonl, mine/)")
    p.add_argument("--limit", type=int, help="build: at most this many changed files per source (smoke runs)")
    p.add_argument("--tool", help="scan: kestrix, bandit or eslint; examples: the tool to analyse")
    p.add_argument("--shard", type=int, help="scan: shard number, or omit to scan every shard in turn")
    p.add_argument("--run", default="base", help="scan: run name for the output; dev-metrics: default run per tool")
    p.add_argument("--tool-run", action="append", help="dev-metrics: TOOL=RUN to read a tool from another run")
    p.add_argument("--label", default="base", help="dev-metrics, compare: name of the report")
    p.add_argument(
        "--base-run", default="base", help="compare: the kestrix run to compare against (--run is the new one)"
    )
    p.add_argument("--bootstrap", type=int, default=1000)
    p.add_argument("--family", help="examples: family to list")
    p.add_argument("--count", type=int, default=8, help="examples: how many")
    p.add_argument("--report", type=Path, help="table: a dev or locked report")
    p.add_argument("--name", default="codebench-v1", help="locked-test: name of this evaluation")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    os.umask(0o077)
    try:
        return _run(args)
    except CodeBenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _need(value: object, flag: str) -> None:
    if not value:
        raise SystemExit(f"this command needs {flag}")


def _run(args: argparse.Namespace) -> int:
    code_sha = os.environ.get("KESTRIX_CODEBENCH_SHA", "unknown")
    if args.command == "table":
        from .report import markdown

        _need(args.report, "--report")
        sys.stdout.write(markdown(json.loads(args.report.read_text(encoding="utf-8"))))
        return 0
    _need(args.root, "--root")
    layout = Layout(args.root)
    if args.command == "build":
        from .build import build

        _need(args.cvefixes_db and args.vul_root, "--cvefixes-db and --vul-root")
        body = build(layout, args.cvefixes_db, args.vul_root, args.limit)
        print(
            json.dumps(
                {
                    s: {k: v[k] for k in ("pairs", "projects", "cves", "unchanged_files")}
                    for s, v in body["splits"].items()
                }
            )
        )
        return 0
    if args.command == "scan":
        from .scan import TOOLS, scan_shard

        if args.tool not in TOOLS:
            raise SystemExit(f"scan needs --tool from {', '.join(TOOLS)}")
        for shard in [args.shard] if args.shard is not None else range(SHARDS):
            print(scan_shard(layout, args.tool, "dev", shard, run=args.run, code_sha=code_sha))
        return 0
    if args.command == "dev-metrics":
        from .report import dev_report
        from .scan import TOOLS

        print(dev_report(layout, _runs(args.tool_run, args.run, TOOLS), args.label, args.bootstrap))
        return 0
    if args.command == "compare":
        from .report import compare_runs

        print(compare_runs(layout, args.base_run, args.run, args.label, args.bootstrap))
        return 0
    if args.command == "examples":
        from .examples import list_examples

        _need(args.tool and args.family, "--tool and --family")
        for line in list_examples(layout, args.tool, args.run, args.family, args.count):
            print(line)
        return 0
    from .report import locked_test
    from .scan import TOOLS

    print(locked_test(layout, args.name, _runs(args.tool_run, args.run, TOOLS), code_sha, args.bootstrap))
    return 0


if __name__ == "__main__":
    sys.exit(main())
