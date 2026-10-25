# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``python -m kestrixcodebench COMMAND --root DIR``: kestrix-scan accuracy on CVE-fix file pairs (offline).

``php-dump`` streams the PHP files of the CVEfixes archive into a working database; ``build`` reads the data ``kestrixvul`` acquired (CVEfixes working database, mined advisory commits), filters, splits
into dev and a locked test and writes the files. ``scan`` runs one tool on dev shards (a Slurm array task);
``dev-metrics`` writes the dev report; ``compare`` writes the paired change between two kestrix runs; ``rule-rates`` writes per-rule firing counts of one run; ``bandit-gap`` counts the pairs Bandit detects and kestrix does not, by Bandit test id; ``web-corpus``, ``php-corpus`` and ``p4-corpus`` scan directory trees of web files, of PHP and SQL files or of Go, Java, Kotlin, C#, Ruby and ERB files; ``examples`` lists ids of missed pairs for hand analysis on the cluster;
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

COMMANDS = (
    "php-dump",
    "build",
    "scan",
    "dev-metrics",
    "compare",
    "rule-rates",
    "bandit-gap",
    "web-corpus",
    "php-corpus",
    "p4-corpus",
    "examples",
    "table",
    "locked-test",
    "test2-select",
    "test2-fetch",
    "test2-build",
    "locked-test2",
)


def _tools(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(part for part in value.split(",") if part) if value else default


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
    p.add_argument("--cvefixes-zip", type=Path, help="php-dump: the CVEfixes_v1.0.8.zip archive")
    p.add_argument("--out", type=Path, help="php-dump: the working database to write")
    p.add_argument("--label-set", choices=("php", "p4"), default="php", help="php-dump: PHP, or the Phase 4 languages")
    p.add_argument("--cvefixes-db", type=Path, help="build: kestrixvul's work/cvefixes.sqlite")
    p.add_argument("--vul-root", type=Path, help="build: kestrixvul's root (work/ghsa.jsonl, mine/)")
    p.add_argument("--limit", type=int, help="build: at most this many changed files per source (smoke runs)")
    p.add_argument(
        "--only-language",
        choices=("python", "javascript", "typescript", "web", "php", "p4"),
        help="build: keep one language (p4: Go, Java, Kotlin, C#, Ruby and ERB)",
    )
    p.add_argument("--corpus-dir", type=Path, action="append", help="web-corpus: a directory tree to scan (repeat)")
    p.add_argument("--tools", help="dev-metrics, locked-test: comma-separated tools (default kestrix,bandit,eslint)")
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
    p.add_argument("--name", default="codebench-v1", help="locked-test, locked-test2: name of this evaluation")
    p.add_argument(
        "--split", default="dev", help="scan, dev-metrics, compare: dev, or tuning (round-1 dev + spent test)"
    )
    p.add_argument(
        "--kestrix-tree", action="append", help="scan, locked-test2: LABEL=CODE_TREE of another kestrix scanner"
    )
    p.add_argument("--old-root", type=Path, help="test2-select, test2-build: the round-1 benchmark root")
    p.add_argument(
        "--allow-known-repos", action="store_true", help="test2-select: also take repositories of the old data"
    )
    p.add_argument(
        "--allow-morefixes", action="store_true", help="test2-select: also take commits only MoreFixes holds"
    )
    p.add_argument("--published-after", help="test2-select: only advisories published after YYYY-MM-DD (a test3)")
    p.add_argument("--workers", type=int, default=8, help="test2-fetch: repositories in parallel")
    p.add_argument("--interval", type=float, default=1.0, help="test2-fetch: seconds between git requests")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    os.umask(0o077)
    try:
        return _run(args)
    except CodeBenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _trees(items: list[str] | None) -> dict[str, Path]:
    out = {}
    for item in items or []:
        label, _, path = item.partition("=")
        if not label or not path:
            raise CodeBenchError("--kestrix-tree expects LABEL=CODE_TREE")
        out[label] = Path(path)
    return out


def _test2(args: argparse.Namespace, layout: Layout, code_sha: str) -> int:
    from . import heldout

    if args.command == "locked-test2":
        print(heldout.locked_test2(layout, args.name, _trees(args.kestrix_tree), code_sha, reps=args.bootstrap))
        return 0
    if args.command == "test2-fetch":
        print(
            json.dumps(
                heldout.fetch_targets(layout.root, workers=args.workers, interval=args.interval, limit=args.limit)[
                    "counts"
                ]
            )
        )
        return 0
    _need(args.old_root and args.vul_root, "--old-root and --vul-root")
    if args.command == "test2-select":
        report = heldout.select_targets(
            layout.root,
            args.old_root,
            args.vul_root,
            allow_morefixes=args.allow_morefixes,
            allow_known_repos=args.allow_known_repos,
            published_after=args.published_after,
        )
        print(json.dumps({k: report[k] for k in ("counts", "tiers", "selected")}))
        return 0
    body = heldout.build_heldout(layout, args.old_root, args.vul_root)
    print(
        json.dumps(
            {k: body["splits"]["test"][k] for k in ("pairs", "pairs_in_scope", "projects", "cves", "unchanged_files")}
            | {"overlap": body["overlap_with_existing"]}
        )
    )
    return 0


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
    if args.command == "php-dump":
        from .phpsource import load_php

        _need(args.cvefixes_zip and args.out, "--cvefixes-zip and --out")
        print(json.dumps(load_php(args.cvefixes_zip, args.out, args.label_set), sort_keys=True))
        return 0
    _need(args.root, "--root")
    layout = Layout(args.root)
    if args.command == "build":
        from .build import build

        _need(args.cvefixes_db and args.vul_root, "--cvefixes-db and --vul-root")
        body = build(layout, args.cvefixes_db, args.vul_root, args.limit, args.only_language)
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
        from .scan import SCAN_TOOLS, base_tool, scan_shard

        if base_tool(args.tool) not in SCAN_TOOLS:
            raise SystemExit(f"scan needs --tool from {', '.join(SCAN_TOOLS)}")
        trees = _trees(args.kestrix_tree)
        tree = trees.get(args.tool.partition("@")[2]) if "@" in args.tool else None
        for shard in [args.shard] if args.shard is not None else range(SHARDS):
            print(scan_shard(layout, args.tool, args.split, shard, run=args.run, code_sha=code_sha, tree=tree))
        return 0
    if args.command == "dev-metrics":
        from .report import dev_report
        from .scan import TOOLS

        tools = ("kestrix",) if args.split == "tuning" else _tools(args.tools, TOOLS)  # baselines: dev only
        runs = _runs(args.tool_run, args.run, tools)
        print(dev_report(layout, runs, args.label, reps=args.bootstrap, split=args.split))
        return 0
    if args.command == "compare":
        from .report import compare_runs

        print(compare_runs(layout, args.base_run, args.run, args.label, reps=args.bootstrap, split=args.split))
        return 0
    if args.command in ("web-corpus", "php-corpus", "p4-corpus"):
        from .corpus import p4_corpus, php_corpus, web_corpus

        _need(args.corpus_dir, "--corpus-dir")
        scanner = {"php-corpus": php_corpus, "p4-corpus": p4_corpus}.get(args.command, web_corpus)
        print(scanner(layout, args.corpus_dir, args.label))
        return 0
    if args.command == "rule-rates":
        from .rates import rule_rates

        print(rule_rates(layout, args.run, args.split, args.label))
        return 0
    if args.command.startswith(("test2-", "locked-test2")):
        return _test2(args, layout, code_sha)
    if args.command == "examples":
        from .examples import list_examples

        _need(args.tool and args.family, "--tool and --family")
        for line in list_examples(layout, args.tool, args.run, args.family, args.count):
            print(line)
        return 0
    from .report import locked_test
    from .scan import TOOLS

    print(
        locked_test(
            layout, args.name, _runs(args.tool_run, args.run, _tools(args.tools, TOOLS)), code_sha, reps=args.bootstrap
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
