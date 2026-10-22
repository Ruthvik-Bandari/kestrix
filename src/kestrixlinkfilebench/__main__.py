# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``python -m kestrixlinkfilebench COMMAND --root DIR [--kind link|file]``: the link and file accuracy benchmark.

``acquire`` (transfer node, standard library only) downloads the datasets into ``ROOT/raw`` and writes
``manifests/``. For each kind (``link``, ``file``), working data lives in ``ROOT/<kind>``: ``build`` reads the
raw downloads, deduplicates, labels and groups, then makes the group-disjoint dev/test split. ``features
--shard N`` runs the ``kestrix.forensics`` analyzer over one shard (a Slurm array task). ``dev-metrics``
writes dev numbers, error analysis and leakage controls. ``locked-test`` evaluates once on the test split.
Reports hold counts, rates, intervals and finding ids only. Exit status is 1 on failure.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from .common import KINDS, Layout, LinkFileBenchError, kind_layout

COMMANDS = ("acquire", "build", "split", "features", "dev-metrics", "probe", "locked-test")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kestrixlinkfilebench", description=__doc__)
    p.add_argument("command", choices=COMMANDS)
    p.add_argument(
        "--root", type=Path, required=True, help="benchmark root, for example /scratch/$USER/kestrix/linkfilebench"
    )
    p.add_argument("--raw-root", type=Path, help="build, features: root that holds raw/ (default: --root)")
    p.add_argument("--kind", choices=KINDS, help="build, split, features, dev-metrics, locked-test: link or file")
    p.add_argument("--only", action="append", help="acquire: source name (repeatable)")
    p.add_argument("--limit", type=int, help="build: at most this many items per input (smoke runs)")
    p.add_argument("--majestic", type=int, default=30_000, help="build link: Majestic hosts to sample")
    p.add_argument("--shard", type=int, help="features: shard number")
    p.add_argument(
        "--splits",
        default="dev,test",
        help="features: comma-separated splits to analyze; rule rounds use 'dev' so the locked test is never run",
    )
    p.add_argument("--shards", type=int, help="number of shards (default 16 for link, 20 for file)")
    p.add_argument("--bootstrap", type=int, default=1000)
    p.add_argument("--name", default="linkfile-v1", help="locked-test: name of this evaluation")
    p.add_argument(
        "--baseline-root",
        type=Path,
        help="locked-test: root of the baseline-rules run (same split, its own test features) to evaluate beside the final rules",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    os.umask(0o077)  # raw data stays private: directories 0700, files 0600
    try:
        return _run(args)
    except LinkFileBenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _layout(args: argparse.Namespace) -> tuple[str, Layout]:
    if args.kind is None:
        raise SystemExit(f"{args.command} needs --kind link|file")
    return args.kind, kind_layout(args.root, args.kind, args.shards)


def _meta(kind: str, layout: Layout) -> list[dict[str, Any]]:
    if kind == "link":
        from .links import read_meta
    else:
        from .files import read_meta
    return read_meta(layout)


def _run(args: argparse.Namespace) -> int:
    cmd = args.command
    if cmd == "acquire":
        from .acquire import acquire

        manifest = acquire(Layout(args.root), args.only)
        for source in manifest["sources"]:
            for f in source["files"]:
                print(f"{source['source']}/{f['filename']}: {f['size']} bytes, sha256 {f['sha256']}")
        return 0
    kind, layout = _layout(args)
    raw = Layout(args.raw_root or args.root).raw
    if cmd in ("build", "split"):
        return _build_or_split(args, kind, layout, raw)
    if cmd == "features":
        return _features(args, kind, layout, raw)
    if cmd == "probe":
        from .files import thread_names
        from .probe import run_probe

        meta = {m["id"]: m for m in _meta(kind, layout)}
        print(f"wrote {run_probe(layout, raw, kind, meta, thread_names() if kind == 'file' else [])}")
        return 0
    from .report import dev_metrics, locked_test

    if cmd == "dev-metrics":
        dev_metrics(layout, kind, args.bootstrap)
        print(f"wrote {layout.reports / f'{kind}-dev-metrics.json'}")
        return 0
    baseline = kind_layout(args.baseline_root, kind, args.shards) if args.baseline_root else None
    print(f"wrote {locked_test(layout, kind, args.name, args.bootstrap, baseline=baseline)}")
    return 0


def _build_or_split(args: argparse.Namespace, kind: str, layout: Layout, raw: Path) -> int:
    from .split import run_split

    if args.command == "build":
        if kind == "link":
            from .links import build_links

            report = build_links(raw, layout, majestic=args.majestic, limit=args.limit)
        else:
            from .files import build_files

            report = build_files(raw, layout, limit=args.limit)
        print(f"kept {report['kept_total']} items in {report['groups']} groups")
    manifest = run_split(layout, _meta(kind, layout), kind)
    print({side: v["items"] for side, v in manifest["splits"].items()})
    return 0


def _features(args: argparse.Namespace, kind: str, layout: Layout, raw: Path) -> int:
    from .split import read_split

    if args.shard is None:
        raise SystemExit("features needs --shard N")
    splits = tuple(args.splits.split(","))
    meta = {m["id"]: m for m in _meta(kind, layout)}
    if kind == "link":
        from .links import run_link_shard

        result = run_link_shard(layout, args.shard, meta, read_split(layout), splits)
    else:
        from .files import run_file_shard

        result = run_file_shard(layout, raw, args.shard, meta, read_split(layout), splits=splits)
    print(result)
    bad = sum(result["errors"].values())
    return 1 if bad > 0.01 * max(1, sum(result["analyzed"].values()) + bad) else 0


if __name__ == "__main__":
    sys.exit(main())
