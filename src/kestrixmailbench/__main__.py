# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``python -m kestrixmailbench COMMAND --root DIR``: the email accuracy benchmark (no network after ``acquire``).

``acquire`` (transfer node, standard library only) downloads the corpora into ``raw/`` and writes
``manifests/``. ``build`` unpacks, filters, deduplicates, labels and groups (``work/``,
``reports/build.json``); ``split`` makes the group-disjoint dev/test split. ``features --shard N``
runs ``kestrix.mail.analyze`` over one shard (a Slurm array task). ``dev-metrics`` writes baseline
numbers and the leakage controls; ``learn`` fits weights on dev; ``locked-test`` evaluates once on the
test split. Reports hold counts, rates, intervals and finding ids only. Exit status is 1 on failure.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .common import Layout

COMMANDS = ("acquire", "build", "split", "features", "dev-metrics", "probe", "learn", "locked-test")


def _years(text: str) -> tuple[int, int]:
    lo, _, hi = text.partition("-")
    return int(lo), int(hi)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kestrixmailbench", description=__doc__)
    p.add_argument("command", choices=COMMANDS)
    p.add_argument(
        "--root", type=Path, required=True, help="benchmark root, for example /scratch/$USER/kestrix/mailbench"
    )
    p.add_argument("--raw", type=Path, help="build: root that holds raw/ (default: --root)")
    p.add_argument("--only", action="append", help="acquire: source name (repeatable)")
    p.add_argument("--limit", type=int, help="build: at most this many messages per input file (smoke runs)")
    p.add_argument("--enron-sample", type=int, default=20_000)
    p.add_argument("--shard", type=int, help="features: shard number")
    p.add_argument(
        "--splits",
        default="dev,test",
        help="features: comma-separated splits to analyze; rule rounds use 'dev' so the locked test is never run",
    )
    p.add_argument("--baseline-root", type=Path, help="probe: root of the earlier run whose dev verdicts form cohorts")
    p.add_argument("--shards", type=int, default=16, help="number of corpus shards (build and all later stages)")
    p.add_argument("--bootstrap", type=int, default=1000)
    p.add_argument("--era-ham-years", type=_years, default=(2002, 2005))
    p.add_argument("--era-pos-years", type=_years, default=(2005, 2007))
    p.add_argument("--feature-set", default="content", help="learn: all, content, content_strict or content_noera")
    p.add_argument("--far-suspicious", type=float, default=0.05)
    p.add_argument("--far-malicious", type=float, default=0.01)
    p.add_argument("--far-basis", choices=("each_source", "pooled"), default="each_source")
    p.add_argument(
        "--balance",
        choices=("cell", "class"),
        default="cell",
        help="learn: weight every source/label cell equally, or only the two classes",
    )
    p.add_argument("--output-suffix", default="", help="learn: appended to the output file names (for example _pooled)")
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--min-support", type=int, default=5)
    p.add_argument(
        "--interaction",
        action="append",
        help="learn: 'idA+idB' product feature (repeatable; 'none' for no interactions)",
    )
    p.add_argument("--weights", type=Path, action="append", help="locked-test: weights JSON (repeatable)")
    p.add_argument("--name", default="mail-v1", help="locked-test: name of this evaluation")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    os.umask(0o077)  # raw data stays private: directories 0700, files 0600
    from .common import MailBenchError

    layout = Layout(args.root, args.shards)
    try:
        return _run(args, layout)
    except MailBenchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace, layout: Layout) -> int:
    cmd = args.command
    if cmd == "acquire":
        from .acquire import acquire

        manifest = acquire(layout, args.only)
        for source in manifest["sources"]:
            for f in source["files"]:
                print(f"{source['source']}/{f['filename']}: {f['size']} bytes, sha256 {f['sha256']}")
        return 0
    if cmd == "build":
        from .build import build
        from .split import run_split

        report = build(
            (Layout(args.raw) if args.raw else layout).raw, layout, limit=args.limit, enron_sample=args.enron_sample
        )
        print(f"kept {report['kept_total']} messages in {report['groups']} groups")
        from .build import read_meta

        manifest = run_split(layout, read_meta(layout))
        print({side: v["messages"] for side, v in manifest["splits"].items()})
        return 0
    if cmd == "split":
        from .build import read_meta
        from .split import run_split

        manifest = run_split(layout, read_meta(layout))
        print({side: v["messages"] for side, v in manifest["splits"].items()})
        return 0
    if cmd == "features":
        from .build import read_meta
        from .features import run_shard
        from .split import read_split

        if args.shard is None:
            raise SystemExit("features needs --shard N")
        meta = {m["id"]: m for m in read_meta(layout)}
        result = run_shard(layout, args.shard, meta, read_split(layout), tuple(args.splits.split(",")))
        print(result)
        return 1 if result["errors"] and sum(result["errors"].values()) > 0.01 * sum(result["analyzed"].values()) else 0
    return _analysis(args, layout)


def _analysis(args: argparse.Namespace, layout: Layout) -> int:
    from .metrics import FEATURE_SETS, FeatureSet, default_strata

    strata = default_strata(args.era_ham_years, args.era_pos_years)
    if args.command == "dev-metrics":
        from .report import dev_metrics

        dev_metrics(layout, strata, args.bootstrap)
        print(f"wrote {layout.reports / 'mail-dev-metrics.json'}")
        return 0
    if args.command == "probe":
        from .probe import REPORT, run_probe

        run_probe(layout, Layout(args.baseline_root or args.root, args.shards))
        print(f"wrote {layout.reports / REPORT}")
        return 0
    if args.command == "learn":
        from .common import write_json
        from .features import read_features
        from .learn import DEFAULT_INTERACTIONS, learn
        from .report import era_sensitive_ids

        name = args.feature_set
        if name == "content_noera":
            fset = FeatureSet(name, ("auth",), era_sensitive_ids(layout))
        elif name in FEATURE_SETS:
            fset = FEATURE_SETS[name]
        else:
            raise SystemExit(f"unknown feature set {name}")
        pairs: tuple[tuple[str, str], ...] = DEFAULT_INTERACTIONS
        if args.interaction:
            pairs = (
                ()
                if args.interaction == ["none"]
                else tuple((i.split("+", 1)[0], i.split("+", 1)[1]) for i in args.interaction)
            )
        model, report = learn(
            layout,
            read_features(layout, "dev"),
            fset,
            interactions=pairs,
            far_suspicious=args.far_suspicious,
            far_malicious=args.far_malicious,
            far_basis=args.far_basis,
            balance=args.balance,
            folds=args.folds,
            min_support=args.min_support,
            strata=strata,
            reps=args.bootstrap,
        )
        write_json(layout.reports / f"mail-weights-{name}{args.output_suffix}.json", model)
        write_json(layout.reports / f"mail-learn-{name}{args.output_suffix}.json", report)
        print(f"wrote weights and report for {name}: thresholds {model['thresholds']}")
        return 0
    from .report import locked_test

    if not args.weights:
        raise SystemExit("locked-test needs --weights FILE (repeatable)")
    out = locked_test(layout, args.weights, args.name, strata, args.bootstrap)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
