# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""``python -m kestrixvul COMMAND --root DIR``: the C5 data pipeline (no training).

``acquire`` (transfer node, standard library only) downloads and verifies the pinned archives and
git sources into ``raw/`` and writes ``manifests/<source>.json`` plus ``manifests/SHA256SUMS``.
``qc`` (Slurm) re-verifies every pin, loads the Python/JavaScript/TypeScript part of each dump into
``work/<source>.sqlite`` and writes ``reports/qc.json``. ``labels`` applies the PrimeVul rules
(``work/candidates.jsonl``, ``reports/labels.json``). ``dedup`` removes exact and near duplicates
(``work/deduped.jsonl``, ``reports/dedup.json``). ``licenses-export`` writes the public repository
list; ``licenses-fetch`` runs on the owner's machine with an authenticated ``gh``;
``licenses-import`` validates the returned table (``reports/licenses-summary.json``). ``split``
assigns the temporal, project-disjoint split (``work/split.jsonl``, ``reports/split-manifest.json``).
``mine-targets``, ``mine-fetch`` (transfer node) and ``mine-extract`` mine the uncovered GHSA fix
commits (``ghsa_mine.py``); ``dedup-extend``, ``licenses-export-new`` and ``licenses-merge`` add them
to the pool; ``split-extend`` writes split manifest v2 without changing the frozen test split;
``negatives`` samples unchanged functions; ``audit-sample``, ``audit-combine`` (outside the cluster,
on the private review folder) and ``audit-import`` run the AI-assisted label audit.
Reports hold counts, ids and hashes only. Exit status is 1 on any failure.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .sources import ARCHIVES, GIT_SOURCES, NAMES

COMMANDS = (
    "acquire",
    "qc",
    "labels",
    "dedup",
    "licenses-export",
    "licenses-fetch",
    "licenses-import",
    "split",
    "mine-targets",
    "mine-fetch",
    "mine-extract",
    "dedup-extend",
    "licenses-export-new",
    "licenses-merge",
    "split-extend",
    "negatives",
    "audit-sample",
    "audit-combine",
    "audit-import",
)


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _acquire(root: Path, names: list[str] | None) -> int:
    from kestrixbench.acquire import AcquisitionError, checkout, manifest

    from .acquire import VerificationError, fetch, sha256sums

    os.umask(0o077)  # raw data stays private: directories 0700, files 0600
    raw = root / "raw"
    raw.mkdir(parents=True, exist_ok=True, mode=0o700)
    wanted = set(names or NAMES)
    failed = False
    for archive in ARCHIVES:
        if archive.name not in wanted:
            continue
        try:
            record = fetch(archive, raw)
        except (VerificationError, OSError) as exc:
            failed = True
            print(f"{archive.name}: FAILED {exc}", file=sys.stderr)
            continue
        write_json(root / "manifests" / f"{archive.name}.json", record)
        for f in record["files"]:  # type: ignore[attr-defined]
            print(f"{archive.name}: {f['filename']} verified, sha256 {f['sha256']}")
    for source in GIT_SOURCES:
        if source.name not in wanted:
            continue
        try:
            checkout(source, raw / source.name)
            git_record = manifest(source, raw / source.name)
        except (AcquisitionError, OSError) as exc:
            failed = True
            print(f"{source.name}: FAILED {exc}", file=sys.stderr)
            continue
        write_json(root / "manifests" / f"{source.name}.json", git_record)
        print(f"{source.name}: {git_record['file_count']} files, content {str(git_record['content_sha256'])[:12]}")
    records = [json.loads(p.read_text()) for p in sorted((root / "manifests").glob("*.json"))]
    (root / "manifests" / "SHA256SUMS").write_text(sha256sums(records))
    return 1 if failed else 0


def _run(command: str, root: Path, args: argparse.Namespace) -> int:
    if command == "qc":
        from .qc import run as qc

        report = qc(root, rebuild=args.rebuild)
        write_json(root / "reports" / "qc.json", report)
    elif command == "labels":
        from .labels import run as labels

        write_json(root / "reports" / "labels.json", labels(root))
    elif command == "dedup":
        from .dedup import run as dedup

        write_json(root / "reports" / "dedup.json", dedup(root))
    elif command == "licenses-export":
        from .licenses import export

        print(f"licenses-export: {export(root)} repositories -> {root / 'licenses' / 'repos.txt'}")
    elif command == "licenses-import":
        from .licenses import import_table

        if args.table is None:
            raise ValueError("licenses-import needs --table")
        write_json(root / "reports" / "licenses-summary.json", import_table(root, args.table))
    elif command == "split":
        from .split import run as split

        write_json(root / "reports" / "split-manifest.json", split(root))
    elif command.startswith("mine-"):
        return _mine(command, root, args)
    else:
        _extend(command, root, args)
    print(f"{command}: done")
    return 0


def _mine(command: str, root: Path, args: argparse.Namespace) -> int:
    from . import ghsa_mine

    if command == "mine-targets":
        write_json(root / "reports" / "mine-targets.json", ghsa_mine.targets(root))
    elif command == "mine-fetch":
        os.umask(0o077)
        config = ghsa_mine.FetchConfig(timeout=args.timeout, max_bytes=args.max_mb * 1024 * 1024)
        report = ghsa_mine.fetch(root, workers=args.workers, interval=args.interval, config=config, limit=args.limit)
        write_json(root / "reports" / "mine-fetch.json", report)
    else:
        write_json(root / "reports" / "mine-extract.json", ghsa_mine.extract(root))
    print(f"{command}: done")
    return 0


def _extend(command: str, root: Path, args: argparse.Namespace) -> None:
    if command == "dedup-extend":
        from .dedup import run_extend

        write_json(root / "reports" / "dedup-extend.json", run_extend(root))
    elif command == "licenses-export-new":
        from .licenses import export_new

        print(f"licenses-export-new: {export_new(root)} repositories -> {root / 'licenses' / 'repos-new.txt'}")
    elif command == "licenses-merge":
        from .licenses import merge_table

        if args.table is None:
            raise ValueError("licenses-merge needs --table")
        write_json(root / "reports" / "licenses-summary-v2.json", merge_table(root, args.table))
    elif command == "split-extend":
        from .extend import run as extend

        write_json(root / "reports" / "split-manifest-v2.json", extend(root))
    elif command == "negatives":
        from .negatives import run as negatives

        write_json(root / "reports" / "negatives.json", negatives(root))
    elif command == "audit-sample":
        from .audit import sample

        write_json(root / "reports" / "audit-sample.json", sample(root))
    elif command == "audit-combine":
        from .audit import write_combined

        print(f"audit-combine: {write_combined(root)}")
    elif command == "audit-import":
        from .audit import import_verdicts

        if args.table is None:
            raise ValueError("audit-import needs --table")
        write_json(root / "reports" / "audit.json", import_verdicts(root, args.table))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kestrixvul")
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("--root", type=Path, help="data root outside the repository (not licenses-fetch)")
    parser.add_argument("--source", action="append", choices=list(NAMES), help="acquire: only these sources")
    parser.add_argument("--rebuild", action="store_true", help="qc: reload the dumps even if work/ is current")
    parser.add_argument(
        "--table", type=Path, help="licenses-import/-merge: CSV from licenses-fetch; audit-import: verdicts.csv"
    )
    parser.add_argument("--repos", type=Path, help="licenses-fetch: repos.txt from licenses-export")
    parser.add_argument("--out", type=Path, help="licenses-fetch: output CSV (a cache next to it is reused)")
    parser.add_argument("--workers", type=int, default=8, help="mine-fetch: repositories in parallel")
    parser.add_argument("--interval", type=float, default=1.0, help="mine-fetch: seconds between git requests")
    parser.add_argument("--timeout", type=float, default=300.0, help="mine-fetch: seconds per git call")
    parser.add_argument("--max-mb", type=int, default=500, help="mine-fetch: object store cap per repository")
    parser.add_argument("--limit", type=int, help="mine-fetch: only the first N repositories (smoke run)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "licenses-fetch":
        from .licenses import fetch_table

        if args.repos is None or args.out is None:
            parser.error("licenses-fetch needs --repos and --out")
        print(f"licenses-fetch: {fetch_table(args.repos, args.out)}")
        return 0
    if args.root is None:
        parser.error("--root is required")
    root: Path = args.root.resolve()
    repo = Path(__file__).resolve().parents[2]
    if (repo / ".git").exists() and root.is_relative_to(repo):
        parser.error("--root must be outside the repository working tree")
    if args.command == "acquire":
        return _acquire(root, args.source)
    try:
        return _run(args.command, root, args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"{args.command}: FAILED {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
