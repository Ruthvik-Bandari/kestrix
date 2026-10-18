"""``python -m kestrixbench {acquire,qc,replay,review-sheet,review-status,split,variants,evaluate,sft,train-m1,compare} --root DIR [--source NAME ...] [--es-url URL]``.

``acquire`` writes ``<root>/<source>/`` checkouts and ``<root>/manifests/<source>.json``.
``qc`` re-verifies each manifest against disk, then writes ``<root>/reports/qc-<source>.json``.
``replay`` runs every supported Sigma rule on the pinned engine and writes ``reports/replay-positives.json``.
``review-sheet`` writes the private OTRF candidate review files; ``review-status`` validates labels (counts only).
``split`` previews the root-grouped split (``reports/split-preview.json``); ``--freeze`` writes
``benchmark/split-manifest.json`` once. ``variants`` writes impairment cases (private) and
``reports/variants.json``. ``evaluate`` scores a repair system on the cases (train and development;
``--locked`` adds the test split) into ``reports/eval-<system>.json``. ``sft`` writes M1 training
examples (train and development); ``train-m1`` fits the LoRA adapter on a GPU. ``compare`` pairs
evaluated systems on identical cases (``reports/comparison.{json,md}``).
Exit status is 1 if any source fails, so a Slurm job fails visibly. ``acquire`` uses only the
standard library, so it runs on the cluster transfer node without the project environment.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .acquire import AcquisitionError, checkout, manifest
from .sources import SOURCES, by_name


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _replay(root: Path, es_url: str) -> int:
    from kestrix.core.errors import Rejected
    from kestrix.detect.engine import Elasticsearch

    from .positives import run

    es = Elasticsearch(es_url, timeout=120.0)
    try:
        report = run(root, es)
    except Rejected as exc:
        print(f"replay: FAILED {exc.reason}: {exc.detail}", file=sys.stderr)
        return 1
    finally:
        es.close()
    _write_json(root / "reports" / "replay-positives.json", report)
    print(f"replay: {report['rules_replayed']} rules; fidelity {report['fidelity']}; summary {report['summary']}")
    return 1 if report["engine_errors"] else 0


SPLIT_SEED = "aegis-bench-v1"


def _reviewed(root: Path, report: dict[str, object]) -> dict[str, str]:
    """Validated labels, or {} before review; invalid rows stop the run."""
    from .review import ReviewError, ai_labeled_events, candidates, read_labels

    path = root / "review" / "labels.csv"
    if not path.exists():
        return {}
    labels, problems = read_labels(path, set(candidates(root, report)))
    if problems:
        raise ReviewError(f"{len(problems)} invalid label rows; run review-status")
    if os.environ.get("KESTRIX_IGNORE_AI_LABELS") == "1":
        # Sensitivity check: keep only human labels, so the benchmark rests on SigmaHQ's
        # maintainer-verified recordings plus any human-reviewed events.
        return {e: label for e, label in labels.items() if e not in ai_labeled_events(path)}
    return labels


def _natural_mine(root: Path, history: Path | None) -> int:
    from .natural import mine, summarize_mining, to_record
    from .positives import supported_rules
    from .sources import by_name

    git_dir = history or root / "sigma-history.git"
    pinned = by_name("sigma").commit
    try:
        rules, _ = supported_rules(root / "sigma")
        changes, skipped = mine(git_dir, pinned, set(rules))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"natural-mine: FAILED {exc}", file=sys.stderr)
        return 1
    out = root / "benchmark" / "natural" / "changes.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(to_record(c), sort_keys=True) + "\n" for c in changes), encoding="utf-8")
    summary = summarize_mining(changes, skipped, pinned)
    _write_json(root / "reports" / "natural-mining.json", summary)
    print(f"natural-mine: {json.dumps(summary)}")
    return 0


def _natural_changes(root: Path) -> list[dict[str, Any]]:
    lines = (root / "benchmark" / "natural" / "changes.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line]


def _natural_verify(root: Path, es_url: str) -> int:
    from kestrix.core.errors import Rejected
    from kestrix.detect.engine import Elasticsearch

    from .natural import verify_all
    from .review import ReviewError

    es = Elasticsearch(es_url, timeout=120.0)
    try:
        es.require_pinned()
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        malicious = {e for e, label in _reviewed(root, report).items() if label == "malicious"}
        result = verify_all(root, _natural_changes(root), malicious, es)
    except (Rejected, ReviewError, OSError, ValueError) as exc:
        print(f"natural-verify: FAILED {exc}", file=sys.stderr)
        return 1
    finally:
        es.close()
    _write_json(root / "reports" / "natural-verified.json", result)
    print(f"natural-verify: {json.dumps({k: v for k, v in result.items() if k != 'verified'})}")
    return 0


def _natural_build(root: Path, manifest_path: Path | None, seed: str) -> int:
    import shutil

    from .natural import build
    from .review import ReviewError

    frozen = root / "benchmark" / "split-manifest.json"
    path = manifest_path or frozen
    try:
        manifest = json.loads(path.read_text())
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        verified = json.loads((root / "reports" / "natural-verified.json").read_text())
        labels = _reviewed(root, report)
        benign = {e for e, label in labels.items() if label == "benign"}
        malicious = {e for e, label in labels.items() if label == "malicious"}
        for stale in (root / "benchmark" / "cases").glob("*/*-natural-*"):
            shutil.rmtree(stale)  # regenerate natural cases; synthetic variants are left alone
        result = build(
            root, _natural_changes(root), verified, manifest, report, benign=benign, seed=seed, malicious=malicious
        )
    except (ReviewError, OSError, ValueError) as exc:
        print(f"natural-build: FAILED {exc}", file=sys.stderr)
        return 1
    result["manifest"] = path.name
    result["from_frozen_split"] = path.resolve() == frozen.resolve()
    _write_json(root / "reports" / "natural-cases.json", result)
    print(f"natural-build: {json.dumps(result)}")
    return 0


def _compare(root: Path, systems: list[str], baseline: str, *, locked: bool) -> int:
    from .compare import CompareError, compare, markdown

    suffix = "-locked" if locked else ""
    try:
        reports = {s: json.loads((root / "reports" / f"eval-{s}{suffix}.json").read_text()) for s in systems}
        result = compare(reports, baseline)
    except (CompareError, OSError, ValueError) as exc:
        print(f"compare: FAILED {exc}", file=sys.stderr)
        return 1
    _write_json(root / "reports" / f"comparison{suffix}.json", result)
    (root / "reports" / f"comparison{suffix}.md").write_text(markdown(result))
    print(markdown(result))
    return 0


def _sft(root: Path, es_url: str) -> int:
    from kestrix.core.errors import Rejected
    from kestrix.detect.engine import Elasticsearch

    from .sft import build

    es = Elasticsearch(es_url, timeout=120.0)
    counts: dict[str, int] = {}
    try:
        es.require_pinned()
        for split in ("train", "development"):
            rows, skipped = build(root / "benchmark" / "cases", split, es)
            counts[f"{split}_skipped_outside_contract"] = skipped
            out = root / "sft" / f"{split}.jsonl"
            out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
            counts[split] = len(rows)
    except (Rejected, OSError, ValueError) as exc:
        print(f"sft: FAILED {exc}", file=sys.stderr)
        return 1
    finally:
        es.close()
    print(f"sft: {counts}")
    return 0


def _train_m1(root: Path, max_steps: int, seed: int) -> int:
    from .m1 import TrainConfig, train

    snapshot = os.environ.get("KESTRIX_B2_SNAPSHOT")
    if not snapshot:
        print("train-m1: set KESTRIX_B2_SNAPSHOT", file=sys.stderr)
        return 2
    name = f"m1-seed{seed}" + (f"-smoke{max_steps}" if max_steps else "")
    cfg = TrainConfig(seed=seed, max_steps=max_steps)
    manifest = train(
        Path(snapshot), root / "sft/train.jsonl", root / "sft/development.jsonl", root / "models" / name, cfg
    )
    _write_json(root / "reports" / f"{name}-training.json", manifest)
    print(
        f"train-m1: {json.dumps({k: manifest[k] for k in ('optimizer_steps', 'history', 'peak_gpu_memory_gb', 'tokens_per_second', 'truncated_examples', 'gpu')})}"
    )
    return 0


def _evaluate(root: Path, system_name: str, es_url: str, *, locked: bool, label: str | None = None) -> int:
    from kestrix.core.errors import Rejected
    from kestrix.detect.engine import Elasticsearch

    from .evaluate import SYSTEM_STATS, SYSTEMS, run_cases, summarize

    if system_name not in SYSTEMS:
        print(f"evaluate: unknown system {system_name!r}; choose from {sorted(SYSTEMS)}", file=sys.stderr)
        return 2
    es = Elasticsearch(es_url, timeout=120.0)
    try:
        es.require_pinned()
        cases = root / "benchmark" / "cases"
        rows = run_cases(cases, SYSTEMS[system_name](cases), es, locked=locked)
    except (Rejected, OSError, ValueError) as exc:
        print(f"evaluate: FAILED {exc}", file=sys.stderr)
        return 1
    finally:
        es.close()
    suffix = "-locked" if locked else ""
    summary = summarize(rows)
    result = {
        "schema_version": 1,
        "system": system_name,
        "locked_test_included": locked,
        "system_stats": dict(SYSTEM_STATS),
        "summary": summary,
    }
    name = label or system_name
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", name):
        print(f"evaluate: invalid --report-name {name!r}", file=sys.stderr)
        return 2
    result["label"] = name
    _write_json(root / "reports" / f"eval-{name}{suffix}.json", {**result, "cases": rows})
    print(f"evaluate: {json.dumps(summary['overall'])}")
    errors = sum(r["error"] is not None for r in rows)
    if errors:
        print(f"evaluate: {errors} case(s) hit engine errors; the report is not a valid comparison", file=sys.stderr)
        return 1
    return 0


def _variants(root: Path, manifest_path: Path | None, es_url: str, seed: str) -> int:
    import shutil

    from kestrix.core.errors import Rejected
    from kestrix.detect.engine import Elasticsearch

    from .review import ReviewError
    from .variants import build

    frozen = root / "benchmark" / "split-manifest.json"
    path = manifest_path or frozen
    es = Elasticsearch(es_url, timeout=120.0)
    try:
        es.require_pinned()
        manifest = json.loads(path.read_text())
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        labels = _reviewed(root, report)
        benign = {e for e, label in labels.items() if label == "benign"}
        malicious = {e for e, label in labels.items() if label == "malicious"}
        for stale in (root / "benchmark" / "cases").glob("*/*"):
            if "-natural-" not in stale.name:
                shutil.rmtree(stale)  # regenerate synthetic variants; natural cases are left alone
        result = build(root, manifest, report, benign=benign, es=es, seed=seed, malicious=malicious)
    except (Rejected, ReviewError, OSError, ValueError) as exc:
        print(f"variants: FAILED {exc}", file=sys.stderr)
        return 1
    finally:
        es.close()
    result["manifest"] = path.name
    result["from_frozen_split"] = path.resolve() == frozen.resolve()
    _write_json(root / "reports" / "variants.json", result)
    print(f"variants: {result}")
    return 0


def _split(root: Path, seed: str, frozen: bool) -> int:
    from .natural import extra_roots
    from .review import ReviewError
    from .split import SplitError, build, freeze

    try:
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        malicious = {e for e, label in _reviewed(root, report).items() if label == "malicious"}
        natural = root / "reports" / "natural-verified.json"
        extra = extra_roots(json.loads(natural.read_text())) if natural.exists() else {}
        manifest = build(root / "sigma", report, malicious, seed, extra=extra)
        if frozen:
            digest = freeze(manifest, root / "sigma", root / "benchmark" / "split-manifest.json")
            print(f"split: frozen, sha256 {digest}")
        else:
            _write_json(root / "reports" / "split-preview.json", manifest)
    except (ReviewError, SplitError, OSError, ValueError) as exc:
        print(f"split: FAILED {exc}", file=sys.stderr)
        return 1
    print(
        f"split: {manifest['eligible_roots']} eligible roots, largest group {manifest['largest_group']}, {manifest['summary']}"
    )
    return 0


def _page(root: Path) -> int:
    """Writes review/human-check.html for the event ids in review/human-check.txt (private, 0600)."""
    from .review import ReviewError, _private_write, render_check_page

    try:
        ids = [
            line.strip()
            for line in (root / "review" / "human-check.txt").read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        _private_write(root / "review" / "human-check.html", render_check_page(root, ids))
    except (ReviewError, OSError) as exc:
        print(f"review-page: FAILED {exc}", file=sys.stderr)
        return 1
    print(f"review-page: {len(ids)} events -> {root / 'review' / 'human-check.html'}")
    return 0


def _import(root: Path, labels: Path | None) -> int:
    from .review import ReviewError, import_labels

    try:
        if labels is None:
            raise ReviewError("review-import needs --labels")
        rows = json.loads(labels.read_text(encoding="utf-8"))
        counts = import_labels(root, rows)
    except (ReviewError, OSError, ValueError) as exc:
        print(f"review-import: FAILED {exc}", file=sys.stderr)
        return 1
    print(f"review-import: {counts}")
    return 0


def _label(root: Path, args: argparse.Namespace) -> int:
    """Interactive labelling. Prints raw event values: for the reviewer's own terminal only."""
    from .review import ReviewError, format_candidate, next_candidate, set_label

    try:
        if args.command == "review-label":
            if not (args.event and args.label):
                raise ReviewError("review-label needs --event and --label")
            set_label(root, args.event, args.label, args.rationale, args.reviewer)
        item, remaining = next_candidate(root)
    except (ReviewError, OSError, ValueError) as exc:
        print(f"{args.command}: FAILED {exc}", file=sys.stderr)
        return 1
    print(format_candidate(item, remaining) if item else "Every candidate is labelled.")
    return 0


def _review(root: Path, command: str) -> int:
    from .review import ReviewError, status, write_sheet

    try:
        report = json.loads((root / "reports" / "replay-positives.json").read_text())
        if command == "review-sheet":
            print(f"review-sheet: {write_sheet(root, report)} (raw values in {root / 'review'}, private to you)")
            return 0
        result = status(root, report)
    except (ReviewError, OSError, ValueError) as exc:
        print(f"{command}: FAILED {exc}", file=sys.stderr)
        return 1
    _write_json(root / "reports" / "review-status.json", result)
    print(f"review-status: {result}")
    return 1 if result["problems"] else 0


COMMANDS = (
    "acquire",
    "qc",
    "replay",
    "review-sheet",
    "review-status",
    "review-next",
    "review-label",
    "review-import",
    "review-page",
    "split",
    "variants",
    "evaluate",
    "sft",
    "train-m1",
    "compare",
    "natural-mine",
    "natural-verify",
    "natural-build",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kestrixbench")
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("--root", type=Path, required=True, help="data root outside the repository")
    parser.add_argument("--source", action="append", choices=[s.name for s in SOURCES])
    parser.add_argument("--es-url", default="http://127.0.0.1:9200", help="pinned Elasticsearch for replay")
    parser.add_argument("--freeze", action="store_true", help="split: write the frozen manifest (never overwritten)")
    parser.add_argument("--seed", default=SPLIT_SEED, help="split: assignment seed")
    parser.add_argument("--manifest", type=Path, help="variants: split manifest (default: the frozen one)")
    parser.add_argument("--system", default="b0", help="evaluate: repair system")
    parser.add_argument("--report-name", help="evaluate: report name (default: the system), e.g. m1-seed2")
    parser.add_argument("--locked", action="store_true", help="evaluate/compare: include the locked test split")
    parser.add_argument("--max-steps", type=int, default=0, help="train-m1: stop after N steps (smoke run)")
    parser.add_argument("--train-seed", type=int, default=1, help="train-m1: training seed")
    parser.add_argument("--systems", nargs="+", default=["b0", "b1", "b2"], help="compare: evaluated systems")
    parser.add_argument("--baseline", default="b0", help="compare: baseline system")
    parser.add_argument("--labels", type=Path, help="review-import: JSON list of {event_id,label,rationale,reviewer}")
    parser.add_argument("--history", type=Path, help="natural-mine: bare clone of SigmaHQ with full history")
    parser.add_argument("--event", help="review-label: event id")
    parser.add_argument("--label", choices=["malicious", "benign", "unknown"], help="review-label: decision")
    parser.add_argument("--rationale", default="", help="review-label: what decided it (one line)")
    parser.add_argument("--reviewer", default=os.environ.get("KESTRIX_REVIEWER", ""), help="review-label: initials")
    return parser


def _sources(root: Path, command: str, names: list[str] | None) -> int:
    failed = False
    for source in [by_name(n) for n in names] if names else list(SOURCES):
        dest = root / source.name
        try:
            if command == "acquire":
                checkout(source, dest)
                record = manifest(source, dest)
                _write_json(root / "manifests" / f"{source.name}.json", record)
                print(f"{source.name}: {record['file_count']} files, content {str(record['content_sha256'])[:12]}")
                continue
            from .qc import QC  # needs the project environment; acquire needs only the stdlib

            recorded = json.loads((root / "manifests" / f"{source.name}.json").read_text())
            current = manifest(source, dest)
            if current["files"] != recorded["files"]:
                raise AcquisitionError(f"{source.name}: files changed since acquisition")
            report = {
                "schema_version": 1,
                "source": source.name,
                "commit": source.commit,
                "content_sha256": current["content_sha256"],
                "checks": QC[source.name](dest),
            }
            _write_json(root / "reports" / f"qc-{source.name}.json", report)
            print(f"{source.name}: QC report written")
        except (AcquisitionError, OSError, ValueError) as exc:
            failed = True
            print(f"{source.name}: FAILED {exc}", file=sys.stderr)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()
    repo = Path(__file__).resolve().parents[2]
    if (repo / ".git").exists() and root.is_relative_to(repo):
        parser.error("--root must be outside the repository working tree")
    dispatch = {
        "replay": lambda: _replay(root, args.es_url),
        "review-sheet": lambda: _review(root, args.command),
        "review-status": lambda: _review(root, args.command),
        "review-next": lambda: _label(root, args),
        "review-label": lambda: _label(root, args),
        "review-import": lambda: _import(root, args.labels),
        "review-page": lambda: _page(root),
        "split": lambda: _split(root, args.seed, args.freeze),
        "variants": lambda: _variants(root, args.manifest, args.es_url, args.seed),
        "evaluate": lambda: _evaluate(root, args.system, args.es_url, locked=args.locked, label=args.report_name),
        "sft": lambda: _sft(root, args.es_url),
        "train-m1": lambda: _train_m1(root, args.max_steps, args.train_seed),
        "compare": lambda: _compare(root, args.systems, args.baseline, locked=args.locked),
        "natural-mine": lambda: _natural_mine(root, args.history),
        "natural-verify": lambda: _natural_verify(root, args.es_url),
        "natural-build": lambda: _natural_build(root, args.manifest, args.seed),
    }
    if args.command in dispatch:
        return dispatch[args.command]()
    return _sources(root, args.command, args.source)


if __name__ == "__main__":
    raise SystemExit(main())
