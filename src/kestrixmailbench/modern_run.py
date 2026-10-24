# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Build, features and held-out stages of the modern-ham measurement (see ``modern.py``)."""

from __future__ import annotations

import argparse
import base64
import re
from collections import Counter
from email.parser import BytesHeaderParser
from pathlib import Path
from typing import Any

from kestrix.core.errors import Rejected
from kestrix.mail.analyzers import parse_authentication_results

from .build import Candidate, dedupe, group_key, near_key
from .common import Layout, MailBenchError, ids_sha256, now, read_jsonl, seeded_key, write_json, write_jsonl
from .features import feature_row
from .ingest import iter_mbox

SEED = "kestrixmodern-v1"
SOURCES = ("asf", "gnu")
SYNTHETIC_MODERN = "synthetic_modern"
CAP_PER_LIST_MONTH = 250
HELD_OUT_LISTS = {"asf": 3, "gnu": 2}  # lists per source whose mail is never used to design a fix
FILE = re.compile(r"^(?P<name>.+)_(?P<year>\d{4})-(?P<month>\d{2})\.mbox$")
AUTO_HEADERS = ("x-jira-fingerprint", "x-github-reason", "x-gitlab-project", "x-jenkins-job", "auto-submitted")


def assign_lists(lists: dict[str, list[str]], seed: str = SEED) -> dict[str, str]:
    """{source|list: 'dev' or 'heldout'}: the lists with the smallest seeded hash are held out, per source."""
    out: dict[str, str] = {}
    for source, names in sorted(lists.items()):
        ranked = sorted(names, key=lambda n: seeded_key(seed, f"{source}|{n}"))
        for i, name in enumerate(ranked):
            out[f"{source}|{name}"] = "heldout" if i < HELD_OUT_LISTS.get(source, 0) else "dev"
    return out


def split_name(meta: dict[str, Any]) -> str:
    return "synthetic" if meta["source"] == SYNTHETIC_MODERN else str(meta["split"])


def _collect(
    files: list[tuple[str, str, int, int, Path]], split_of_list: dict[str, str], limit: int | None
) -> tuple[list[tuple[Candidate, str, int]], Counter[str], Counter[str]]:
    from kestrix.mail.parse import parse_message

    read: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
    kept_rows: list[tuple[Candidate, str, int]] = []
    seen_exact: set[str] = set()
    seen_near: set[str] = set()
    for source, name, year, month, path in files:
        pool: list[Candidate] = []
        for message in iter_mbox(path, limit):
            read[f"{source}|{name}"] += 1
            if message.skip:
                dropped[f"{source}|{name}|{message.skip}"] += 1
                continue
            try:
                parsed = parse_message(message.data)
            except Rejected as exc:
                dropped[f"{source}|{name}|{exc.reason.value}"] += 1
                continue
            except Exception:
                dropped[f"{source}|{name}|parse_error"] += 1
                continue
            sha = parsed.sha256
            near = near_key(parsed.subject, parsed.texts)
            pool.append(Candidate(source, name, False, "ham", message.data, sha, near, year, seeded_key(SEED, sha)))
        pool.sort(key=lambda c: c.rank)
        local: Counter[str] = Counter()
        for cand in dedupe(pool, seen_exact, seen_near, local, CAP_PER_LIST_MONTH):
            kept_rows.append((cand, split_of_list[f"{source}|{name}"], month))
        for key, n in local.items():
            dropped[f"{source}|{name}|{key.split('|', 1)[1]}"] += n
    return kept_rows, read, dropped


def build(layout: Layout, limit: int | None = None) -> dict[str, Any]:
    """Read the downloaded months, drop what the analyzer rejects, deduplicate, cap, split by list, shard."""
    from kestrix.mail.parse import parse_message

    from .modern_synth import generate

    files: list[tuple[str, str, int, int, Path]] = []
    for source in SOURCES:
        folder = layout.raw / "modern" / source
        if not folder.is_dir():
            raise MailBenchError(f"missing {folder}; run acquire first")
        for path in sorted(folder.glob("*.mbox")):
            m = FILE.match(path.name)
            if m:
                files.append((source, m["name"], int(m["year"]), int(m["month"]), path))
    lists: dict[str, list[str]] = {}
    for source, name, *_ in files:
        if name not in lists.setdefault(source, []):
            lists[source].append(name)
    split_of_list = assign_lists(lists)
    kept_rows, read, dropped = _collect(files, split_of_list, limit)
    meta: list[dict[str, Any]] = []
    by_shard: dict[int, list[dict[str, Any]]] = {}

    def add(cand: Candidate, split: str, month: int) -> None:
        shard = int(cand.sha[:8], 16) % layout.shards
        meta.append(
            {
                "id": cand.sha,
                "source": cand.source,
                "subset": cand.origin,
                "label": "ham",
                "year": cand.year,
                "month": month,
                "group": group_key(cand.source, cand.origin, cand.year, False),
                "shard": shard,
                "split": split,
            }
        )
        by_shard.setdefault(shard, []).append({"id": cand.sha, "b64": base64.b64encode(cand.data).decode("ascii")})

    for cand, split, month in kept_rows:
        add(cand, split, month)
    for serial, (family, raw) in enumerate(generate(SEED)):
        parsed = parse_message(raw)
        add(Candidate(SYNTHETIC_MODERN, family, True, "ham", raw, parsed.sha256, None, 2026, ""), "synthetic", serial)
    for shard in range(layout.shards):
        write_jsonl(layout.raw_shard(shard), by_shard.get(shard, []))
    write_jsonl(layout.meta, sorted(meta, key=lambda m: m["id"]))
    report = build_report(meta, read, dropped, split_of_list, limit)
    write_json(layout.reports / "modern-build.json", report)
    return report


def build_report(
    meta: list[dict[str, Any]],
    read: Counter[str],
    dropped: Counter[str],
    split_of_list: dict[str, str],
    limit: int | None,
) -> dict[str, Any]:
    kept = Counter(f"{m['source']}|{m['subset']}|{m['year']}" for m in meta)
    by_split: dict[str, dict[str, Any]] = {}
    for side in ("dev", "heldout", "synthetic"):
        chosen = [m for m in meta if m["split"] == side]
        by_split[side] = {
            "messages": len(chosen),
            "groups": len({m["group"] for m in chosen}),
            "lists": sorted({f"{m['source']}|{m['subset']}" for m in chosen}),
            "ids_sha256": ids_sha256(m["id"] for m in chosen),
        }
    return {
        "schema_version": 1,
        "generated_at": now(),
        "seed": SEED,
        "limit_per_file": limit,
        "cap_per_list_month": CAP_PER_LIST_MONTH,
        "split_by_list": dict(sorted(split_of_list.items())),
        "read_by_list": dict(sorted(read.items())),
        "dropped": dict(sorted(dropped.items())),
        "kept_by_list_year": dict(sorted(kept.items())),
        "splits": by_split,
    }


# --- features ---------------------------------------------------------------------------------


def header_probes(data: bytes) -> dict[str, Any]:
    """Coarse header facts, no values: list headers, automation markers, DKIM and ARC counts, the topmost
    Authentication-Results reduced to authserv-id and method results."""
    head = BytesHeaderParser().parsebytes(data[:262144])
    names = {k.lower() for k in head}
    headers = head.get_all("authentication-results") or []
    top = headers[0] if headers else None
    summary: dict[str, Any] | None = None
    if top is not None:
        parsed = parse_authentication_results(str(top))
        summary = {"authserv": parsed.authserv_id}
        for method in ("dkim", "spf", "dmarc", "arc"):
            summary[method] = sorted(r.result for r in parsed.results if r.method == method)
    return {
        "list_id": "list-id" in names,
        "list_unsub": "list-unsubscribe" in names,
        "precedence": str(head.get("precedence", "")).strip().lower()[:12],
        "auto": sorted(n for n in AUTO_HEADERS if n in names),
        "dkim_sigs": len(head.get_all("dkim-signature") or []),
        "arc": "arc-seal" in names,
        "reply_to": "reply-to" in names,
        "ar": summary,
        "ar_count": len(head.get_all("authentication-results") or []),
        "received_spf": "received-spf" in names,
    }


def feature_file(layout: Layout, shard: int, split: str) -> Path:
    return layout.features / f"modern-{split}-shard-{shard:02d}.jsonl"


def analyze_shard(layout: Layout, shard: int, splits: tuple[str, ...]) -> dict[str, int]:
    """Analyze the messages of ``shard`` whose split is in ``splits`` (current rules); write one file per split."""
    meta = {m["id"]: m for m in read_jsonl(layout.meta)}
    rows: dict[str, list[dict[str, Any]]] = {s: [] for s in splits}
    errors = 0
    for item in read_jsonl(layout.raw_shard(shard)):
        info = meta[item["id"]]
        side = split_name(info)
        if side not in splits:
            continue
        data = base64.b64decode(item["b64"])
        try:
            fields = feature_row(data)
        except Exception:
            errors += 1
            continue
        keep = {k: info[k] for k in ("id", "source", "subset", "label", "year", "month", "group")}
        rows[side].append({**keep, "split": side, **fields, **header_probes(data)})
    for side in splits:
        write_jsonl(feature_file(layout, shard, side), rows[side])
    return {"errors": errors, **{s: len(rows[s]) for s in splits}}


def read_split_features(layout: Layout, split: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for shard in range(layout.shards):
        path = feature_file(layout, shard, split)
        if not path.is_file():
            raise MailBenchError(f"{path} is missing; run features for every shard first")
        rows.extend(read_jsonl(path))
    rows.sort(key=lambda r: r["id"])
    return rows


def run(args: argparse.Namespace, layout: Layout) -> int:
    cmd = args.command
    if cmd == "build":
        report = build(layout, args.limit)
        print({k: v["messages"] for k, v in report["splits"].items()})
        return 0
    if cmd == "features":
        splits = tuple(args.splits.split(","))
        if "heldout" in splits:
            raise MailBenchError("held-out features are written only by the heldout command (one claimed run)")
        print(analyze_shard(layout, args.shard, splits))
        return 0
    from .modern_report import run_report

    return run_report(args, layout)
