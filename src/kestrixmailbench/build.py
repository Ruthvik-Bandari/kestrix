# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Unpack the corpora, drop what the analyzer would reject, deduplicate, label and group.

Outputs under the benchmark root (all 0600, directories 0700):

* ``work/raw/shard-NN.jsonl``: ``{id, b64}`` raw message bytes, sharded by the id (cluster only);
* ``work/meta.jsonl``: ``{id, source, subset, origin, label, year, group, shard}`` per kept message;
* ``reports/build.json``: counts only (read, kept, dropped by reason, kept by source, label and year).

Exact duplicates share a SHA-256 of the raw bytes; near duplicates share a hash of the normalized
subject and body. The first message in a fixed order is kept. The split group is the source file (or
Enron mailbox) plus the Date-header year, except one-year files, which are one group whole.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kestrix.core.errors import Rejected
from kestrix.mail.parse import parse_message

from .common import (
    SEED,
    SYNTHETIC,
    Layout,
    MailBenchError,
    message_year,
    now,
    read_jsonl,
    write_json,
    write_jsonl,
)
from .ingest import RawMessage, enron_names, enron_select, iter_enron, iter_mbox, iter_tar_messages
from .sources import ENRON, KIND_ENRON, KIND_MBOX, KIND_TAR_MESSAGES, SOURCES, Source
from .synthetic import generate

ENRON_SAMPLE = 20_000
ENRON_OVERSAMPLE = 1.5
NEAR_CHARS = 20_000
_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_DIGITS = re.compile(r"\d+")
_SPACE = re.compile(r"\s+")
_REPLY = re.compile(r"^(?:(?:re|fw|fwd)\s*:\s*)+", re.IGNORECASE)


@dataclass
class Candidate:
    source: str
    origin: str
    single_year: bool
    label: str
    data: bytes
    sha: str
    near: str | None
    year: int | None
    rank: str


def near_key(subject: str | None, texts: tuple[str, ...]) -> str | None:
    """Hash of the lower-cased subject and body with URLs and digits masked, or None for an empty message."""
    body = _SPACE.sub(" ", _DIGITS.sub("0", _URL.sub("u", " ".join(texts).casefold()))).strip()[:NEAR_CHARS]
    head = _REPLY.sub("", (subject or "").casefold()).strip()
    head = _SPACE.sub(" ", _DIGITS.sub("0", head))
    if not body and not head:
        return None
    return hashlib.sha256(f"{head}\x1f{body}".encode()).hexdigest()


def group_key(source: str, origin: str, year: int | None, single_year: bool) -> str:
    return f"{source}|{origin}|{'-' if single_year else year if year is not None else 'unk'}"


def _source_messages(
    source: Source, raw: Path, limit: int | None, enron_sample: int, oversample: float, seed: str
) -> Iterator[tuple[str, bool, RawMessage]]:
    """(label, single_year, message) for every file of ``source``."""
    for entry in sorted(source.files, key=lambda f: f.name):
        path = raw / source.name / entry.name
        if not path.is_file():
            raise MailBenchError(f"missing input {path}; run acquire on the transfer node first")
        if entry.kind == KIND_MBOX:
            stream = iter_mbox(path, limit)
        elif entry.kind == KIND_TAR_MESSAGES:
            stream = iter_tar_messages(path, limit)
        elif entry.kind == KIND_ENRON:
            selected = enron_select(enron_names(path), int(enron_sample * oversample), seed)
            stream = iter_enron(path, selected)
        else:
            raise MailBenchError(f"unknown kind {entry.kind}")
        for message in stream:
            yield entry.label, entry.single_year, message


def candidates(
    sources: tuple[Source, ...], raw: Path, limit: int | None, enron_sample: int, oversample: float, seed: str
) -> tuple[dict[str, list[Candidate]], Counter[str], Counter[str]]:
    """Parse every message once; return candidates by source, read counts and drop counts by source|reason."""
    out: dict[str, list[Candidate]] = {}
    read: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
    for source in sources:
        kept: list[Candidate] = []
        for label, single_year, message in _source_messages(source, raw, limit, enron_sample, oversample, seed):
            read[source.name] += 1
            if message.skip:
                dropped[f"{source.name}|{message.skip}"] += 1
                continue
            try:
                parsed = parse_message(message.data)
            except Rejected as exc:
                dropped[f"{source.name}|{exc.reason.value}"] += 1
                continue
            except Exception:
                dropped[f"{source.name}|parse_error"] += 1
                continue
            kept.append(
                Candidate(
                    source.name,
                    message.origin,
                    single_year,
                    label,
                    message.data,
                    parsed.sha256,
                    near_key(parsed.subject, parsed.texts),
                    message_year(message.data),
                    message.rank,
                )
            )
        out[source.name] = kept
    return out, read, dropped


def dedupe(
    pool: list[Candidate], seen_exact: set[str], seen_near: set[str], dropped: Counter[str], cap: int | None = None
) -> list[Candidate]:
    """Keep the first of each exact and near-duplicate class, in the order given, up to ``cap`` messages."""
    kept: list[Candidate] = []
    for cand in pool:
        if cand.sha in seen_exact:
            dropped[f"{cand.source}|duplicate_exact"] += 1
            continue
        if cand.near is not None and cand.near in seen_near:
            dropped[f"{cand.source}|duplicate_near"] += 1
            continue
        if cap is not None and len(kept) >= cap:
            dropped[f"{cand.source}|over_sample_cap"] += 1
            continue
        seen_exact.add(cand.sha)
        if cand.near is not None:
            seen_near.add(cand.near)
        kept.append(cand)
    return kept


def _synthetic_candidates(seed: str, limit: int | None) -> tuple[list[Candidate], Counter[str]]:
    dropped: Counter[str] = Counter()
    out: list[Candidate] = []
    per_family = 30 if limit is None else min(30, max(5, limit // 3))
    for family, label, data in generate(seed, per_family):
        try:
            parsed = parse_message(data)
        except Rejected as exc:  # a template bug, counted rather than hidden
            dropped[f"{SYNTHETIC}|{exc.reason.value}"] += 1
            continue
        out.append(
            Candidate(
                SYNTHETIC, family, True, label, data, parsed.sha256, near_key(parsed.subject, parsed.texts), 2026, ""
            )
        )
    return out, dropped


def build(
    raw: Path,
    layout: Layout,
    *,
    limit: int | None = None,
    enron_sample: int = ENRON_SAMPLE,
    oversample: float = ENRON_OVERSAMPLE,
    seed: str = SEED,
    sources: tuple[Source, ...] | None = None,
) -> dict[str, Any]:
    """Write the corpus shards, metadata and ``reports/build.json``; return the report."""
    shards = layout.shards
    sources = sources or SOURCES
    pools, read, dropped = candidates(sources, raw, limit, enron_sample, oversample, seed)
    synth, synth_dropped = _synthetic_candidates(seed, limit)
    dropped.update(synth_dropped)
    read[SYNTHETIC] = len(synth) + sum(synth_dropped.values())
    seen_exact: set[str] = set()
    seen_near: set[str] = set()
    kept: list[Candidate] = []
    for source in sources:
        pool = pools[source.name]
        cap = None
        if source.name == ENRON:  # sample in rank order, then cap: the first N unique messages by seeded rank
            pool = sorted(pool, key=lambda c: c.rank)
            cap = enron_sample
        kept += dedupe(pool, seen_exact, seen_near, dropped, cap)
    kept += dedupe(synth, seen_exact, seen_near, dropped)
    meta: list[dict[str, Any]] = []
    by_shard: dict[int, list[dict[str, Any]]] = {}
    for cand in kept:
        shard = int(cand.sha[:8], 16) % shards
        meta.append(
            {
                "id": cand.sha,
                "source": cand.source,
                "subset": _subset(cand),
                "origin": cand.origin,
                "label": cand.label,
                "year": cand.year,
                "group": group_key(cand.source, cand.origin, cand.year, cand.single_year),
                "shard": shard,
            }
        )
        by_shard.setdefault(shard, []).append({"id": cand.sha, "b64": base64.b64encode(cand.data).decode("ascii")})
    for shard in range(shards):
        write_jsonl(layout.raw_shard(shard), by_shard.get(shard, []))
    write_jsonl(layout.meta, sorted(meta, key=lambda m: m["id"]))
    report = _report(meta, read, dropped, limit, enron_sample, seed, shards)
    write_json(layout.reports / "build.json", report)
    return report


def _subset(cand: Candidate) -> str:
    """Public subset name (never a person): the file name, or ``maildir`` for Enron mailboxes."""
    return "maildir" if cand.source == ENRON else cand.origin


def _report(
    meta: list[dict[str, Any]],
    read: Counter[str],
    dropped: Counter[str],
    limit: int | None,
    enron_sample: int,
    seed: str,
    shards: int,
) -> dict[str, Any]:
    by_reason: dict[str, dict[str, int]] = {}
    for key, n in sorted(dropped.items()):
        source, reason = key.split("|", 1)
        by_reason.setdefault(source, {})[reason] = n
    kept = Counter((m["source"], m["label"]) for m in meta)
    years: dict[str, Counter[str]] = {}
    for m in meta:
        years.setdefault(f"{m['source']}/{m['label']}", Counter())[str(m["year"]) if m["year"] else "unknown"] += 1
    return {
        "schema_version": 1,
        "generated_at": now(),
        "seed": seed,
        "shards": shards,
        "limit_per_file": limit,
        "enron_sample": enron_sample,
        "read": dict(sorted(read.items())),
        "dropped_by_reason": by_reason,
        "kept": {f"{s}/{label}": n for (s, label), n in sorted(kept.items())},
        "kept_total": len(meta),
        "kept_by_year": {k: dict(sorted(v.items())) for k, v in sorted(years.items())},
        "groups": len({m["group"] for m in meta}),
        "meta_sha256": hashlib.sha256(json.dumps(sorted(m["id"] for m in meta)).encode()).hexdigest(),
    }


def read_meta(layout: Layout) -> list[dict[str, Any]]:
    if not layout.meta.is_file():
        raise MailBenchError(f"{layout.meta} is missing; run build first")
    return list(read_jsonl(layout.meta))
