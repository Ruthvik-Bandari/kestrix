# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""File benchmark data: Govdocs1 threads (presumed benign) plus synthetic cases; run ``analyze_file`` per file.

Files are read as bytes from the zip archives and never executed, decompressed beyond the zip member or
rendered. Outputs under ``<root>/file`` (0600/0700):

* ``work/meta.jsonl``: ``{id, source, subset, label, year, group, shard, member, ext, size}``, one per kept file;
* ``reports/build.json``: counts only (read, dropped by reason, kept by source, extension and size band).

``id`` is the SHA-256 prefix of the content, so a file that appears in several threads is kept once (the
first thread and member in name order). Shard N is the Nth thread in name order; shard 0 also holds the
synthetic cases. The split group is the thread. Features hold the detected type, extension, size, entropy
and finding ids and severities, never a name or content.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from kestrix.core.errors import Rejected
from kestrix.forensics.analysis import MAX_FILE_BYTES, analyze_file

from .common import (
    BENIGN,
    SEED,
    SYNTHETIC,
    Layout,
    LinkFileBenchError,
    now,
    read_jsonl,
    write_json,
    write_jsonl,
)
from .sources import GOVDOCS, KIND_GOVDOCS, SOURCES
from .synth import MALICIOUS, generate

SIZE_BANDS = ((0, "0"), (4_096, "<4K"), (65_536, "<64K"), (1_048_576, "<1M"), (10_485_760, "<10M"))


def size_band(size: int) -> str:
    return next((label for limit, label in SIZE_BANDS if size < limit or (limit == 0 and size == 0)), ">=10M")


def clean_ext(name: str) -> str:
    """Lower-case last extension of a file name, at most 12 characters of a-z and 0-9, else ``other``/``none``."""
    suffix = name.rsplit("/", 1)[-1].rpartition(".")[2].lower() if "." in name.rsplit("/", 1)[-1] else ""
    if not suffix:
        return "none"
    return suffix if suffix.isalnum() and suffix.isascii() and len(suffix) <= 12 else "other"


def thread_names() -> list[str]:
    source = next(s for s in SOURCES if s.name == GOVDOCS)
    return sorted(f.name for f in source.files if f.kind == KIND_GOVDOCS)


def iter_members(path: Path, limit: int | None = None) -> Iterator[tuple[str, int, bytes | None]]:
    """(member name, size, content) of every file in a zip; content is None for a member over the analyzer limit."""
    with zipfile.ZipFile(path) as archive:
        n = 0
        for info in sorted(archive.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            if limit is not None and n >= limit:
                return
            n += 1
            if info.file_size > MAX_FILE_BYTES:
                yield info.filename, info.file_size, None
            else:
                yield info.filename, info.file_size, archive.read(info)


def build_files(
    raw: Path, layout: Layout, limit: int | None = None, seed: str = SEED, threads: list[str] | None = None
) -> dict[str, Any]:
    """Hash every member of every thread, drop duplicates by content, add the synthetic cases; write ``work/``."""
    threads = threads or thread_names()
    if len(threads) != layout.shards:
        raise LinkFileBenchError(
            f"{len(threads)} Govdocs threads but {layout.shards} shards; use --shards {len(threads)}"
        )
    read: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []
    for shard, zip_name in enumerate(threads):
        path = raw / GOVDOCS / zip_name
        if not path.is_file():
            raise LinkFileBenchError(f"missing input {path}; run acquire on the transfer node first")
        thread = zip_name.removesuffix(".zip")
        for member, size, content in iter_members(path, limit):
            read[GOVDOCS] += 1
            if content is None:
                dropped[f"{GOVDOCS}|input_too_large"] += 1
                continue
            digest = hashlib.sha256(content).hexdigest()
            if digest in seen:
                dropped[f"{GOVDOCS}|duplicate_content"] += 1
                continue
            seen.add(digest)
            kept.append(
                {
                    "id": digest[:24],
                    "source": GOVDOCS,
                    "subset": thread,
                    "label": BENIGN,
                    "year": None,
                    "group": f"{GOVDOCS}|{thread}",
                    "shard": shard,
                    "member": member,
                    "ext": clean_ext(member),
                    "size": size,
                }
            )
    cases = generate()
    read[SYNTHETIC] = len(cases)
    for case in cases:
        kept.append(
            {
                "id": case.id,
                "source": SYNTHETIC,
                "subset": case.family,
                "label": case.label,
                "year": None,
                "group": case.group,
                "shard": 0,
                "member": "",
                "ext": clean_ext(case.name),
                "size": len(case.data),
            }
        )
    ids = [k["id"] for k in kept]
    if len(set(ids)) != len(ids):
        raise LinkFileBenchError("file id collision")
    kept.sort(key=lambda k: k["id"])
    write_jsonl(layout.meta, kept)
    real = [k for k in kept if k["source"] == GOVDOCS]
    report = {
        "schema_version": 1,
        "kind": "file",
        "generated_at": now(),
        "seed": seed,
        "threads": [t.removesuffix(".zip") for t in threads],
        "read": dict(sorted(read.items())),
        "dropped": dict(sorted(dropped.items())),
        "kept": {GOVDOCS: len(real), SYNTHETIC: len(kept) - len(real)},
        "kept_total": len(kept),
        "groups": len({k["group"] for k in kept}),
        "govdocs_by_thread": dict(sorted(Counter(k["subset"] for k in real).items())),
        "govdocs_top_extensions": dict(Counter(k["ext"] for k in real).most_common(40)),
        "govdocs_size_bands": dict(Counter(size_band(k["size"]) for k in real).most_common()),
        "synthetic_families": {f: sum(1 for k in kept if k["subset"] == f) for f in sorted({c.family for c in cases})},
        "synthetic_malicious_families": sorted({c.family for c in cases if c.label == MALICIOUS}),
    }
    write_json(layout.reports / "build.json", report)
    return report


def read_meta(layout: Layout) -> list[dict[str, Any]]:
    if not layout.meta.is_file():
        raise LinkFileBenchError(f"{layout.meta} is missing; run build first")
    return list(read_jsonl(layout.meta))


def file_row(data: bytes, name: str) -> dict[str, Any]:
    """Analyze one file offline and return the stored fields: type, extension, size, entropy and findings."""
    report = analyze_file(io.BytesIO(data), name)
    return {
        "type": report.file_type.id,
        "ext": clean_ext(name),
        "size": report.size,
        "entropy": round(report.entropy.overall, 3),
        "regions": report.entropy.high_entropy_region_count,
        "exif": report.exif_status,
        "findings": [[f.id, f.severity] for f in report.findings],
    }


def run_file_shard(
    layout: Layout,
    raw: Path,
    shard: int,
    meta: dict[str, dict[str, Any]],
    split_of: dict[str, str],
    *,
    splits: tuple[str, ...],
    threads: list[str] | None = None,
) -> dict[str, Any]:
    """Analyze every kept file of one thread (and, for shard 0, the synthetic cases) in ``splits``."""
    from .features import write_shard

    threads = threads or thread_names()
    rows: dict[str, list[dict[str, Any]]] = {side: [] for side in splits}
    errors: Counter[str] = Counter()

    def add(item_id: str, name: str, data: bytes) -> None:
        info = meta[item_id]
        try:
            fields = file_row(data, name)
        except Rejected as exc:
            errors[exc.reason.value] += 1
            return
        except Exception:
            errors["analyzer_error"] += 1
            return
        side = split_of[item_id]
        rows[side].append(
            {**{k: info[k] for k in ("id", "source", "subset", "label", "year", "group")}, "split": side, **fields}
        )

    wanted = {i: m for i, m in meta.items() if m["source"] == GOVDOCS and m["shard"] == shard and split_of[i] in splits}
    if wanted:
        path = raw / GOVDOCS / threads[shard]
        if not path.is_file():
            raise LinkFileBenchError(f"{path} is missing; run acquire first")
        by_member = {m["member"]: i for i, m in wanted.items()}
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                item_id = by_member.get(info.filename)
                if item_id is not None and info.file_size <= MAX_FILE_BYTES:
                    add(item_id, info.filename, archive.read(info))
    if shard == 0:
        for case in generate():
            if split_of[case.id] in splits:
                add(case.id, case.name, case.data)
    return write_shard(layout, shard, rows, errors)
