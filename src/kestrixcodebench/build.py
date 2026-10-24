# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Build the file-pair benchmark: filter, de-duplicate, group, split, write the files.

* **Filters** (``kestrixvul.paths``, so the same rules as the function benchmark): no test, vendored, bundled, minified
  or generated files; files over ``MAX_CHARS`` or ``MAX_LINES`` and before-files under ``MIN_LINES`` are skipped; a pair
  whose two versions are identical is dropped.
* **De-duplication**: pairs with the same before and after text are one pair (their CVEs, CWEs and repositories merge).
* **Groups**: connected components of repositories, CVE and advisory ids and before-file contents (so a fork or a
  backport that copied a file lands in the same group as the original). A group never straddles dev and test.
* **Split**: a seeded hash of the group id sends ``TEST_PERCENT`` percent of the groups to the locked test, the rest to
  dev. The split is made before any scanner runs. Test files are written but no job reads them until the locked test.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from kestrixvul.paths import content_reason, path_reason
from kestrixvul.split import UnionFind

from .common import (
    EXTENSIONS,
    KINDS,
    PHP_LANGUAGE,
    SEED,
    SHARDS,
    SPLITS,
    TEST_PERCENT,
    CodeBenchError,
    Layout,
    ids_sha256,
    now,
    private_dir,
    seeded_percent,
    sha256_text,
    shard_of,
    write_json,
    write_jsonl,
    write_private,
)
from .diff import MAX_LINES as DIFF_MAX_LINES
from .diff import diff_ops, old_ranges
from .families import families_for_cwes
from .sources import RawPair, RawUnchanged, read_cvefixes, read_ghsa

MAX_CHARS = 400_000
MAX_LINES = DIFF_MAX_LINES
MIN_LINES = 5


def language_of(path: str) -> tuple[str, str] | None:
    """(language, extension) of a source path, or None for other files."""
    ext = PurePosixPath(path).suffix.lower()
    language = EXTENSIONS.get(ext)
    return (language, ext) if language else None


def size_reason(text: str, *, minimum: bool) -> str | None:
    if len(text) > MAX_CHARS:
        return "oversized"
    lines = text.count("\n") + 1
    if lines > MAX_LINES:
        return "too_many_lines"
    if minimum and lines < MIN_LINES:
        return "too_short"
    return None


def _language_ok(path: str, only: str | None) -> bool:
    found = language_of(path)
    if found is None:
        return False
    if only is None:  # PHP has a root of its own (a different working database), so the default build leaves it out
        return found[0] != PHP_LANGUAGE
    return found[0] == only


def pair_reason(pair: RawPair, only: str | None = None) -> str | None:
    """Why a changed file is left out of the benchmark, or None to keep it."""
    if not _language_ok(pair.path, only):
        return "other_language"
    reason = path_reason(pair.path) or content_reason(pair.before) or content_reason(pair.after)
    if reason:
        return reason
    reason = size_reason(pair.before, minimum=True) or size_reason(pair.after, minimum=False)
    if reason:
        return reason
    if pair.before.split() == pair.after.split():
        return "whitespace_only"
    return None


def unchanged_reason(item: RawUnchanged, only: str | None = None) -> str | None:
    if not _language_ok(item.path, only):
        return "other_language"
    return path_reason(item.path) or content_reason(item.text) or size_reason(item.text, minimum=True)


def file_id(*parts: str) -> str:
    return sha256_text("\x1f".join(parts))[:16]


def merge_pairs(pairs: list[RawPair], dropped: Counter[str], only: str | None = None) -> list[dict[str, Any]]:
    """Filter and de-duplicate; one record per distinct (before, after) text, with the diff computed once."""
    rows: dict[str, dict[str, Any]] = {}
    texts: dict[str, tuple[str, str]] = {}
    for pair in pairs:
        reason = pair_reason(pair, only)
        if reason:
            dropped[f"{pair.source}:{reason}"] += 1
            continue
        before_sha, after_sha = sha256_text(pair.before), sha256_text(pair.after)
        key = file_id(before_sha, after_sha)
        row = rows.get(key)
        if row is not None:
            dropped[f"{pair.source}:duplicate_pair"] += 1
            for name, values in (("repos", pair.repos), ("cves", pair.cves), ("advisories", pair.advisories)):
                row[name] = sorted(set(row[name]) | set(values))
            row["cwes"] = sorted(set(row["cwes"]) | set(pair.cwes))
            row["families"] = sorted(families_for_cwes(row["cwes"]))
            row["commits"] = sorted(set(row["commits"]) | {pair.commit})
            continue
        language, ext = language_of(pair.path) or ("", "")
        ops = diff_ops(pair.before, pair.after)
        old_lines = pair.before.count("\n") + 1
        rows[key] = {
            "id": key,
            "source": pair.source,
            "repos": sorted(pair.repos),
            "commits": [pair.commit],
            "published": pair.published,
            "cves": pair.cves,
            "advisories": pair.advisories,
            "cwes": sorted(pair.cwes),
            "families": sorted(families_for_cwes(pair.cwes)),
            "language": language,
            "ext": ext,
            "path": pair.path,
            "before_lines": old_lines,
            "after_lines": pair.after.count("\n") + 1,
            "before_sha": before_sha,
            "after_sha": after_sha,
            "ops": [list(op) for op in ops],
            "old_ranges": [list(r) for r in old_ranges(ops, old_lines)],
        }
        texts[key] = (pair.before, pair.after)
    for key, row in rows.items():
        row["_text"] = texts[key]
    return list(rows.values())


def merge_unchanged(
    items: list[RawUnchanged], known_texts: set[str], dropped: Counter[str], only: str | None = None
) -> list[tuple[dict[str, Any], str]]:
    out: dict[str, tuple[dict[str, Any], str]] = {}
    for item in items:
        reason = unchanged_reason(item, only)
        if reason:
            dropped[f"unchanged:{reason}"] += 1
            continue
        text_sha = sha256_text(item.text)
        if text_sha in known_texts or text_sha in out:
            dropped["unchanged:duplicate"] += 1
            continue
        language, ext = language_of(item.path) or ("", "")
        out[text_sha] = (
            {
                "id": file_id("u", text_sha),
                "source": item.source,
                "repo": item.repo,
                "commit": item.commit,
                "language": language,
                "ext": ext,
                "path": item.path,
                "lines": item.text.count("\n") + 1,
                "text_sha": text_sha,
            },
            item.text,
        )
    return list(out.values())


def split_rows(
    pairs: list[dict[str, Any]], unchanged: list[dict[str, Any]], seed: str = SEED
) -> tuple[dict[str, str], dict[str, str]]:
    """({file id: split}, {file id: group}). Raises if a group, repository or CVE appears on both sides."""
    uf = UnionFind()
    for row in pairs:
        nodes = [f"repo:{r}" for r in row["repos"]]
        nodes += [f"cve:{c}" for c in row["cves"]] + [f"adv:{a}" for a in row["advisories"]]
        nodes.append(f"blob:{row['before_sha']}")
        for node in nodes[1:]:
            uf.union(nodes[0], node)
        uf.find(nodes[0])
    for row in unchanged:
        uf.union(f"repo:{row['repo']}", f"blob:{row['text_sha']}")
    split: dict[str, str] = {}
    group: dict[str, str] = {}
    for row in pairs:
        root = uf.find(f"repo:{row['repos'][0]}")
        group[row["id"]] = root
        split[row["id"]] = "test" if seeded_percent(seed, root) < TEST_PERCENT else "dev"
    for row in unchanged:
        root = uf.find(f"repo:{row['repo']}")
        group[row["id"]] = root
        split[row["id"]] = "test" if seeded_percent(seed, root) < TEST_PERCENT else "dev"
    owner: dict[str, str] = {}
    for row in pairs:
        for node in [f"repo:{r}" for r in row["repos"]] + [f"cve:{c}" for c in row["cves"]]:
            if owner.setdefault(node, split[row["id"]]) != split[row["id"]]:
                raise CodeBenchError(f"{node} appears in dev and test")
    for row in unchanged:
        if owner.setdefault(f"repo:{row['repo']}", split[row["id"]]) != split[row["id"]]:
            raise CodeBenchError(f"repo:{row['repo']} appears in dev and test")
    return split, group


def write_file(layout: Layout, row: dict[str, Any], kind: str, text: str) -> None:
    path = layout.shard_dir(row["split"], shard_of(row["id"])) / kind / f"{row['id']}{row['ext']}"
    write_private(path, text.encode("utf-8", "replace"))


def cve_count(rows: list[dict[str, Any]]) -> int:
    return len({c for r in rows for c in r["cves"]} | {a for r in rows for a in r["advisories"] if not r["cves"]})


def manifest(
    pairs: list[dict[str, Any]], unchanged: list[dict[str, Any]], dropped: Counter[str], seed: str = SEED
) -> dict[str, Any]:
    splits: dict[str, Any] = {}
    for side in SPLITS:
        chosen = [r for r in pairs if r["split"] == side]
        extra = [r for r in unchanged if r["split"] == side]
        in_scope = [r for r in chosen if r["families"]]
        splits[side] = {
            "pairs": len(chosen),
            "pairs_in_scope": len(in_scope),
            "projects": len({r["repos"][0] for r in chosen}),
            "cves": cve_count(chosen),
            "by_language": dict(sorted(Counter(r["language"] for r in chosen).items())),
            "by_language_in_scope": dict(sorted(Counter(r["language"] for r in in_scope).items())),
            "by_source": dict(sorted(Counter(r["source"] for r in chosen).items())),
            "by_family": dict(sorted(Counter(f for r in chosen for f in r["families"]).items())),
            "by_cwe": dict(sorted(Counter(str(c) for r in chosen for c in r["cwes"]).items())),
            "before_kloc": round(sum(r["before_lines"] for r in chosen) / 1000, 1),
            "after_kloc": round(sum(r["after_lines"] for r in chosen) / 1000, 1),
            "unchanged_files": len(extra),
            "unchanged_by_language": dict(sorted(Counter(r["language"] for r in extra).items())),
            "unchanged_kloc": round(sum(r["lines"] for r in extra) / 1000, 1),
            "ids_sha256": ids_sha256([r["id"] for r in chosen] + [r["id"] for r in extra]),
        }
    body: dict[str, Any] = {
        "schema_version": 1,
        "created_at": now(),
        "seed": seed,
        "test_percent_of_groups": TEST_PERCENT,
        "unit": "group = connected component of repositories, CVE and advisory ids, and before-file contents",
        "shards": SHARDS,
        "dropped": dict(sorted(dropped.items())),
        "splits": splits,
        "evaluated": {"dev": True, "test": False},
    }
    body["manifest_sha256"] = ids_sha256([f"{s}:{v['ids_sha256']}" for s, v in splits.items()])
    return body


def build(
    layout: Layout, cvefixes_db: Path, vul_root: Path, limit: int | None = None, only_language: str | None = None
) -> dict[str, Any]:
    """Read both sources, filter, de-duplicate, split and write the files and the manifest.

    ``only_language`` ("web") keeps only that language's files: the web-file benchmark is built in its own root, so the
    ids and the split of the Python, JavaScript and TypeScript benchmark are untouched.
    """
    if not cvefixes_db.is_file():
        raise CodeBenchError(f"{cvefixes_db} is missing")
    os.umask(0o077)
    private_dir(layout.work)
    dropped: Counter[str] = Counter()
    raw: list[RawPair] = []
    raw_unchanged: list[RawUnchanged] = []
    for source in (read_cvefixes(cvefixes_db), read_ghsa(vul_root, raw_unchanged)):
        for count, pair in enumerate(source):
            if limit is not None and count >= limit:
                break
            raw.append(pair)
    by_source = Counter(p.source for p in raw)
    pairs = merge_pairs(raw, dropped, only_language)
    texts = {r["id"]: r.pop("_text") for r in pairs}
    known = {r["before_sha"] for r in pairs} | {r["after_sha"] for r in pairs}
    unchanged_items = merge_unchanged(raw_unchanged, known, dropped, only_language)
    unchanged = [row for row, _ in unchanged_items]
    unchanged_text = {row["id"]: text for row, text in unchanged_items}
    split, group = split_rows(pairs, unchanged)
    for row in [*pairs, *unchanged]:
        row["split"], row["group"] = split[row["id"]], group[row["id"]]
    for side in SPLITS:
        for shard in range(SHARDS):
            for kind in KINDS:
                private_dir(layout.shard_dir(side, shard) / kind)
    for row in pairs:
        before, after = texts[row["id"]]
        write_file(layout, row, "b", before)
        write_file(layout, row, "a", after)
    for row in unchanged:
        write_file(layout, row, "u", unchanged_text[row["id"]])
    write_jsonl(layout.pairs, sorted(pairs, key=lambda r: r["id"]))
    write_jsonl(layout.unchanged, sorted(unchanged, key=lambda r: r["id"]))
    body = manifest(pairs, unchanged, dropped)
    body["raw_changed_files"] = dict(by_source)
    write_json(layout.split_manifest, body)
    return body
