# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Normalize, then remove exact and near-duplicate functions across every source, before any split.

Normalization drops comments and all whitespace differences (Python through ``tokenize``,
JavaScript/TypeScript through a small lexer that keeps string and template literals intact).
Near duplicates use MinHash over token 5-gram shingles: 128 independent hash functions taken
from one SHAKE-128 digest per shingle (standard library only), banded LSH with 16 bands of 8
rows, and an estimated Jaccard similarity of at least 0.9.

Records are visited in a fixed priority order (SVEN, CVEfixes, MoreFixes, then publication date
and id). A record is dropped when its vulnerable or patched function duplicates a function of a
record kept earlier, so no function (in either role) appears twice in the pool, and no split can
see a copy of another split's code. Pairs whose two versions are equal after normalization are
dropped first.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import struct
import textwrap
import tokenize
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .labels import SOURCE_PRIORITY

SHINGLE = 5
PERMUTATIONS = 128
BANDS = 16
ROWS = PERMUTATIONS // BANDS
THRESHOLD = 0.9
BUCKET_CAP = 500
GENERIC = re.compile(r"[A-Za-z_$][\w$]*|\d[\w.]*|\S")
PY_SKIP = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}


def python_tokens(code: str) -> list[str]:
    try:
        return [
            t.string
            for t in tokenize.generate_tokens(io.StringIO(textwrap.dedent(code)).readline)
            if t.type not in PY_SKIP
        ]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        stripped = re.sub(r"(?m)#[^\n'\"]*$", "", code)
        return GENERIC.findall(stripped)


def js_tokens(code: str) -> list[str]:
    """Tokens of JavaScript/TypeScript with comments removed; string literals stay whole."""
    tokens: list[str] = []
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        if c.isspace():
            i += 1
        elif code.startswith("//", i):
            end = code.find("\n", i)
            i = n if end < 0 else end
        elif code.startswith("/*", i):
            end = code.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif c in "'\"`":
            j = i + 1
            while j < n and code[j] != c:
                j += 2 if code[j] == "\\" else 1
            tokens.append(code[i : j + 1])
            i = j + 1
        else:
            m = GENERIC.match(code, i)
            assert m is not None  # GENERIC matches any non-space character
            tokens.append(m.group(0))
            i = m.end()
    return tokens


def tokens(code: str, language: str) -> list[str]:
    return python_tokens(code) if language == "python" else js_tokens(code)


def normalized(code: str, language: str) -> str:
    return " ".join(tokens(code, language))


def fingerprint(code: str, language: str) -> str:
    return hashlib.sha256(normalized(code, language).encode()).hexdigest()


def shingles(toks: list[str]) -> set[str]:
    if len(toks) < SHINGLE:
        return {" ".join(toks)}
    return {" ".join(toks[i : i + SHINGLE]) for i in range(len(toks) - SHINGLE + 1)}


def minhash(items: set[str]) -> tuple[int, ...]:
    """128 minima, one per hash function; hash function k is bytes 4k..4k+3 of SHAKE-128(shingle)."""
    rows = [struct.unpack("<128I", hashlib.shake_128(s.encode()).digest(4 * PERMUTATIONS)) for s in items]
    return tuple(map(min, zip(*rows, strict=True)))


def similarity(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    return sum(x == y for x, y in zip(a, b, strict=True)) / PERMUTATIONS


def bands(signature: tuple[int, ...]) -> list[tuple[int, tuple[int, ...]]]:
    return [(b, signature[b * ROWS : (b + 1) * ROWS]) for b in range(BANDS)]


class NearIndex:
    """Banded LSH over the signatures of kept functions."""

    def __init__(self) -> None:
        self.buckets: dict[tuple[int, tuple[int, ...]], list[int]] = defaultdict(list)
        self.signatures: list[tuple[int, ...]] = []
        self.owners: list[str] = []

    def find(self, signature: tuple[int, ...]) -> str | None:
        seen: set[int] = set()
        for key in bands(signature):
            for idx in self.buckets.get(key, ()):
                if idx not in seen:
                    seen.add(idx)
                    if similarity(signature, self.signatures[idx]) >= THRESHOLD:
                        return self.owners[idx]
        return None

    def add(self, signature: tuple[int, ...], owner: str) -> None:
        idx = len(self.signatures)
        self.signatures.append(signature)
        self.owners.append(owner)
        for key in bands(signature):
            bucket = self.buckets[key]
            if len(bucket) < BUCKET_CAP:
                bucket.append(idx)


def order_key(record: dict[str, Any]) -> tuple[int, str, str]:
    return (SOURCE_PRIORITY.index(record["source"]), record.get("published") or "9999", record["id"])


def deduplicate(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return the kept records (with normalized hashes added) and the drop statistics."""
    stats: dict[str, Counter[str]] = defaultdict(Counter)
    cross: Counter[str] = Counter()
    exact: dict[str, str] = {}
    near = NearIndex()
    by_id: dict[str, dict[str, Any]] = {}
    kept: list[dict[str, Any]] = []
    for record in sorted(records, key=order_key):
        key = f"{record['source']}/{record['language']}"
        stats[key]["input"] += 1
        language = record["language"]
        units = [("vulnerable", record["vulnerable"])]
        if record.get("patched"):
            units.append(("patched", record["patched"]))
        toks = {role: tokens(code, language) for role, code in units}
        hashes = {role: hashlib.sha256(" ".join(t).encode()).hexdigest() for role, t in toks.items()}
        if hashes.get("patched") == hashes["vulnerable"]:
            stats[key]["dropped_unchanged_after_normalization"] += 1
            continue
        owner = next((exact[h] for h in hashes.values() if h in exact), None)
        reason = "dropped_exact_duplicate"
        signatures = {}
        if owner is None:
            signatures = {role: minhash(shingles(t)) for role, t in toks.items()}
            owner = next((o for o in (near.find(s) for s in signatures.values()) if o is not None), None)
            reason = "dropped_near_duplicate"
        if owner is not None:
            stats[key][reason] += 1
            cross[f"{record['source']}->{by_id[owner]['source']}"] += 1
            continue
        for role, h in hashes.items():
            exact[h] = record["id"]
            near.add(signatures[role], record["id"])
        record["vulnerable_sha256"] = hashes["vulnerable"]
        record["patched_sha256"] = hashes.get("patched")
        by_id[record["id"]] = record
        kept.append(record)
        stats[key]["kept"] += 1
    report = {
        "schema_version": 1,
        "method": {
            "normalization": "comments and whitespace removed (Python tokenize; JS/TS lexer)",
            "exact": "sha256 of the normalized token stream",
            "near": f"MinHash {PERMUTATIONS} hash functions (SHAKE-128), {SHINGLE}-token shingles, "
            f"LSH {BANDS}x{ROWS}, estimated Jaccard >= {THRESHOLD}",
            "order": "sven, cvefixes, morefixes; then publication date; then id",
        },
        "per_source_language": {k: dict(sorted(v.items())) for k, v in sorted(stats.items())},
        "dropped_by_source_pair": dict(sorted(cross.items())),
        "kept_total": len(kept),
    }
    return kept, report


def run(root: Path) -> dict[str, Any]:
    src = root / "work" / "candidates.jsonl"
    records = [json.loads(line) for line in src.read_text(encoding="utf-8").splitlines() if line]
    kept, report = deduplicate(records)
    out = root / "work" / "deduped.jsonl"
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in kept), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(out)
    return report
