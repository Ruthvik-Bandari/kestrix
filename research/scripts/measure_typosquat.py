# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Measure the typosquat detector (``kestrix_scan.popular``) offline; prints the numbers docs/modules/code.md quotes.

Run from the repo root: ``python3 research/scripts/measure_typosquat.py --tail-dir DIR [--simple-index FILE]``.

- ``--tail-dir``: the ``tail-<ecosystem>.txt`` files that ``scripts/refresh_popular_names.py --tail-dir`` writes
  (ranks 5,001 to 10,000: real, established packages the detector should leave alone).
- ``--simple-index``: PyPI's ``https://pypi.org/simple/`` JSON (``Accept: application/vnd.pypi.simple.v1+json``);
  a seeded sample of its names measures the warn rate on the raw long tail (unlabeled: it holds real squats).
- The local OSV index (``kestrix-scan db update``) supplies the names of packages reported as malicious (``MAL-``);
  only names are read.

Synthetic squats are made from the top 3,000 listed names with seeded random edits, so recall on them measures
the rules against the generator's classes, not against real attackers; the OSV names are the independent check.
"""

# ruff: noqa: S311  (seeded sampling for a measurement, not security)
from __future__ import annotations

import argparse
import random
import sqlite3
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages" / "kestrix-scan" / "src"))

from kestrix_scan import osvdb, popular  # noqa: E402

SEED = 20261023
PER_CLASS = 1000
KEYS = {c: popular._NEIGHBOURS[c] for c in popular._NEIGHBOURS}
LETTERS = "abcdefghijklmnopqrstuvwxyz"


def _positions(name: str) -> list[int]:
    return [i for i, c in enumerate(name) if c.isalpha() and i >= 2]


def _head(name: str) -> tuple[str, str]:
    """(part to edit, rest): a vendor or scope is edited, the package after it is kept."""
    head, slash, rest = name.partition("/")
    return (head, slash + rest) if slash else (name, "")


def _transform(kind: str, name: str, rng: random.Random) -> str | None:
    head, rest = _head(name)
    pos = _positions(head)
    if not pos or len(head) < 5:
        return None
    i = rng.choice(pos)
    if kind == "swap":
        return head[:i] + head[i + 1] + head[i] + head[i + 2 :] + rest if i + 1 < len(head) else None
    if kind == "drop":
        return head[:i] + head[i + 1 :] + rest
    if kind == "double":
        return head[: i + 1] + head[i] + head[i + 1 :] + rest
    if kind == "insert":
        return head[:i] + rng.choice(LETTERS) + head[i:] + rest
    if kind == "key":
        near = sorted(KEYS.get(head[i], ()))
        return head[:i] + rng.choice(near) + head[i + 1 :] + rest if near else None
    if kind == "substitute":
        return head[:i] + rng.choice(LETTERS) + head[i + 1 :] + rest
    if kind == "homoglyph":
        table = {"o": "0", "l": "1", "i": "1", "s": "5", "m": "rn", "w": "vv"}
        spots = [j for j, c in enumerate(head) if c in table]
        if not spots:
            return None
        j = rng.choice(spots)
        return head[:j] + table[head[j]] + head[j + 1 :] + rest
    if kind == "separator":
        if "-" in head:
            return head.replace("-", "", 1) + rest
        return head[:i] + "-" + head[i:] + rest
    if kind == "affix":
        choice = rng.choice(["python-", "py", "node-", "js-", "-js", "-py", "-python", "-node"])
        return head + choice + rest if choice.startswith("-") else choice + head + rest
    if kind == "two edits":
        first = _transform("substitute", name, rng)
        return _transform("drop", first, rng) if first else None
    if kind == "combosquat":
        return head + rng.choice(["-utils", "-security", "-official", "-core2", "-helper"]) + rest
    return None


KINDS = (
    "swap", "drop", "double", "insert", "key", "substitute", "homoglyph", "separator", "affix", "two edits", "combosquat",
)  # fmt: skip


def _malicious(ecosystem: str) -> list[str]:
    db = osvdb.connect()
    if db is None:
        return []
    try:
        rows = db.execute(
            "SELECT DISTINCT f.name FROM affected f JOIN advisories a ON a.id = f.advisory "
            "WHERE f.ecosystem = ? AND a.malicious = 1",
            (ecosystem,),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()
    return [popular.normalize(ecosystem, row[0]) for row in rows]


def _loose(index: popular._Index, name: str) -> bool:
    """Within one edit of any listed name of 5 or more characters, with none of the detector's gates (ranks, digits)."""
    mask = popular._mask(name)
    return any(
        len(other) >= popular.MIN_LENGTH
        and (mask ^ other_mask).bit_count() <= 2
        and popular._distance(name, other, 1) == 1
        for length in (len(name) - 1, len(name), len(name) + 1)
        for other, _, other_mask in index.by_length.get(length, ())
    )


def _read(path: Path) -> list[str]:
    return [line for line in path.read_text().splitlines() if line] if path.is_file() else []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tail-dir", type=Path, required=True)
    parser.add_argument("--simple-index", type=Path)
    args = parser.parse_args()
    generated, counts = popular.snapshot_info()
    print(f"snapshot generated {generated}: {counts}")
    for eco in popular.ECOSYSTEMS:
        index = popular._index(eco)
        assert index is not None
        rng = random.Random(f"{SEED}{eco}")
        listed = set(index.names)
        tail = _read(args.tail_dir / f"tail-{eco}.txt")
        legit = listed | set(tail)
        warned_listed = sum(1 for name in index.names if popular.suspect(eco, name))
        warned_tail = [name for name in tail if popular.suspect(eco, name)]
        print(f"\n## {eco}")
        print(f"listed names flagged: {warned_listed} of {len(index.names)}")
        print(f"established tail (ranks 5001-10000) flagged: {len(warned_tail)} of {len(tail)}", end="")
        print(
            f" ({100 * len(warned_tail) / max(len(tail), 1):.2f}%); by rule: {dict(Counter(popular.suspect(eco, n).rule for n in warned_tail))}"
        )  # type: ignore[union-attr]
        if eco == "PyPI" and args.simple_index:
            import json

            names = [popular.normalize(eco, p["name"]) for p in json.loads(args.simple_index.read_text())["projects"]]
            sample = random.Random(SEED).sample([n for n in names if n not in legit], 20_000)
            flagged = sum(1 for name in sample if popular.suspect(eco, name))
            print(
                f"raw PyPI long tail (seeded sample of 20,000 of {len(names)} names): flagged {flagged} ({100 * flagged / len(sample):.2f}%)"
            )
        pool = [n for n in index.names[:3000] if len(n) >= 5]
        total_hit = total = 0
        print("synthetic squats (recall by class, n = distinct squats not in any list):")
        for kind in KINDS:
            made: set[str] = set()
            for _ in range(PER_CLASS * 5):
                squat = _transform(kind, rng.choice(pool), rng)
                if squat and squat not in legit:
                    made.add(popular.normalize(eco, squat))
                if len(made) >= PER_CLASS:
                    break
            made -= legit
            hit = sum(1 for name in made if popular.suspect(eco, name))
            print(f"  {kind:11s} n={len(made):4d} recall={100 * hit / max(len(made), 1):5.1f}%")
            if kind != "combosquat":
                total_hit, total = total_hit + hit, total + len(made)
        print(f"  all classes except combosquat: recall={100 * total_hit / max(total, 1):.1f}% of {total}")
        mal = [n for n in _malicious(eco) if n not in legit]
        if mal:
            hits = [(n, popular.suspect(eco, n)) for n in mal]
            flagged = [(n, s) for n, s in hits if s]
            print(
                f"OSV malicious names (MAL-, {len(mal)} not in the lists): flagged {len(flagged)} ({100 * len(flagged) / len(mal):.2f}%)"
            )
            print("  by rule:", dict(Counter(s.rule for _, s in flagged)))
            sample = random.Random(SEED).sample(mal, min(len(mal), 20_000))
            loose = [n for n in sample if len(n) >= popular.MIN_LENGTH and _loose(index, n)]
            caught = sum(1 for n in loose if popular.suspect(eco, n))
            print(
                f"  squat-shaped (one edit from a listed name, no gates; sample of {len(sample)}): {len(loose)}, "
                f"flagged {caught} ({100 * caught / max(len(loose), 1):.1f}%)"
            )
            for name, found in random.Random(SEED).sample(flagged, min(12, len(flagged))):
                print(f"    {name} -> {found.target} ({found.rule}: {found.reason})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
