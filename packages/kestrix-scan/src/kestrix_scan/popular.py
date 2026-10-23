# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Typosquat detection for the install guard: is a requested name a near-miss of a popular package?

The data is ``popular_names.json``, a snapshot of the most popular package names per ecosystem in rank order
(PyPI, npm, crates.io, Packagist; refreshed by hand with ``scripts/refresh_popular_names.py``). Nothing here uses
the network. A name that is itself in the snapshot is never suspect. Otherwise it is suspect when one of these
rules matches, tried in this order, and the popular package it resembles ranks high enough for that rule:

1. ``homoglyph``: the same name once look-alike characters are folded (``0``/``o``, ``1``/``l``/``i``, ``rn``/``m``,
   ``vv``/``w``, accented and a few Cyrillic or Greek letters). Any rank.
2. ``separator``: the same name once ``-``, ``_`` and ``.`` are removed (``crossenv`` for ``cross-env``). Any rank.
3. ``affix``: a popular name with a conventional prefix or suffix added (``python-``, ``py``, ``node-``, ``-js``,
   ``-py``, ``-python``...). Top 1,500 only.
   A name in the popular package's own npm scope or Packagist vendor is never suspect (only its owner can publish there).
4. ``edit``: Damerau-Levenshtein (optimal string alignment) distance 1, or 2 when both names are long (the
   requested one has 10 or more characters). A swap of two adjacent letters, a doubled or dropped letter, or a
   neighbouring-key slip counts at any rank; any other single edit (names of 7 or more characters) only against the top 1,500, and two edits
   only against the top 1,000. Edits that add, drop or change a digit are ignored (``boto`` and ``boto3`` are
   siblings, not squats), and names under 5 characters are never checked.

The rules are deterministic and the reason is spelled out for the user. This is a heuristic: a sibling or
fork with a similar name can be flagged, and a squat that is not close to a listed name is missed.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

ECOSYSTEMS = ("PyPI", "npm", "crates.io", "Packagist")
MIN_LENGTH = 5
LONG_NAME = 10
AFFIX_RANK = 1500
EDIT1_RANK = 1500
OTHER_EDIT_LENGTH = 7
EDIT2_RANK = 1000
SNAPSHOT = "popular_names.json"
_SEPARATORS = re.compile(r"[-_.]+")
_PREFIXES = ("python-", "python", "py-", "py", "node-", "node", "js-", "npm-", "lib", "the-")
_SUFFIXES = ("-js", ".js", "js", "-py", "py", "-python", "-node", "-nodejs", "-npm", "-lib", "-library", "-pkg")
_CONFUSABLE = str.maketrans(
    {
        "0": "o", "1": "l", "i": "l", "5": "s",
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",  # Cyrillic
        "\u0456": "l", "\u0458": "j", "\u0455": "s",
        "\u03bf": "o", "\u03bd": "v", "\u03c1": "p", "\u03b1": "a", "\u03b9": "l",  # Greek
    }
)  # fmt: skip
_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
_NEIGHBOURS = {
    char: {_ROWS[r][c + d] for d in (-1, 1) if 0 <= c + d < len(_ROWS[r])}
    | {
        _ROWS[r + dr][c + dc]
        for dr in (-1, 1)
        for dc in (-1, 0)
        if 0 <= r + dr < len(_ROWS) and 0 <= c + dc < len(_ROWS[r + dr])
    }
    for r in range(len(_ROWS))
    for c, char in enumerate(_ROWS[r])
}


@dataclass(frozen=True, slots=True)
class Suspect:
    ecosystem: str
    name: str  # as normalized
    target: str  # the popular name it resembles
    rank: int  # 1-based rank of the target in the snapshot
    rule: str  # homoglyph, separator, affix or edit
    reason: str  # plain words for the user


@dataclass(frozen=True, slots=True)
class _Index:
    names: tuple[str, ...]
    rank: dict[str, int]  # name -> 1-based rank
    skeleton: dict[str, str]  # folded name -> most popular name with that fold
    stripped: dict[str, str]  # name without separators -> most popular name
    by_length: dict[int, list[tuple[str, int, int]]]  # length -> (name, rank, character-presence mask)


def normalize(ecosystem: str, name: str) -> str:
    """The name as the registry compares it: PEP 503 for PyPI, ``-`` for ``_`` on crates.io, lower case otherwise."""
    name = name.strip().lower()
    if ecosystem == "PyPI":
        return _SEPARATORS.sub("-", name)
    if ecosystem == "crates.io":
        return name.replace("_", "-")
    return name


@lru_cache(maxsize=1)
def _snapshot() -> dict[str, Any]:
    """The bundled snapshot, or an empty one when it is missing or unreadable (the check then stays silent)."""
    try:
        data = json.loads(resources.files("kestrix_scan").joinpath(SNAPSHOT).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def snapshot_info() -> tuple[str, dict[str, int]]:
    """(generated date, names per ecosystem) of the bundled snapshot; ('', {}) when there is none."""
    data = _snapshot()
    names = data.get("names")
    if not isinstance(names, dict):
        return "", {}
    return str(data.get("generated", "")), {eco: len(items) for eco, items in names.items() if isinstance(items, list)}


def _fold(name: str) -> str:
    plain = (
        "".join(char for char in unicodedata.normalize("NFKD", name) if not unicodedata.combining(char))
        .replace("rn", "m")
        .replace("vv", "w")
    )
    return plain.translate(_CONFUSABLE)


def _mask(name: str) -> int:
    mask = 0
    for char in name:
        mask |= 1 << (ord(char) & 63)
    return mask


@lru_cache(maxsize=len(ECOSYSTEMS))
def _index(ecosystem: str) -> _Index | None:
    names = _snapshot().get("names", {}).get(ecosystem)
    if not isinstance(names, list) or not names:
        return None
    rank: dict[str, int] = {}
    skeleton: dict[str, str] = {}
    stripped: dict[str, str] = {}
    by_length: dict[int, list[tuple[str, int, int]]] = {}
    for position, name in enumerate(names, 1):
        if not isinstance(name, str):
            continue
        rank.setdefault(name, position)
        skeleton.setdefault(_fold(name), name)
        stripped.setdefault(_SEPARATORS.sub("", name), name)
        by_length.setdefault(len(name), []).append((name, position, _mask(name)))
    return _Index(tuple(names), rank, skeleton, stripped, by_length)


def _distance(a: str, b: str, limit: int) -> int:
    """Optimal string alignment distance (insert, delete, substitute, swap adjacent), or ``limit + 1`` when larger."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous2: list[int] = []
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        row = [i]
        for j, char_b in enumerate(b, 1):
            best = min(previous[j] + 1, row[j - 1] + 1, previous[j - 1] + (char_a != char_b))
            if i > 1 and j > 1 and char_a == b[j - 2] and a[i - 2] == char_b:
                best = min(best, previous2[j - 2] + 1)
            row.append(best)
        if min(row) > limit:
            return limit + 1
        previous2, previous = previous, row
    return previous[-1]


def _squattable(wanted: str, target: str) -> bool:
    """False for a name in the target's own scope or vendor (only its owner can publish there) and for a scoped
    name compared with an unscoped one."""
    if ("/" in wanted) != ("/" in target):
        return False
    return "/" not in wanted or wanted.partition("/")[0] != target.partition("/")[0]


def _digits(name: str) -> str:
    return "".join(sorted(char for char in name if char.isdigit()))


def _single_edit(a: str, b: str) -> tuple[str, str] | None:
    """(kind, words) for names exactly one edit apart; None otherwise. ``a`` is requested and ``b`` popular."""
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]:
            return "swap", "two adjacent letters are swapped"
        if len(diff) == 1:
            if a[diff[0]] in _NEIGHBOURS.get(b[diff[0]], ()):
                return "key", f"`{a[diff[0]]}` sits next to `{b[diff[0]]}` on the keyboard"
            return "other", "one letter differs"
        return None
    longer, shorter = (a, b) if len(a) > len(b) else (b, a)
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1 :] == shorter:
            extra = longer[i]
            doubled = extra in longer[max(i - 1, 0) : i] or extra in longer[i + 1 : i + 2]
            if len(a) > len(b):
                return ("double" if doubled else "other"), f"`{extra}` is added" + (
                    " (a doubled letter)" if doubled else ""
                )
            return ("double" if doubled else "other"), f"`{extra}` is missing" + (
                " (a doubled letter)" if doubled else ""
            )
    return None


def _involves_digit(a: str, b: str) -> bool:
    return _digits(a) != _digits(b)


def _by_affix(index: _Index, name: str) -> tuple[str, str] | None:
    candidates = []
    for prefix in _PREFIXES:
        if name.startswith(prefix):
            candidates.append((name[len(prefix) :].lstrip("-_."), f"the prefix `{prefix}` is added"))
    for suffix in _SUFFIXES:
        if name.endswith(suffix):
            candidates.append((name[: -len(suffix)].rstrip("-_."), f"the suffix `{suffix}` is added"))
    best: tuple[int, str, str] | None = None
    for base, words in candidates:
        position = index.rank.get(base)
        if (
            position is not None
            and len(base) >= MIN_LENGTH
            and position <= AFFIX_RANK
            and _squattable(name, base)
            and (best is None or position < best[0])
        ):
            best = (position, base, words)
    return None if best is None else (best[1], best[2])


def suspect(ecosystem: str, name: str) -> Suspect | None:
    """The popular package ``name`` looks like a squat of, or None. ``ecosystem`` is an OSV ecosystem name."""
    index = _index(ecosystem) if ecosystem in ECOSYSTEMS else None
    if index is None:
        return None
    wanted = normalize(ecosystem, name)
    if wanted in index.rank or len(wanted) < MIN_LENGTH:
        return None
    for rule, table, words in (
        (
            "homoglyph",
            index.skeleton,
            "it matches once look-alike characters (such as `0`/`o`, `1`/`l`, `rn`/`m`) are folded",
        ),
        ("separator", index.stripped, "it matches once `-`, `_` and `.` are ignored"),
    ):
        key = _fold(wanted) if rule == "homoglyph" else _SEPARATORS.sub("", wanted)
        target = table.get(key)
        if target is not None and target != wanted and len(key) >= MIN_LENGTH and _squattable(wanted, target):
            return Suspect(ecosystem, wanted, target, index.rank[target], rule, words)
    affixed = _by_affix(index, wanted)
    if affixed is not None:
        return Suspect(ecosystem, wanted, affixed[0], index.rank[affixed[0]], "affix", affixed[1])
    return _by_edit(index, ecosystem, wanted)


def _by_edit(index: _Index, ecosystem: str, wanted: str) -> Suspect | None:
    limit = 2 if len(wanted) >= LONG_NAME else 1
    best: tuple[int, str, str] | None = None
    wanted_mask = _mask(wanted)
    for length in range(len(wanted) - limit, len(wanted) + limit + 1):
        for name, position, mask in index.by_length.get(length, ()):
            if (best is not None and position >= best[0]) or len(name) < MIN_LENGTH or not _squattable(wanted, name):
                continue
            if (wanted_mask ^ mask).bit_count() > 2 * limit or _involves_digit(wanted, name):
                continue
            distance = _distance(wanted, name, limit)
            if distance == 1:
                single = _single_edit(wanted, name)
                if single is None:
                    continue
                kind, words = single
                if kind in ("swap", "key", "double") or (position <= EDIT1_RANK and len(wanted) >= OTHER_EDIT_LENGTH):
                    best = (position, name, words)
            elif distance == 2 and limit == 2 and position <= EDIT2_RANK and len(name) >= LONG_NAME - 2:
                best = (position, name, "two letters differ")
    if best is None:
        return None
    return Suspect(ecosystem, wanted, best[1], best[0], "edit", best[2])
