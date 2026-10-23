# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Version ordering for Packagist (Composer), RubyGems, NuGet and Maven, from each ecosystem's own rules.

Each ``*_key`` function returns an object that orders versions as the package manager does, or ``None`` when
the text is not a version it understands (the scanner then reports the dependency as possibly affected
instead of guessing).

- Composer (``composer_key``): https://getcomposer.org/doc/articles/versions.md. A leading ``v`` is dropped,
  numeric parts compare as numbers with trailing zeros ignored, and the stability suffix orders
  ``-dev`` < ``alpha`` < ``beta`` < ``RC`` < stable < ``patch``/``pl``. Branch names (``dev-main``) are not versions.
- RubyGems (``rubygems_key``): ``Gem::Version``. Segments split at dots and at digit/letter changes; a version
  with a letter segment is a pre-release and sorts before the release; ``-`` means ``.pre.``.
- NuGet (``nuget_key``): SemVer 2.0 with up to four numeric parts; pre-release labels compare case-insensitively.
- Maven (``maven_key``): a port of ``org.apache.maven.artifact.versioning.ComparableVersion`` (Maven 3.9):
  ``.`` and ``-`` separators, nested lists after ``-``, and the qualifier order
  ``alpha`` < ``beta`` < ``milestone`` < ``rc`` < ``snapshot`` < release (``""``, ``ga``, ``final``, ``release``) < ``sp``
  < any other qualifier, compared as text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ----- Composer

_COMPOSER = re.compile(
    r"v?(?P<rel>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[._-]?(?P<mod>stable|beta|b|rc|alpha|a|patch|pl|p)(?:[.-]?(?P<modn>[0-9]+))?)?"
    r"(?:[.-]?(?P<dev>dev))?(?:\+.*)?",
    re.IGNORECASE,
)
_COMPOSER_RANK = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "stable": 4, "patch": 5, "pl": 5, "p": 5}


def _strip_zeros(parts: list[int]) -> tuple[int, ...]:
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def composer_key(text: str) -> tuple[Any, ...] | None:
    match = _COMPOSER.fullmatch(text.strip())
    if match is None:
        return None
    release = _strip_zeros([int(part) for part in match.group("rel").split(".")])
    modifier = match.group("mod")
    dev = match.group("dev") is not None
    if modifier is None:
        rank, number = (0, 0) if dev else (4, 0)
    else:
        rank, number = _COMPOSER_RANK[modifier.lower()], int(match.group("modn") or 0)
    return (release, rank, number, 0 if dev else 1)


# ----- RubyGems

_GEM = re.compile(r"[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def rubygems_key(text: str) -> tuple[Any, ...] | None:
    text = text.strip()
    if not _GEM.fullmatch(text):
        return None
    segments: list[int | str] = [
        int(part) if part.isdigit() else part.lower()
        for part in re.findall(r"[0-9]+|[a-zA-Z]+", text.replace("-", ".pre."))
    ]
    first_letter = next((i for i, part in enumerate(segments) if isinstance(part, str)), len(segments))
    release = [part for part in segments[:first_letter] if isinstance(part, int)]
    tail = segments[first_letter:]
    pre = [(0, part, 0) if isinstance(part, str) else (1, "", part) for part in tail]
    while pre and pre[-1] == (1, "", 0):
        pre.pop()
    return (_strip_zeros(release or [0]), 0 if tail else 1, tuple(pre))


# ----- NuGet

_NUGET = re.compile(
    r"(?P<n>[0-9]+(?:\.[0-9]+){0,3})(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?"
)


def nuget_key(text: str) -> tuple[Any, ...] | None:
    match = _NUGET.fullmatch(text.strip())
    if match is None:
        return None
    parts = [int(part) for part in match.group("n").split(".")]
    parts += [0] * (4 - len(parts))
    pre = match.group("pre")
    if pre is None:
        return (tuple(parts), (1,))
    labels = tuple((0, int(p), "") if p.isdigit() else (1, 0, p.lower()) for p in pre.split("."))
    return (tuple(parts), (0, labels))


# ----- Maven (ComparableVersion)

_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_RELEASE_INDEX = str(_QUALIFIERS.index(""))
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
_SHORT = {"a": "alpha", "b": "beta", "m": "milestone"}
_MAX_MAVEN_CHARS = 200


@dataclass(slots=True)
class _Int:
    value: int


@dataclass(slots=True)
class _Str:
    value: str  # normalized qualifier


@dataclass(slots=True)
class _List:
    items: list[Any]


_Item = _Int | _Str | _List


def _qualifier(text: str, followed_by_digit: bool) -> _Str:
    if followed_by_digit and len(text) == 1 and text in _SHORT:
        text = _SHORT[text]
    return _Str(_ALIASES.get(text, text))


def _comparable(qualifier: str) -> str:
    return str(_QUALIFIERS.index(qualifier)) if qualifier in _QUALIFIERS else f"{len(_QUALIFIERS)}-{qualifier}"


def _is_null(item: _Item) -> bool:
    if isinstance(item, _Int):
        return item.value == 0
    if isinstance(item, _Str):
        return _comparable(item.value) == _RELEASE_INDEX
    return not item.items


def _normalize(items: list[Any]) -> None:
    """Drop trailing items equal to "nothing" (``0``, ``ga``, empty lists), looking past a trailing non-empty list."""
    for index in range(len(items) - 1, -1, -1):
        if _is_null(items[index]):
            del items[index]
        elif not isinstance(items[index], _List):
            break


def _cmp(a: Any, b: Any) -> int:
    return int(a > b) - int(a < b)


def _compare(left: _Item | None, right: _Item | None) -> int:
    if left is None:
        return 0 if right is None else -_compare(right, None)
    if isinstance(left, _Int):
        if right is None:
            return 0 if left.value == 0 else 1
        return _cmp(left.value, right.value) if isinstance(right, _Int) else 1
    if isinstance(left, _Str):
        if right is None:
            return _cmp(_comparable(left.value), _RELEASE_INDEX)
        if isinstance(right, _Str):
            return _cmp(_comparable(left.value), _comparable(right.value))
        return -1
    if right is None:
        return 0 if not left.items else _compare(left.items[0], None)
    if isinstance(right, _Int):
        return -1
    if isinstance(right, _Str):
        return 1
    for index in range(max(len(left.items), len(right.items))):
        one = left.items[index] if index < len(left.items) else None
        two = right.items[index] if index < len(right.items) else None
        result = _compare(one, two)
        if result:
            return result
    return 0


def _parse_maven(version: str) -> _List:
    text = version.lower()
    root = _List([])
    current = root
    stack = [root]
    is_digit = False
    start = 0

    def item(digit: bool, chunk: str) -> _Item:
        return _Int(int(chunk)) if digit else _qualifier(chunk, False)

    for index, char in enumerate(text):
        if char == ".":
            current.items.append(_Int(0) if index == start else item(is_digit, text[start:index]))
            start = index + 1
        elif char == "-":
            current.items.append(_Int(0) if index == start else item(is_digit, text[start:index]))
            start = index + 1
            current = _List([])
            stack[-1].items.append(current)
            stack.append(current)
        elif char.isdigit():
            if not is_digit and index > start:
                current.items.append(_qualifier(text[start:index], True))
                start = index
                nested = _List([])
                current.items.append(nested)
                current = nested
                stack.append(current)
            is_digit = True
        else:
            if is_digit and index > start:
                current.items.append(item(True, text[start:index]))
                start = index
                nested = _List([])
                current.items.append(nested)
                current = nested
                stack.append(current)
            is_digit = False
    if len(text) > start:
        current.items.append(item(is_digit, text[start:]))
    while stack:
        _normalize(stack.pop().items)
    return root


class MavenVersion:
    """A parsed Maven version; orders like ``ComparableVersion``."""

    __slots__ = ("_root", "text")

    def __init__(self, text: str) -> None:
        self.text = text
        self._root = _parse_maven(text)

    def _order(self, other: object) -> int:
        if not isinstance(other, MavenVersion):
            return NotImplemented  # type: ignore[no-any-return]
        return _compare(self._root, other._root)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MavenVersion) and self._order(other) == 0

    def __hash__(self) -> int:
        return hash(repr(self._root))

    def __lt__(self, other: object) -> bool:
        return self._order(other) < 0

    def __le__(self, other: object) -> bool:
        return self._order(other) <= 0

    def __gt__(self, other: object) -> bool:
        return self._order(other) > 0

    def __ge__(self, other: object) -> bool:
        return self._order(other) >= 0


_MAVEN_OK = re.compile(r"[0-9A-Za-z_.+-]+")


def maven_key(text: str) -> MavenVersion | None:
    text = text.strip()
    if not text or len(text) > _MAX_MAVEN_CHARS or not _MAVEN_OK.fullmatch(text):
        return None
    return MavenVersion(text)
