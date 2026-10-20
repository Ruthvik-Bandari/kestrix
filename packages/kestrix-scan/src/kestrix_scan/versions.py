# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Version ordering for PyPI (PEP 440) and npm (SemVer 2.0), and OSV ``affected`` matching.

PEP 440 is implemented here from the specification (https://peps.python.org/pep-0440/) rather than
vendored from ``packaging``: the scanner only needs to parse and order versions, which is about 60
lines, while ``packaging.version`` would bring a second license and code that has to be kept in
sync. Supported: epochs, release segments of any length (trailing zeros ignored), pre-releases
(``a``/``b``/``rc`` and their spellings ``alpha``, ``beta``, ``c``, ``pre``, ``preview``),
post-releases (including the implicit ``1.0-1``), dev releases, local versions, a leading ``v``,
case and the ``.``/``-``/``_`` separators. Legacy (non-PEP 440) versions do not parse and are
reported as not checked.

SemVer follows https://semver.org/spec/v2.0.0.html: numeric identifiers compare numerically,
alphanumeric ones in ASCII order, a pre-release sorts before its release and build metadata is
ignored. A leading ``v`` or ``=`` and a missing minor or patch number (``1.2``) are accepted.

OSV matching follows https://ossf.github.io/osv-schema/#affectedranges-field: a version is affected
when it is listed in ``versions`` or falls inside an ``ECOSYSTEM`` or ``SEMVER`` range. Within a
range the events are sorted by version; ``introduced`` opens an interval (``"0"`` means from the
start), ``fixed`` closes it before that version and ``last_affected`` closes it after that version.
``GIT`` ranges and ranges with unparseable events are ignored.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from typing import Any

VersionKey = tuple[Any, ...]

_PEP440 = re.compile(
    r"""
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    """,
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}

_SEMVER = re.compile(
    r"[v=]?\s*(?P<major>0|[1-9][0-9]*)(?:\.(?P<minor>0|[1-9][0-9]*))?(?:\.(?P<patch>0|[1-9][0-9]*))?"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def pep440_key(text: str) -> VersionKey | None:
    """A sort key that orders PEP 440 versions as the specification does, or None when ``text`` is not one."""
    match = _PEP440.fullmatch(text.strip())
    if match is None:
        return None
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_l, dev_l = match.group("pre_l"), match.group("dev_l")
    post_n = match.group("post_n1") or match.group("post_n2")
    has_post = match.group("post_n1") is not None or match.group("post_l") is not None
    if pre_l is not None:
        pre: tuple[int, ...] = (1, _PRE_RANK[pre_l.lower()], int(match.group("pre_n") or 0))
    elif not has_post and dev_l is not None:
        pre = (0,)  # 1.0.dev0 sorts before 1.0a0
    else:
        pre = (2,)  # a final (or post) release sorts after every pre-release
    post = (1, int(post_n or 0)) if has_post else (0,)
    dev = (0, int(match.group("dev_n") or 0)) if dev_l is not None else (1,)
    local: tuple[tuple[int, int, str], ...] = ()
    if match.group("local"):
        parts = re.split(r"[-_.]", match.group("local").lower())
        local = tuple((1, int(p), "") if p.isdigit() else (0, 0, p) for p in parts)
    return (int(match.group("epoch") or 0), tuple(release), pre, post, dev, local)


def semver_key(text: str) -> VersionKey | None:
    """A sort key that orders SemVer 2.0 versions by precedence, or None when ``text`` is not one."""
    match = _SEMVER.fullmatch(text.strip())
    if match is None:
        return None
    core = (int(match.group("major")), int(match.group("minor") or 0), int(match.group("patch") or 0))
    pre = match.group("pre")
    if pre is None:
        return (core, (1,))
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (core, (0, ids))


KEYS: dict[str, Callable[[str], VersionKey | None]] = {"PyPI": pep440_key, "npm": semver_key}


def version_key(ecosystem: str, text: str) -> VersionKey:
    """A sort key for ``text`` in ``ecosystem``; an unparseable version sorts first."""
    parse = KEYS.get(ecosystem)
    key = parse(text) if parse is not None else None
    return key if key is not None else ()


_ZERO = "0"


def in_range(
    key: VersionKey, events: Sequence[dict[str, Any]], parse: Callable[[str], VersionKey | None]
) -> bool | None:
    """True when ``key`` falls inside the OSV range ``events``; None when an event cannot be parsed."""
    ordered: list[tuple[VersionKey, int, str]] = []
    for event in events:
        if not isinstance(event, dict):
            return None
        for kind, rank in (("introduced", 0), ("fixed", 1), ("last_affected", 1)):
            value = event.get(kind)
            if not isinstance(value, str):
                continue
            if kind == "introduced" and value == _ZERO:
                ordered.append(((), rank, kind))  # sorts before every version
                continue
            parsed = parse(value)
            if parsed is None:
                return None
            ordered.append((parsed, rank, kind))
    ordered.sort(key=lambda item: (item[0], item[1]))
    affected = False
    for event_key, _, kind in ordered:
        if kind == "introduced" and event_key <= key:
            affected = True
        elif (kind == "fixed" and event_key <= key) or (kind == "last_affected" and event_key < key):
            affected = False
    return affected


def is_affected(ecosystem: str, version: str, ranges: Iterable[Any], versions: Iterable[Any]) -> bool:
    """True when ``version`` is in the OSV ``versions`` list or inside one of the ``ranges``."""
    parse = KEYS.get(ecosystem)
    if parse is None:
        return False
    key = parse(version)
    for listed in versions:
        if isinstance(listed, str) and (listed == version or (key is not None and parse(listed) == key)):
            return True
    if key is None:
        return False
    for item in ranges:
        if not isinstance(item, dict) or item.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        events = item.get("events")
        if isinstance(events, list) and in_range(key, events, parse):
            return True
    return False


def fixed_versions(ranges: Iterable[Any]) -> list[str]:
    """Every ``fixed`` event in ECOSYSTEM and SEMVER ranges, in the order they appear."""
    found: list[str] = []
    for item in ranges:
        if not isinstance(item, dict) or item.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        for event in item.get("events") or []:
            value = event.get("fixed") if isinstance(event, dict) else None
            if isinstance(value, str) and value not in found:
                found.append(value)
    return found


def next_fixed(ecosystem: str, version: str, candidates: Iterable[str]) -> str | None:
    """The lowest fixed version above ``version``, or None when there is none."""
    parse = KEYS.get(ecosystem)
    current = parse(version) if parse is not None else None
    if parse is None or current is None:
        return None
    above = [(k, text) for text in candidates if (k := parse(text)) is not None and k > current]
    return min(above)[1] if above else None


def highest(ecosystem: str, candidates: Iterable[str]) -> str | None:
    """The highest parseable version among ``candidates``, or None."""
    parse = KEYS.get(ecosystem)
    keyed = [(k, text) for text in candidates if parse is not None and (k := parse(text)) is not None]
    return max(keyed)[1] if keyed else None


def all_versions(ranges: Iterable[Any], versions: Iterable[Any]) -> bool:
    """True when a range opens at ``0`` and never closes: every version is affected (typical of MAL- entries)."""
    for item in ranges:
        if not isinstance(item, dict) or item.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        events = [e for e in item.get("events") or [] if isinstance(e, dict)]
        if any(e.get("introduced") == _ZERO for e in events) and not any(
            "fixed" in e or "last_affected" in e or "limit" in e for e in events
        ):
            return True
    return False
