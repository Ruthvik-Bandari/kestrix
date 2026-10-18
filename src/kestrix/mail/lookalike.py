# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Look-alike domain checks: the From domain and every link host against the protected domains.

A host is compared by its registrable label, the first label of its organizational domain
(``paypal`` in ``mail.paypal.com``). Both sides are reduced to a "skeleton" first: NFKC
(fullwidth forms become ASCII), lower case, a compact table of Cyrillic and Greek letters that
look Latin, then ASCII homoglyphs (``0`` -> ``o``, ``rn`` -> ``m`` ...). A host in the
same organization as the protected domain is genuine and never flagged. A host whose
registrable label is exactly the protected label under another suffix (``paypal.de`` for
``paypal.com``) is not flagged either: brands own many country domains, and this module has no
registry data to tell them apart.

Mixed-script labels are flagged with or without protected domains. The table is a curated
subset of Unicode confusables, not the full list, so some look-alikes are missed.
"""

from __future__ import annotations

import unicodedata
from urllib.parse import urlsplit

from .analyzers import _finding, _is_ip, aligned, org_domain
from .models import Finding, Severity
from .parse import ParsedMessage, normalize_domain

MAX_LOOKALIKE_FINDINGS = 50
MIN_BRAND_LABEL = 3
MIN_EDIT_LABEL = 5
LONG_EDIT_LABEL = 9

# Cyrillic, Greek and a few other letters that render like Latin ones in common fonts.
_CONFUSABLES = str.maketrans(
    {
        "\N{CYRILLIC SMALL LETTER A}": "a",
        "\N{CYRILLIC SMALL LETTER IE}": "e",
        "\N{CYRILLIC SMALL LETTER O}": "o",
        "\N{CYRILLIC SMALL LETTER ER}": "p",
        "\N{CYRILLIC SMALL LETTER ES}": "c",
        "\N{CYRILLIC SMALL LETTER U}": "y",
        "\N{CYRILLIC SMALL LETTER HA}": "x",
        "\N{CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I}": "i",
        "\N{CYRILLIC SMALL LETTER JE}": "j",
        "\N{CYRILLIC SMALL LETTER KOMI DE}": "d",
        "\N{LATIN SMALL LETTER SCRIPT G}": "g",
        "\N{ARMENIAN SMALL LETTER VO}": "n",
        "\N{CYRILLIC SMALL LETTER DZE}": "s",
        "\N{CYRILLIC SMALL LETTER WE}": "w",
        "\N{GREEK SMALL LETTER NU}": "v",
        "\N{GREEK SMALL LETTER OMICRON}": "o",
        "\N{GREEK SMALL LETTER ALPHA}": "a",
        "\N{GREEK SMALL LETTER IOTA}": "i",
        "\N{GREEK SMALL LETTER KAPPA}": "k",
        "\N{GREEK SMALL LETTER TAU}": "t",
    }
)
# ASCII look-alikes: single characters first, then sequences, so "c1" and "cl" fold the same way.
_ASCII_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_ASCII_CHARS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK")


def skeleton(text: str) -> str:
    """Fold ``text`` to the Latin letters it resembles: ``paypa1`` with a Cyrillic "a" -> ``paypal``."""
    folded = unicodedata.normalize("NFKC", text).lower().translate(_CONFUSABLES).translate(_ASCII_CHARS)
    for sequence, letter in _ASCII_SEQUENCES:
        folded = folded.replace(sequence, letter)
    return folded


def edit_distance(a: str, b: str, limit: int) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance, or ``limit + 1`` once it exceeds ``limit``.

    Only cells within ``limit`` of the diagonal are computed, so the cost stays linear in length.
    """
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    beyond = limit + 1
    previous: list[int] = []
    row = [min(j, beyond) for j in range(len(b) + 1)]
    for i in range(1, len(a) + 1):
        previous, before = row, previous
        row = [beyond] * (len(b) + 1)
        row[0] = min(i, beyond)
        for j in range(max(1, i - limit), min(len(b), i + limit) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            best = min(previous[j] + 1, row[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                best = min(best, before[j - 2] + 1)
            row[j] = min(best, beyond)
        if min(row) > limit:
            return beyond
    return row[len(b)]


def analyze_lookalike(msg: ParsedMessage, protected_domains: frozenset[str] = frozenset()) -> list[Finding]:
    """Check the From domain and link hosts. One finding per host and reason, at most 50."""
    hosts: list[tuple[str, bool]] = []
    if msg.from_ is not None:
        hosts.append((msg.from_.domain, True))
    hosts.extend((host, False) for link in msg.links if (host := _link_host(link.href)) is not None)
    protected = [(domain, normalize_domain(domain)[1]) for domain in sorted(protected_domains)]
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for host, is_from in hosts:
        for finding_id, finding in _host_findings(host, is_from, protected):
            if (finding_id, host) in seen:
                continue
            seen.add((finding_id, host))
            findings.append(finding)
            if len(findings) >= MAX_LOOKALIKE_FINDINGS:
                return findings
    return findings


def _link_host(href: str) -> str | None:
    try:
        parts = urlsplit(href.strip())
        hostname = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not hostname:
        return None
    host = normalize_domain(hostname)[0]
    return None if not host or _is_ip(host) else host


def _host_findings(host: str, is_from: bool, protected: list[tuple[str, str]]) -> list[tuple[str, Finding]]:
    display = normalize_domain(host)[1]
    where = "From domain" if is_from else "Link host"
    shown = display if display == host else f"{display} ({host})"
    hits: list[tuple[str, Finding]] = []
    mixed = next((label for label in display.split(".") if _mixed_script(label)), None)
    if mixed is not None:
        hits.append(
            (
                "mail.lookalike.mixed_script",
                _finding(
                    "mail.lookalike.mixed_script",
                    "medium",
                    f"{where} mixes alphabets in one name",
                    "One part of the name combines Latin letters with Cyrillic or Greek ones. Real domains almost "
                    "never do this; it is how a look-alike of a familiar name is built.",
                    f"{where.lower()} {shown}; label {mixed}",
                ),
            )
        )
    label = org_domain(display).split(".")[0]
    label_skeleton = skeleton(label)
    for domain, domain_display in protected:
        if aligned(host, domain):
            continue
        protected_label = org_domain(domain_display).split(".")[0]
        protected_skeleton = skeleton(protected_label)
        evidence = f"{where.lower()} {shown} vs protected domain {domain_display}"
        if not display.isascii() and label_skeleton == protected_skeleton:
            hits.append(
                (
                    "mail.lookalike.homograph",
                    _finding(
                        "mail.lookalike.homograph",
                        "high",
                        f"{where} imitates {domain_display} with look-alike letters",
                        f"Letters from another alphabet make this name look exactly like {domain_display}, but it is a "
                        "different domain owned by someone else.",
                        evidence,
                    ),
                )
            )
        elif label != protected_label and _close(label_skeleton, protected_skeleton):
            severity: Severity = "high" if is_from else "medium"
            hits.append(
                (
                    "mail.lookalike.domain",
                    _finding(
                        "mail.lookalike.domain",
                        severity,
                        f"{where} is a look-alike of {domain_display}",
                        f"The name differs from {domain_display} by a swapped, added or look-alike character (such as "
                        "'rn' for 'm' or '1' for 'l'). Look-alike domains are registered to impersonate a brand.",
                        evidence,
                    ),
                )
            )
        elif (
            label != protected_label
            and len(protected_skeleton) >= MIN_BRAND_LABEL
            and _embeds(display, protected_skeleton)
        ):
            hits.append(
                (
                    "mail.lookalike.brand_in_host",
                    _finding(
                        "mail.lookalike.brand_in_host",
                        "medium",
                        f"{where} puts the name {protected_label} inside another organization's domain",
                        f"The name contains '{protected_label}' but the domain that owns it is {org_domain(display)}, "
                        f"not {domain_display}. Names such as 'paypal.com.account-verify.example' rely on readers "
                        "seeing only the start.",
                        evidence,
                    ),
                )
            )
    return hits


def _close(label_skeleton: str, protected_skeleton: str) -> bool:
    """Equal after folding, or within the edit-distance budget for the protected label's length."""
    if label_skeleton == protected_skeleton:
        return True
    if len(protected_skeleton) < MIN_EDIT_LABEL:
        return False
    limit = 2 if len(protected_skeleton) >= LONG_EDIT_LABEL else 1
    return edit_distance(label_skeleton, protected_skeleton, limit) <= limit


def _embeds(display: str, protected_skeleton: str) -> bool:
    """True when a dot- or hyphen-separated token of the host folds to the protected label."""
    tokens = (token for label in display.split(".") for token in label.split("-"))
    return any(skeleton(token) == protected_skeleton for token in tokens)


def _mixed_script(label: str) -> bool:
    scripts: set[str] = set()
    for char in label:
        if char.isalpha():
            name = unicodedata.name(char, "")
            scripts.update(script for script in _SCRIPTS if name.startswith(script))
    return "LATIN" in scripts and len(scripts) > 1
