# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""CWE families: how a CVE's CWE and each tool's findings are put on one scale.

The families are the categories of ``bench/mapping.py`` (the existing benchmark's CWE table, so "command injection" means
the same thing in both benchmarks) plus five that matter for JavaScript or that eslint-plugin-security reports. A CVE
pair is *in scope* when at least one of its CWEs maps to a family; the other CVEs (CWE-20, memory safety, access
control, information exposure and so on) count only in the any-finding-near-the-change rate.

Kestrix and Bandit map exactly as in ``bench/mapping.py`` (rule table first, then the CWE the finding reports);
eslint-plugin-security reports no CWE, so its rules are mapped here by the weakness each rule's documentation names.
The tables are facts about each tool's rules; no rule text is copied.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from bench.mapping import BANDIT_OVERRIDES, CWE_CATEGORY, KESTRIX_BY_CWE, KESTRIX_PREFIXES, KESTRIX_RULES

EXTRA_CWE_FAMILY: dict[int, str] = {
    1321: "protopollution",
    1333: "redos",
    185: "redos",
    352: "csrf",
    208: "timing",
    942: "cors",
    98: "fileinclusion",  # PHP include/require of a request-chosen path (added with the PHP benchmark)
}
FAMILY_OF_CWE: dict[int, str] = CWE_CATEGORY | EXTRA_CWE_FAMILY

FAMILY_NAMES: dict[str, str] = {
    "cmdi": "Command injection",
    "codeinj": "Code injection",
    "deserialization": "Insecure deserialization",
    "hash": "Weak hash or cipher",
    "ldapi": "LDAP injection",
    "pathtraver": "Path traversal",
    "redirect": "Open redirect",
    "securecookie": "Insecure cookie",
    "sqli": "SQL injection",
    "trustbound": "Trust boundary violation",
    "weakrand": "Weak randomness",
    "xpathi": "XPath injection",
    "xss": "Cross-site scripting",
    "xxe": "XML external entities",
    "ssrf": "Server-side request forgery",
    "tls": "TLS verification disabled",
    "jwt": "JWT signature not verified",
    "tempfile": "Insecure temporary file",
    "debug": "Debug mode enabled",
    "secrets": "Hard-coded credential",
    "protopollution": "Prototype pollution",
    "redos": "Regular-expression denial of service",
    "csrf": "Cross-site request forgery",
    "timing": "Timing side channel",
    "cors": "Permissive CORS",
    "fileinclusion": "File inclusion",
}

# eslint-plugin-security rule -> CWE of the weakness the rule documents. Rules with no entry map to no family.
ESLINT_SECURITY_CWE: dict[str, int] = {
    "security/detect-child-process": 78,
    "security/detect-eval-with-expression": 95,
    "security/detect-non-literal-fs-filename": 22,
    "security/detect-unsafe-regex": 1333,
    "security/detect-non-literal-regexp": 1333,
    "security/detect-pseudoRandomBytes": 338,
    "security/detect-possible-timing-attacks": 208,
    "security/detect-no-csrf-before-method-override": 352,
    "security/detect-disable-mustache-escape": 79,
    "security/detect-object-injection": 1321,
}

_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def parse_cwes(values: Iterable[str]) -> list[int]:
    """CWE numbers from strings such as ``CWE-79`` or ``CWE-078``; NVD placeholders are dropped."""
    found: list[int] = []
    for value in values:
        for match in _CWE.findall(value or ""):
            number = int(match)
            if number not in found:
                found.append(number)
    return found


def families_for_cwes(cwes: Iterable[int]) -> frozenset[str]:
    return frozenset(FAMILY_OF_CWE[c] for c in cwes if c in FAMILY_OF_CWE)


def kestrix_families(rule_id: str, cwe: str) -> frozenset[str]:
    cwes = parse_cwes([cwe])
    if rule_id in KESTRIX_BY_CWE:
        return families_for_cwes(cwes)
    if rule_id in KESTRIX_RULES:
        return frozenset({KESTRIX_RULES[rule_id]})
    for prefix, family in KESTRIX_PREFIXES.items():
        if rule_id.startswith(prefix):
            return frozenset({family})
    return families_for_cwes(cwes)  # js.* and any rule added later map by the CWE they report


def bandit_families(test_id: str, cwe: int | None) -> frozenset[str]:
    if test_id in BANDIT_OVERRIDES:
        family = BANDIT_OVERRIDES[test_id]
        return frozenset({family}) if family else frozenset()
    return families_for_cwes([cwe] if cwe else [])


# Psalm taint analysis issue type -> CWE of the weakness it reports (the weakness each type's documentation names).
PSALM_TAINT_CWE: dict[str, int] = {
    "TaintedSql": 89,
    "TaintedHtml": 79,
    "TaintedTextWithQuotes": 79,
    "TaintedShell": 78,
    "TaintedInclude": 98,
    "TaintedFile": 22,
    "TaintedSSRF": 918,
    "TaintedUnserialize": 502,
    "TaintedEval": 95,
    "TaintedCallable": 94,
    "TaintedLdap": 90,
    "TaintedXpath": 643,
}


def psalm_families(issue_type: str) -> frozenset[str]:
    cwe = PSALM_TAINT_CWE.get(issue_type)
    return families_for_cwes([cwe] if cwe else [])


def eslint_families(rule_id: str) -> frozenset[str]:
    cwe = ESLINT_SECURITY_CWE.get(rule_id)
    return families_for_cwes([cwe] if cwe else [])
