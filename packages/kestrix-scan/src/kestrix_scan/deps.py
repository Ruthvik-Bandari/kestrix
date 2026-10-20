# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Dependency findings: pinned versions in lockfiles checked against the local OSV index, offline.

For each dependency the advisories naming its package are matched against its version. All the
advisories that affect it become one finding: ``dep.malicious`` (critical) when any of them is a
``MAL-`` malicious-package report, otherwise ``dep.vulnerable`` with the highest advisory severity,
the first advisory CWE (``CWE-1395`` when none is given) and the lowest version that fixes every
advisory. No index means no dependency findings and one ``dep.db_stale`` note per scan.

Suppression: an advisory id or alias in ``[tool.kestrix] ignore-advisories`` (with a reason) drops
that advisory everywhere; ``# kestrix: ignore[<rule-id or advisory id>] reason`` on a requirements
line, or the line above, does the same for that line.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .lockfiles import Dependency, Parsed, parser_for
from .models import SEVERITY_RANK, Finding, Note, fingerprint
from .registry import RULES
from .versions import fixed_versions, highest, is_affected, next_fixed, version_key

if TYPE_CHECKING:  # osvdb (sqlite3, zipfile) is imported only when a dependency file is checked
    from . import osvdb

VULNERABLE = "dep.vulnerable"
MALICIOUS = "dep.malicious"
STALE = "dep.db_stale"
NOT_CHECKED = "dep.not_checked"
UNSUPPORTED = "dep.unsupported"
DEFAULT_CWE = "CWE-1395"
MAX_IDS_SHOWN = 4
MAX_NOT_CHECKED_SHOWN = 5


@dataclass
class _Index:
    """The read-only index connection, opened on first use and shared by every file of a process.

    It is reopened when ``KESTRIX_SCAN_DB`` points somewhere else, or while there is no index yet.
    """

    path: Path | None = None
    db: sqlite3.Connection | None = None
    cache: dict[tuple[str, str], list[osvdb.Advisory]] = field(default_factory=dict)

    def advisories(self, ecosystem: str, name: str) -> list[osvdb.Advisory]:
        from . import osvdb

        current = osvdb.db_path()
        if self.db is None or current != self.path:
            if self.db is not None:
                self.db.close()
            self.path, self.db, self.cache = current, osvdb.connect(current), {}
        if self.db is None:
            return []
        key = (ecosystem, name)
        if key not in self.cache:
            try:
                self.cache[key] = osvdb.advisories_for(self.db, ecosystem, name)
            except sqlite3.Error:
                self.cache[key] = []
        return self.cache[key]


_INDEX = _Index()


def is_dependency_file(rel: str) -> bool:
    return parser_for(rel) is not None


def check_file(
    text: str,
    rel: str,
    suppressions: Mapping[int, frozenset[str]],
    active: frozenset[str] | None,
    ignore_advisories: Mapping[str, str],
) -> tuple[list[Finding], list[Note], int]:
    """Findings, notes and the suppressed count for one dependency file's text."""
    parse = parser_for(rel)
    if parse is None:
        return [], [], 0
    parsed: Parsed = parse(text.replace("\r\n", "\n"))
    notes = _file_notes(parsed, rel)
    findings: list[Finding] = []
    suppressed = 0
    for dep in parsed.dependencies:
        ids_here = suppressions.get(dep.line, frozenset()) | suppressions.get(dep.line - 1, frozenset())
        matched = [
            adv
            for adv in _INDEX.advisories(dep.ecosystem, dep.name)
            if is_affected(dep.ecosystem, dep.version, adv.ranges, adv.versions)
        ]
        kept = [adv for adv in matched if not ({adv.id, *adv.aliases} & (ids_here | set(ignore_advisories)))]
        if not kept:
            if matched:
                suppressed += 1
            continue
        finding = _finding(dep, kept, rel)
        if active is not None and finding.rule_id not in active:
            continue
        if finding.rule_id in ids_here:
            suppressed += 1
            continue
        findings.append(finding)
    return findings, notes, suppressed


def _file_notes(parsed: Parsed, rel: str) -> list[Note]:
    notes = []
    if parsed.unsupported is not None:
        notes.append(Note(id=UNSUPPORTED, path=rel, line=1, message=f"Dependencies not checked: {parsed.unsupported}."))
    if parsed.not_checked:
        shown = ", ".join(parsed.not_checked[:MAX_NOT_CHECKED_SHOWN])
        more = (
            f" and {len(parsed.not_checked) - MAX_NOT_CHECKED_SHOWN} more"
            if len(parsed.not_checked) > MAX_NOT_CHECKED_SHOWN
            else ""
        )
        notes.append(
            Note(
                id=NOT_CHECKED,
                path=rel,
                line=1,
                message=f"{len(parsed.not_checked)} requirement(s) without an exact == pin were not checked: {shown}{more}. Pin them, or check the lockfile instead.",
            )
        )
    return notes


def vulnerabilities(advisories: list[osvdb.Advisory]) -> list[list[str]]:
    """Advisories grouped into vulnerabilities: ids linked through aliases (a GHSA, its PYSEC and CVE) form one group.

    Each group lists its ids with GitHub (GHSA) ids first, then CVE ids, then the rest.
    """
    groups: list[set[str]] = []
    for adv in advisories:
        ids = {adv.id, *adv.aliases}
        linked = [group for group in groups if group & ids]
        merged = ids.union(*linked)
        groups = [group for group in groups if not (group & ids)] + [merged]
    rank = {"GHSA": 0, "CVE": 1}
    ordered = [sorted(group, key=lambda i: (rank.get(i.split("-", 1)[0], 2), i)) for group in groups]
    return sorted(ordered, key=lambda group: group[0])


def group_fixes(group: list[str], advisories: list[osvdb.Advisory]) -> list[str]:
    """The fixed versions every advisory of one vulnerability group names."""
    return [fix for adv in advisories if adv.id in group for fix in fixed_versions(adv.ranges)]


def describe_ids(groups: list[list[str]]) -> str:
    """``GHSA-a (CVE-1), GHSA-b`` for at most four vulnerabilities, then ``+N more``."""
    shown = [f"{group[0]} ({group[1]})" if len(group) > 1 else group[0] for group in groups[:MAX_IDS_SHOWN]]
    more = f" (+{len(groups) - MAX_IDS_SHOWN} more)" if len(groups) > MAX_IDS_SHOWN else ""
    return ", ".join(shown) + more


def _finding(dep: Dependency, advisories: list[osvdb.Advisory], rel: str) -> Finding:
    groups = vulnerabilities(advisories)
    shown = describe_ids(groups)
    package = f"{dep.name}@{dep.version}"
    snippet = f"{package} {' '.join(sorted(adv.id for adv in advisories))}"
    malicious = [adv for adv in advisories if adv.malicious]
    if malicious:
        rule = RULES[MALICIOUS]
        return Finding(
            rule_id=rule.id,
            cwe=rule.cwe,
            severity="critical",
            confidence=rule.confidence,
            path=rel,
            line=dep.line,
            column=1,
            end_line=dep.line,
            message=f"{package} ({dep.ecosystem}) is reported as a malicious package: {shown}. {malicious[0].summary}".strip(),
            why=rule.why,
            fix=f"Remove {dep.name} from the project and its lockfile, then rotate every credential, token and key on machines where it was installed.",
            snippet=snippet,
            fingerprint=fingerprint(rule.id, rel, snippet),
        )
    rule = RULES[VULNERABLE]
    severity = max((adv.severity for adv in advisories), key=lambda s: SEVERITY_RANK[s])
    cwe = next((cwe for adv in advisories for cwe in adv.cwes), DEFAULT_CWE)
    fixes = [next_fixed(dep.ecosystem, dep.version, group_fixes(group, advisories)) for group in groups]
    known = [fix for fix in fixes if fix is not None]
    target = highest(dep.ecosystem, known)
    known = sorted(set(known), key=lambda v: version_key(dep.ecosystem, v))
    if target is None:
        fix = f"No fixed version of {dep.name} is published for {groups[0][0]}: remove or replace it, or record why it is safe in [tool.kestrix] ignore-advisories."
        fixed_text = "no fixed version"
    elif None in fixes:
        fix = f"Upgrade {dep.name} to {target} or later; some vulnerabilities have no fix yet, so also review them."
        fixed_text = f"fixed in {', '.join(known)}"
    else:
        fix = f"Upgrade {dep.name} to {target} or later and update the lockfile."
        fixed_text = f"fixed in {', '.join(known)}"
    summary = advisories[0].summary.rstrip(".")
    return Finding(
        rule_id=rule.id,
        cwe=cwe,
        severity=severity,
        confidence=rule.confidence,
        path=rel,
        line=dep.line,
        column=1,
        end_line=dep.line,
        message=f"{package} ({dep.ecosystem}) has {len(groups)} known vulnerability(ies): {shown}. {summary}; {fixed_text}.",
        why=rule.why,
        fix=fix,
        snippet=snippet,
        fingerprint=fingerprint(rule.id, rel, snippet),
    )


def stale_note(rel: str, now: float | None = None) -> Note | None:
    """The scan's one ``dep.db_stale`` note: no index, or an index more than 7 days old."""
    from . import osvdb

    state = osvdb.status()
    age = state.age_s(now)
    if age is None:
        message = "No vulnerability index, so dependencies were not checked. Run `kestrix-scan db update` (downloads the OSV data)."
    elif age > osvdb.STALE_AFTER_S:
        message = f"The vulnerability index is {int(age // 86400)} days old. Run `kestrix-scan db update` (downloads the OSV data) to refresh it."
    else:
        return None
    return Note(id=STALE, path=rel, line=1, message=message)
