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

from .lockfiles import Dependency, Parsed, ecosystem_for_file, parser_for
from .models import SEVERITY_RANK, Finding, Note, fingerprint
from .registry import RULES
from .versions import affects, fixed_versions, highest, next_fixed, version_key

if TYPE_CHECKING:  # osvdb (sqlite3, zipfile) is imported only when a dependency file is checked
    from . import osvdb

VULNERABLE = "dep.vulnerable"
MALICIOUS = "dep.malicious"
STALE = "dep.db_stale"
NOT_CHECKED = "dep.not_checked"
UNSUPPORTED = "dep.unsupported"
ECOSYSTEM_MISSING = "dep.ecosystem_missing"
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
    covered: frozenset[str] = frozenset()

    def _open(self) -> sqlite3.Connection | None:
        from . import osvdb

        current = osvdb.db_path()
        if self.db is None or current != self.path:
            if self.db is not None:
                self.db.close()
            self.path, self.db, self.cache = current, osvdb.connect(current), {}
            self.covered = frozenset(source.ecosystem for source in osvdb.sources(self.db)) if self.db else frozenset()
        return self.db

    def ecosystems(self) -> frozenset[str] | None:
        """The ecosystems the index holds data for, or None when there is no index."""
        return self.covered if self._open() is not None else None

    def advisories(self, ecosystem: str, name: str) -> list[osvdb.Advisory]:
        from . import osvdb

        if self._open() is None or self.db is None:
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
    covered = _INDEX.ecosystems()
    missing = sorted({dep.ecosystem for dep in parsed.dependencies} - covered) if covered is not None else []
    for ecosystem in missing:
        notes.append(
            Note(
                id=ECOSYSTEM_MISSING,
                path=rel,
                line=1,
                message=f"{ecosystem} dependencies were not checked: the local index has no {ecosystem} data. Run `kestrix-scan db update --ecosystem {ecosystem}` (downloads the OSV data).",
            )
        )
    findings: list[Finding] = []
    suppressed = 0
    for dep in parsed.dependencies:
        if dep.ecosystem in missing:
            continue
        ids_here = suppressions.get(dep.line, frozenset()) | suppressions.get(dep.line - 1, frozenset())
        verdicts = [
            (adv, affects(dep.ecosystem, dep.version, adv.ranges, adv.versions))
            for adv in _INDEX.advisories(dep.ecosystem, dep.name)
        ]
        certain = [adv for adv, verdict in verdicts if verdict is True]
        unsure = [adv for adv, verdict in verdicts if verdict is None]
        ignored = ids_here | set(ignore_advisories)
        matched = certain or unsure
        kept = [adv for adv in matched if not ({adv.id, *adv.aliases} & ignored)]
        if not kept:
            if matched:
                suppressed += 1
            continue
        finding = _finding(dep, kept, rel, possible=not certain)
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
                message=f"{len(parsed.not_checked)} requirement(s) without an exact version pin were not checked: {shown}{more}. Pin them, or check the lockfile instead.",
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


def _finding(dep: Dependency, advisories: list[osvdb.Advisory], rel: str, *, possible: bool = False) -> Finding:
    groups = vulnerabilities(advisories)
    shown = describe_ids(groups)
    package = f"{dep.name}@{dep.version}"
    snippet = f"{package} {' '.join(sorted(adv.id for adv in advisories))}"
    if possible:
        return _possible(dep, advisories, rel, groups)
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


def _possible(dep: Dependency, advisories: list[osvdb.Advisory], rel: str, groups: list[list[str]]) -> Finding:
    rule = RULES[VULNERABLE]
    severity = max((adv.severity for adv in advisories), key=lambda s: SEVERITY_RANK[s])
    cwe = next((cwe for adv in advisories for cwe in adv.cwes), DEFAULT_CWE)
    package = f"{dep.name}@{dep.version}"
    shown = describe_ids(groups)
    snippet = f"{package} {' '.join(sorted(adv.id for adv in advisories))}"
    fixes = sorted(
        {fix for group in groups for fix in group_fixes(group, advisories)}, key=lambda v: version_key(dep.ecosystem, v)
    )
    fixed = f"; fixed in {', '.join(fixes)}" if fixes else ""
    return Finding(
        rule_id=rule.id,
        cwe=cwe,
        severity=severity,
        confidence="low",
        path=rel,
        line=dep.line,
        column=1,
        end_line=dep.line,
        message=f"{package} ({dep.ecosystem}) is possibly affected by {len(groups)} known vulnerability(ies): {shown}. "
        f"{advisories[0].summary.rstrip('.')}{fixed}. The version or the advisory's ranges could not be compared exactly.",
        why=rule.why,
        fix=f"Check {dep.name} {dep.version} against {groups[0][0]}; if it is affected, upgrade to a fixed version and update the lockfile, "
        "otherwise record why in [tool.kestrix] ignore-advisories.",
        snippet=snippet,
        fingerprint=fingerprint(rule.id, rel, snippet),
    )


def _freshness(max_age: int | None, now: float | None) -> tuple[float | None, int]:
    """(index age in seconds or None without an index, the allowed age in days)."""
    from . import osvdb

    return osvdb.status().age_s(now), osvdb.max_age_days(max_age)


def freshness_message(max_age: int | None = None, now: float | None = None) -> str | None:
    """Why dependency results may be out of date, or None when the index is present and younger than the limit.

    ``max_age`` is ``[tool.kestrix] db-max-age-days``; ``KESTRIX_SCAN_MAX_AGE_DAYS`` overrides it; the default is 7.
    """
    age, limit = _freshness(max_age, now)
    if age is None:
        return "No vulnerability index, so dependencies were not checked. Run `kestrix-scan db update` (downloads the OSV data)."
    if age > limit * 86400:
        return (
            f"The vulnerability index is {int(age // 86400)} days old (limit {limit}), so advisories published since "
            "then are missing. Run `kestrix-scan db update` (downloads the OSV data) to refresh it."
        )
    return None


def freshness_line(max_age: int | None = None, now: float | None = None) -> str | None:
    """One short sentence for Claude Code hooks, or None when the index is present and fresh enough."""
    age, limit = _freshness(max_age, now)
    if age is None:
        return "Kestrix has no vulnerability index, so dependencies are not checked; the user can run `kestrix-scan db update`."
    if age > limit * 86400:
        return f"Kestrix's vulnerability index is {int(age // 86400)} days old, so new advisories may be missing; the user can run `kestrix-scan db update`."
    return None


def stale_note(rel: str, max_age: int | None = None, now: float | None = None) -> Note | None:
    """The scan's one ``dep.db_stale`` note: no index, or an index older than the allowed age."""
    message = freshness_message(max_age, now)
    return Note(id=STALE, path=rel, line=1, message=message) if message is not None else None


def needed_ecosystems(paths: list[Path], configured: tuple[str, ...] = ()) -> list[str]:
    """The ecosystems `db update` should download: those of the dependency files under ``paths``, those the
    index already holds and those in ``[tool.kestrix] db-ecosystems``; the default pair when there is none."""
    from . import osvdb
    from .analyze import resolve_targets
    from .walk import collect

    root, targets = resolve_targets(paths, None)
    found = {eco for c in collect(targets, root).candidates if (eco := ecosystem_for_file(c.rel)) is not None}
    chosen = found | set(configured) | osvdb.status().ecosystems
    ordered = [eco for eco in osvdb.ECOSYSTEMS if eco in chosen]
    return ordered or list(osvdb.DEFAULT_ECOSYSTEMS)
