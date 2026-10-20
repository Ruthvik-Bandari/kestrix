# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Report models for the code scanner.

A finding carries the location, the rule's explanation and a short snippet of the line. For
secret findings the snippet is redacted to the secret's kind and its first four characters;
the secret value itself is never stored in a finding, a report or any output format.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from .about import ATTRIBUTION

MAX_SNIPPET_CHARS = 200

Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
SkipReason = Literal["binary", "too_large", "unreadable", "syntax_error", "too_complex", "symlink_outside_root"]

SEVERITY_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

NOTICE = (
    "Rule-based pattern analysis on this machine. Rules miss things and can be wrong; no detection rate is "
    "claimed. No findings means no rule fired, not that the code is secure."
)

_WHITESPACE = re.compile(r"\s+")


def fingerprint(rule_id: str, path: str, snippet: str) -> str:
    """Stable SHA-256 over the rule, the normalized path and the snippet without whitespace.

    The line number is deliberately left out, so a finding keeps its fingerprint when code above it moves.
    """
    normalized_path = path.replace("\\", "/").lstrip("./")
    data = "\0".join((rule_id, normalized_path, _WHITESPACE.sub("", snippet)))
    return hashlib.sha256(data.encode()).hexdigest()


def clip_snippet(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_SNIPPET_CHARS else text[: MAX_SNIPPET_CHARS - 1] + "…"


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    rule_id: str  # stable rule id, for example 'py.subprocess.shell_true'
    cwe: str  # CWE identifier, for example 'CWE-78'
    severity: Severity
    confidence: Confidence  # how likely the pattern is a real problem in context
    path: str  # file path relative to the scan root, with '/' separators
    line: int  # 1-based start line
    column: int  # 1-based start column
    end_line: int  # 1-based end line
    message: str  # one-line description of what was found
    why: str  # why it matters
    fix: str  # how to fix it
    snippet: str  # the source line, cut to 200 characters; secrets redacted to their kind and first four characters
    fingerprint: str  # SHA-256 of rule id, path and whitespace-free snippet; used by baselines

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity,
            "confidence": self.confidence,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "message": self.message,
            "why": self.why,
            "fix": self.fix,
            "snippet": self.snippet,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SkippedFile:
    path: str  # file path relative to the scan root
    reason: SkipReason

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True, slots=True, kw_only=True)
class Note:
    id: str  # note code, for example 'kestrix.suppression.missing_reason'
    path: str
    line: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "path": self.path, "line": self.line, "message": self.message}


@dataclass(frozen=True, slots=True, kw_only=True)
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"critical": self.critical, "high": self.high, "medium": self.medium, "low": self.low}


_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def ordered(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first, then by path, line and column."""
    return sorted(findings, key=lambda f: (_ORDER[f.severity], f.path, f.line, f.column, f.rule_id))


def count(findings: Iterable[Finding]) -> SeverityCounts:
    tally = Counter(finding.severity for finding in findings)
    return SeverityCounts(critical=tally["critical"], high=tally["high"], medium=tally["medium"], low=tally["low"])


FailOnLevel = Literal["low", "medium", "high", "critical", "none"]


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanReport:
    """One scan's result. ``to_dict`` and ``to_json`` give the JSON report (``schema_version`` 1).

    The keys and their order are a stable interface: adding a key is a minor change, renaming or
    removing one is a breaking change recorded in the CHANGELOG.
    """

    schema_version: Literal[1] = 1
    generated_by: str = ATTRIBUTION  # tool and author that produced this report
    notice: str = NOTICE
    root: str  # absolute scan root; finding paths are relative to it
    diff_base: str | None = None  # git ref the findings were limited to, if any
    fail_on: FailOnLevel  # lowest severity that makes the scan fail (exit code 1); 'none' never fails
    files_scanned: int
    files_skipped: list[SkippedFile]  # files that were not scanned, with the reason
    truncated: bool  # true when the file limit was reached and the remaining files were not scanned
    findings: list[Finding]  # most severe first, then by path and line
    counts: SeverityCounts
    suppressed: int  # findings silenced by an inline suppression with a reason
    baseline_filtered: int  # findings left out because their fingerprint is in the baseline
    notes: list[Note]  # scanner notes that are not findings, such as suppressions without a reason
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_by": self.generated_by,
            "notice": self.notice,
            "root": self.root,
            "diff_base": self.diff_base,
            "fail_on": self.fail_on,
            "files_scanned": self.files_scanned,
            "files_skipped": [item.to_dict() for item in self.files_skipped],
            "truncated": self.truncated,
            "findings": [finding.to_dict() for finding in self.findings],
            "counts": self.counts.to_dict(),
            "suppressed": self.suppressed,
            "baseline_filtered": self.baseline_filtered,
            "notes": [note.to_dict() for note in self.notes],
            "duration_ms": self.duration_ms,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """The JSON report: UTF-8 text, keys in the documented order."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
