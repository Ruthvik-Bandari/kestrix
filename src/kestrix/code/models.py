# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Report models for the code scanner.

A finding carries the location, the rule's explanation and a short snippet of the line. For
secret findings the snippet is redacted to the secret's kind and its first four characters;
the secret value itself is never stored in a finding, a report or any output format.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, Field

from .. import ATTRIBUTION

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


class Finding(BaseModel):
    rule_id: str = Field(description="Stable rule id, for example 'py.subprocess.shell_true'.")
    cwe: str = Field(description="CWE identifier, for example 'CWE-78'.")
    severity: Severity
    confidence: Confidence = Field(description="How likely the pattern is a real problem in context.")
    path: str = Field(description="File path relative to the scan root, with '/' separators.")
    line: int = Field(ge=1, description="1-based start line.")
    column: int = Field(ge=1, description="1-based start column.")
    end_line: int = Field(ge=1, description="1-based end line.")
    message: str = Field(description="One-line description of what was found.")
    why: str = Field(description="Why it matters.")
    fix: str = Field(description="How to fix it.")
    snippet: str = Field(
        max_length=MAX_SNIPPET_CHARS,
        description="The source line, cut to 200 characters. Secrets are redacted to their kind and first four characters.",
    )
    fingerprint: str = Field(description="SHA-256 of rule id, path and whitespace-free snippet; used by baselines.")


class SkippedFile(BaseModel):
    path: str = Field(description="File path relative to the scan root.")
    reason: SkipReason


class Note(BaseModel):
    id: str = Field(description="Note code, for example 'kestrix.suppression.missing_reason'.")
    path: str
    line: int = Field(ge=1)
    message: str


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def ordered(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first, then by path, line and column."""
    return sorted(findings, key=lambda f: (_ORDER[f.severity], f.path, f.line, f.column, f.rule_id))


def count(findings: Iterable[Finding]) -> SeverityCounts:
    counts = SeverityCounts()
    for finding in findings:
        setattr(counts, finding.severity, getattr(counts, finding.severity) + 1)
    return counts


class ScanReport(BaseModel):
    schema_version: Literal[1] = 1
    generated_by: str = Field(default=ATTRIBUTION, description="Tool and author that produced this report.")
    notice: str = NOTICE
    root: str = Field(description="Absolute scan root; finding paths are relative to it.")
    diff_base: str | None = Field(default=None, description="Git ref the findings were limited to, if any.")
    fail_on: Literal["low", "medium", "high", "critical", "none"] = Field(
        description="Lowest severity that makes the scan fail (exit code 1); 'none' never fails."
    )
    files_scanned: int = Field(ge=0)
    files_skipped: list[SkippedFile] = Field(description="Files that were not scanned, with the reason.")
    truncated: bool = Field(
        description="True when the file limit was reached and the remaining files were not scanned."
    )
    findings: list[Finding] = Field(description="Findings, most severe first, then by path and line.")
    counts: SeverityCounts
    suppressed: int = Field(ge=0, description="Findings silenced by an inline suppression with a reason.")
    baseline_filtered: int = Field(ge=0, description="Findings left out because their fingerprint is in the baseline.")
    notes: list[Note] = Field(description="Scanner notes that are not findings, such as suppressions without a reason.")
    duration_ms: int = Field(ge=0)
