"""Response models for saved-message analysis.

A report carries reason codes, hosts, header values needed to explain a finding, and hashes.
It never carries the message body, anchor text or attachment bytes.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, Field

MAX_EVIDENCE_CHARS = 300
MAX_SUBJECT_CHARS = 200

Severity = Literal["info", "low", "medium", "high"]
Analyzer = Literal["auth", "sender", "links", "attachments"]
Verdict = Literal["clean", "suspicious", "malicious", "insufficient_evidence"]

NOTICE = (
    "Offline heuristic analysis of one saved message. Nothing leaves this machine: links are not visited and "
    "attachments are not opened. The score is a heuristic, not a probability; 'clean' means none of the checks "
    "fired, not that the message is safe."
)


class Finding(BaseModel):
    id: str = Field(description="Stable reason code, for example 'mail.sender.reply_to_mismatch'.")
    analyzer: Analyzer = Field(description="The analyzer that raised it.")
    severity: Severity = Field(description="Attention it deserves: info (context only), low, medium or high.")
    title: str = Field(description="One-line summary of the finding.")
    explanation: str = Field(description="Plain-language explanation of what was seen and what it may mean.")
    evidence: str | None = Field(
        default=None,
        max_length=MAX_EVIDENCE_CHARS,
        description="Header value, host or file name behind the finding. Never message body text.",
    )


_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def by_severity(findings: Iterable[Finding]) -> list[Finding]:
    """Order findings most severe first, keeping the original order within a severity."""
    return sorted(findings, key=lambda finding: _RANK[finding.severity])


class Counts(BaseModel):
    parts: int = Field(description="MIME parts in the message, including containers.")
    links: int = Field(description="Links extracted from HTML anchors and plain-text URLs.")
    attachments: int = Field(description="Non-text parts and parts with a file name.")
    text_truncated: bool = Field(description="True when decoded text passed the scan budget and the rest was skipped.")
    links_truncated: bool = Field(description="True when the message had more links than the extraction limit.")


class MailReport(BaseModel):
    schema_version: Literal[1] = 1
    notice: str = NOTICE
    sha256: str = Field(description="SHA-256 of the raw message bytes.")
    subject: str | None = Field(max_length=MAX_SUBJECT_CHARS, description="Subject header, cut to 200 characters.")
    from_address: str | None = Field(description="Address in the From header, if one could be parsed.")
    verdict: Verdict = Field(
        description="clean, suspicious, malicious or insufficient_evidence; see docs/modules/mail.md."
    )
    heuristic_score: int = Field(
        ge=0,
        le=100,
        description="Heuristic: a capped sum of per-severity weights of the findings. It is not a probability.",
    )
    findings: list[Finding] = Field(description="Findings that explain the verdict, most severe first.")
    counts: Counts
