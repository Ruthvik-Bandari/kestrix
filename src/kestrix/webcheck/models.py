"""Response models for the passive web exposure check."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .. import ATTRIBUTION
from .profile import SiteProfile

Severity = Literal["info", "low", "medium", "high"]
TlsStatus = Literal[
    "ok",
    "not_https",
    "expired",
    "not_yet_valid",
    "hostname_mismatch",
    "untrusted",
    "outdated_protocol",
    "handshake_failed",
]

NOTICE = "Only check websites you own or are authorized to assess. Kestrix sends one GET request (plus redirects) and one TLS handshake."


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    explanation: str
    recommendation: str
    evidence: str | None = None
    # Set when the site profile changed the severity: the checklist severity and why it changed.
    baseline_severity: Severity | None = None
    context: str | None = None


class Hop(BaseModel):
    url: str
    address: str
    status_code: int
    elapsed_ms: int


class TlsInfo(BaseModel):
    host: str
    status: TlsStatus
    detail: str | None = None
    protocol: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None


class Timings(BaseModel):
    total_ms: int
    http_ms: int
    tls_ms: int


class Report(BaseModel):
    generated_by: str = Field(default=ATTRIBUTION, description="Tool and author that produced this report.")
    notice: str = NOTICE
    requested_url: str
    final_url: str
    status_code: int | None
    headers_checked: bool
    redirect_chain: list[Hop]
    tls: TlsInfo
    grade: Literal["A", "B", "C", "D", "F"]
    score: int
    findings: list[Finding]
    timings: Timings
    profile: SiteProfile | None = None
