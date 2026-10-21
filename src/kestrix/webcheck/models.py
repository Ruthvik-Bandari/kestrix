# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Response models for the passive web exposure check."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .. import ATTRIBUTION
from .profile import SiteKind, SiteProfile

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

Scope = Literal["site", "page"]
PageSource = Literal["start", "link", "sitemap", "probe"]
PageOutcome = Literal["checked", "not_html", "http_error", "redirects_off_site", "blocked", "failed", "duplicate"]
Limit = Literal["page_cap", "deadline", "request_budget"]

# Whole-site limits (``crawl.py`` enforces them). Page GETs: the start page, linked and sitemap pages and the
# login probes. Extra GETs: the sitemap and every redirect hop.
PAGE_CAP = 50
EXTRA_REQUEST_CAP = 15
LOGIN_PATHS = ("/login", "/signin", "/admin", "/admin/login", "/account", "/wp-login.php")

_AUTH = "Only check websites you own or are authorized to assess."
NOTICE_PAGE = f"{_AUTH} Kestrix sends one GET request (plus redirects) and one TLS handshake."
NOTICE_SITE = (
    f"{_AUTH} Kestrix sends up to {PAGE_CAP} read-only GET requests to this site's pages, including "
    f"{len(LOGIN_PATHS)} common login addresses, plus its sitemap and any redirects (at most {EXTRA_REQUEST_CAP} more), "
    "and one TLS handshake. It never submits a form, logs in, or follows a link to another site."
)
NOTICE = NOTICE_PAGE


def notice_for(scope: Scope) -> str:
    return NOTICE_SITE if scope == "site" else NOTICE_PAGE


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
    # Whole-site scans: the paths this finding was seen on (at most 20, crawl order) and how many in all.
    pages: list[str] | None = None
    pages_total: int | None = None


class PageResult(BaseModel):
    path: str  # path and query on the site's host
    found_via: PageSource
    outcome: PageOutcome
    status_code: int | None = None
    kind: SiteKind | None = None  # what this page alone looks like; only for checked pages
    finding_ids: list[str] = []
    detail: str | None = None


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
    notice: str = NOTICE_PAGE
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
    # "page": only the requested page was checked. "site": the pages below were. Every field above
    # describes the start page (and the site's connection) in both cases.
    scope: Scope = "page"
    pages: list[PageResult] = []
    requests_sent: int = 1
    limits_reached: list[Limit] = []
    links_skipped: int = 0  # links not fetched: files, other sites, other ports, mailto and similar
    sitemap_entries: int = 0  # addresses read from /sitemap.xml
