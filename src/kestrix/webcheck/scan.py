# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Orchestrates fetch, crawl, TLS probe, evaluation and grading into one report."""

from __future__ import annotations

import time
from functools import partial
from urllib.parse import urlsplit

import httpx

from .checks import apply_profile, check_https, check_tls, evaluate_page, merge_findings
from .crawl import crawl, path_of
from .fetch import USER_AGENT, FetchResult, RequestBudget, TlsProbe, fetch, origin_of, tls_probe
from .grade import grade
from .models import (
    EXTRA_REQUEST_CAP,
    PAGE_CAP,
    Finding,
    Limit,
    PageResult,
    Report,
    Scope,
    Timings,
    TlsInfo,
    notice_for,
)
from .profile import PageProfile, SiteKind, SiteProfile, assess_page, combine_pages, profile_site

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _subject(path: str, start: bool) -> str:
    if not start:
        return path
    return "The home page" if path == "/" else "The start page"


def scan(
    url: str,
    *,
    allow_private: bool = False,
    transport: httpx.BaseTransport | None = None,
    probe: TlsProbe = tls_probe,
    site_type: SiteKind | None = None,
    agent: str = USER_AGENT,
    allowed_ports: frozenset[int] | None = None,
    generic_errors: bool = False,
    scope: Scope = "site",
) -> Report:
    """``scope``: ``"site"`` checks the start page, the pages it links to, the sitemap's pages and six common
    login addresses (see ``crawl.py``); ``"page"`` checks only the start page.
    ``site_type``: the owner's declared site kind; it can raise but never lower the detected one.
    ``allowed_ports`` and ``generic_errors`` are passed to :func:`fetch` (the hosted service sets them)."""
    t0 = time.monotonic()
    budget = RequestBudget(pages=PAGE_CAP, extra=EXTRA_REQUEST_CAP)
    budget.take_page()
    get = partial(
        fetch,
        allow_private=allow_private,
        transport=transport,
        agent=agent,
        allowed_ports=allowed_ports,
        generic_errors=generic_errors,
        budget=budget,
    )
    result = get(url)
    http_ms = round((time.monotonic() - t0) * 1000)
    scheme = urlsplit(result.final_url).scheme
    t1 = time.monotonic()
    if scheme == "https":
        tls = probe(result.final_host, result.final_ip, result.final_port, 10.0)
    else:
        tls = TlsInfo(host=result.final_host, status="not_https")
    tls_ms = round((time.monotonic() - t1) * 1000)
    profile: SiteProfile | None = None
    pages: list[PageResult] = []
    limits: list[Limit] = []
    links_skipped = sitemap_entries = 0
    findings: list[Finding]
    if result.status_code is None:
        findings = check_https(scheme) + check_tls(tls)
        if scope == "site":
            pages = [PageResult(path=path_of(result.final_url), found_via="start", outcome="failed")]
    elif scope == "page":
        profile = profile_site(result.headers, result.body, result.final_url, site_type)
        findings = check_https(scheme) + check_tls(tls) + apply_profile(evaluate_page(result.headers, scheme), profile)
    else:
        t2 = time.monotonic()
        site = origin_of(result.final_url)
        found = crawl(
            result,
            lambda page_url, timeout: get(page_url, timeout=timeout, stay_on=site),
            budget,
            generic_errors=generic_errors,
        )
        http_ms += round((time.monotonic() - t2) * 1000)
        start_path = path_of(result.final_url)
        checked: list[tuple[str, bool, FetchResult]] = [(start_path, True, result)]
        checked += [(v.path, False, v.result) for v in found.visits if v.outcome == "checked" and v.result]
        assessed: list[tuple[str, PageProfile]] = [
            (path, assess_page(r.headers, r.body, r.final_url, _subject(path, is_start)))
            for path, is_start, r in checked
        ]
        profile = combine_pages(assessed, site_type)
        per_page: list[tuple[str, list[Finding]]] = []
        for (path, _, r), (_, page_profile) in zip(checked, assessed, strict=True):
            weighed = profile.model_copy(update={"evidence": page_profile.evidence})  # third-party scripts are per page
            per_page.append((path, apply_profile(evaluate_page(r.headers, scheme), weighed)))
        findings = check_https(scheme) + check_tls(tls) + merge_findings(per_page)
        by_path = {path: (prof, [f.id for f in fs]) for (path, prof), (_, fs) in zip(assessed, per_page, strict=True)}
        pages = [
            PageResult(
                path=start_path,
                found_via="start",
                outcome="checked",
                status_code=result.status_code,
                kind=by_path[start_path][0].detected,
                finding_ids=by_path[start_path][1],
            )
        ]
        for v in found.visits:
            is_checked = v.outcome == "checked"
            pages.append(
                PageResult(
                    path=v.path,
                    found_via=v.source,
                    outcome=v.outcome,
                    status_code=v.result.status_code if v.result else None,
                    kind=by_path[v.path][0].detected if is_checked else None,
                    finding_ids=by_path[v.path][1] if is_checked else [],
                    detail=v.detail,
                )
            )
        limits, links_skipped, sitemap_entries = found.limits, found.links_skipped, found.sitemap_entries
    letter, score = grade(findings, scheme, tls)
    return Report(
        notice=notice_for(scope),
        requested_url=url,
        final_url=result.final_url,
        status_code=result.status_code,
        headers_checked=result.status_code is not None,
        redirect_chain=result.chain,
        tls=tls,
        grade=letter,
        score=score,
        findings=sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity]),
        timings=Timings(total_ms=round((time.monotonic() - t0) * 1000), http_ms=http_ms, tls_ms=tls_ms),
        profile=profile,
        scope=scope,
        pages=pages,
        requests_sent=budget.sent,
        limits_reached=limits,
        links_skipped=links_skipped,
        sitemap_entries=sitemap_entries,
    )
