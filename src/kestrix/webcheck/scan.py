# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Orchestrates fetch, TLS probe, evaluation and grading into one report."""

from __future__ import annotations

import time
from urllib.parse import urlsplit

import httpx

from .checks import apply_profile, check_https, check_tls, evaluate
from .fetch import USER_AGENT, TlsProbe, fetch, tls_probe
from .grade import grade
from .models import Report, Timings, TlsInfo
from .profile import SiteKind, SiteProfile, profile_site


def scan(
    url: str,
    *,
    allow_private: bool = False,
    transport: httpx.BaseTransport | None = None,
    probe: TlsProbe = tls_probe,
    site_type: SiteKind | None = None,
    agent: str = USER_AGENT,
) -> Report:
    """``site_type``: the owner's declared site kind; it can raise but never lower the detected one."""
    t0 = time.monotonic()
    result = fetch(url, allow_private=allow_private, transport=transport, agent=agent)
    http_ms = round((time.monotonic() - t0) * 1000)
    scheme = urlsplit(result.final_url).scheme
    t1 = time.monotonic()
    if scheme == "https":
        tls = probe(result.final_host, result.final_ip, result.final_port, 10.0)
    else:
        tls = TlsInfo(host=result.final_host, status="not_https")
    tls_ms = round((time.monotonic() - t1) * 1000)
    headers_checked = result.status_code is not None
    profile: SiteProfile | None = None
    if headers_checked:
        profile = profile_site(result.headers, result.body, result.final_url, site_type)
        findings = apply_profile(evaluate(result.headers, scheme, tls), profile)
    else:
        findings = check_https(scheme) + check_tls(tls)
    letter, score = grade(findings, scheme, tls)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return Report(
        requested_url=url,
        final_url=result.final_url,
        status_code=result.status_code,
        headers_checked=headers_checked,
        redirect_chain=result.chain,
        tls=tls,
        grade=letter,
        score=score,
        findings=sorted(findings, key=lambda f: order[f.severity]),
        timings=Timings(total_ms=round((time.monotonic() - t0) * 1000), http_ms=http_ms, tls_ms=tls_ms),
        profile=profile,
    )
