# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Site profile: what kind of site was scanned, from evidence on the pages the check fetched.

A missing CSP or framing protection matters most where there is something to steal or click:
logins, forms, sessions and API calls. The profile reads each HTML response the check already
fetched, with a bounded, non-executing parser (``html.parser``), and classifies the site:

- ``static``: pages only, with no forms, cookies or sign of API calls;
- ``static_api``: a backend but no accounts. That means data-entry forms (a contact form, say) or
  scripts that call APIs (``fetch``, XHR, ``/api/``, GraphQL), with no password field and no cookies;
- ``dynamic``: accounts or sessions, meaning a login field or cookies. A login field is a password
  field, a field the page marks for a password, one-time code or passkey (``autocomplete``), a field
  named like a one-time code (``otp``, ``totp``, ``mfa``, ``passcode``), or any form that posts from
  a login-like address such as ``/admin/login``: passwordless and two-factor sign-ins have no
  password field.

The page is untrusted data: nothing is executed, only tags, attributes and short inline-script
markers are counted, and every input is size-bounded. Each page is assessed on its own; the site's
kind is the most sensitive page's kind (dynamic over static_api over static) and its reasons name that
page. One page cannot see everything, so the owner may declare a type, but a declaration can only
*raise* the profile: it never lowers it below what the pages show.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel

SiteKind = Literal["static", "static_api", "dynamic"]
ORDER: dict[SiteKind, int] = {"static": 0, "static_api": 1, "dynamic": 2}
MAX_PARSE_BYTES = 1024 * 1024
MAX_INLINE_SCRIPT_CHARS = 200_000
_LOGIN_PATH = re.compile(r"/(log-?in|sign-?in|account|admin|wp-login)\b", re.I)
_LOGIN_AUTOCOMPLETE = frozenset({"current-password", "new-password", "one-time-code", "webauthn"})
_CODE_FIELD_NAME = re.compile(r"^(?:otp|totp|mfa|2fa|passcode|one[-_]?time[-_]?(?:code|password))$", re.I)
_API = re.compile(r"\bfetch\s*\(|XMLHttpRequest|axios\.|/api/|graphql|\bwss?://", re.I)


class Evidence(BaseModel):
    html: bool = False
    forms: int = 0
    post_forms: int = 0
    password_fields: int = 0
    login_fields: int = 0  # other sign-in fields: one-time codes, passkeys, password autocomplete hints
    input_fields: int = 0
    cookies: int = 0
    scripts_inline: int = 0
    scripts_external: int = 0
    third_party_script_hosts: list[str] = []
    iframes: int = 0
    api_markers: int = 0
    login_links: list[str] = []  # same-site links whose path looks like a login or account page (at most 5)


class SiteProfile(BaseModel):
    kind: SiteKind
    detected: SiteKind
    declared: SiteKind | None = None
    reasons: list[str]
    evidence: Evidence
    decided_by: str | None = None  # the page that set the kind, when it is not the only page checked


class _Collector(HTMLParser):
    def __init__(self, site: str) -> None:
        super().__init__(convert_charrefs=True)
        self.site = site
        self.ev = Evidence(html=True)
        self._in_script = False
        self._script_chars = 0
        self._hosts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self.ev.forms += 1
            self.ev.post_forms += a.get("method", "get").lower() == "post"
        elif tag == "input":
            kind = a.get("type", "text").lower()
            self.ev.password_fields += kind == "password"
            hints = set(a.get("autocomplete", "").lower().split())
            self.ev.login_fields += kind != "password" and (
                bool(hints & _LOGIN_AUTOCOMPLETE) or bool(_CODE_FIELD_NAME.match(a.get("name", "")))
            )
            self.ev.input_fields += kind not in {"hidden", "submit", "button", "image", "reset"}
        elif tag in {"textarea", "select"}:
            self.ev.input_fields += 1
        elif tag == "a":
            href = a.get("href", "")
            host = urlsplit(href).hostname
            if (
                len(self.ev.login_links) < 5
                and (not host or _site(host) == self.site)
                and _LOGIN_PATH.search(urlsplit(href).path)
            ):
                self.ev.login_links.append(href[:100])
        elif tag == "iframe":
            self.ev.iframes += 1
        elif tag == "script":
            src = a.get("src", "")
            if src:
                self.ev.scripts_external += 1
                host = urlsplit(src).hostname
                if host and _site(host) != self.site:
                    self._hosts.add(host.lower())
            else:
                self.ev.scripts_inline += 1
                self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and self._script_chars < MAX_INLINE_SCRIPT_CHARS:
            chunk = data[: MAX_INLINE_SCRIPT_CHARS - self._script_chars]
            self._script_chars += len(chunk)
            self.ev.api_markers += len(_API.findall(chunk))

    def result(self) -> Evidence:
        self.ev.third_party_script_hosts = sorted(self._hosts)[:20]
        return self.ev


def _site(host: str) -> str:
    """Registrable-ish site: the last two labels (good enough to tell first- from third-party)."""
    labels = host.lower().rstrip(".").split(".")
    return ".".join(labels[-2:])


def is_html(headers: dict[str, list[str]]) -> bool:
    ctype = (headers.get("content-type") or [""])[0].lower()
    return "html" in ctype or not ctype


KIND_LABEL: dict[SiteKind, str] = {
    "static": "pages only",
    "static_api": "a site with a form",
    "dynamic": "a site with logins",
}
_RAISED = {
    "static_api": "You said this site has a form or an API, so it was checked as one.",
    "dynamic": "You said this site has logins, so it was checked as a site with logins.",
}
_FORM_ACTION = re.compile(r"(?:^|;)\s*form-action\s+([^;]*)", re.I)


@dataclass
class PageProfile:
    """One page's evidence: its own kind and the plain-language reasons, each starting with ``subject``."""

    detected: SiteKind
    reasons: list[str]
    evidence: Evidence


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many.format(n=n)


def assess_page(headers: dict[str, list[str]], body: bytes, final_url: str, subject: str) -> PageProfile:
    host = urlsplit(final_url).hostname or ""
    ev = Evidence()
    if is_html(headers) and body:
        collector = _Collector(_site(host))
        try:
            collector.feed(body[:MAX_PARSE_BYTES].decode("utf-8", errors="replace"))
            collector.close()
        except (ValueError, AssertionError):
            pass  # malformed markup only reduces the evidence; it never fails the scan
        ev = collector.result()
    ev.cookies = len(headers.get("set-cookie", []))
    ctype = (headers.get("content-type") or [""])[0].lower()

    reasons: list[str] = []
    if ev.password_fields:
        reasons.append(f"{subject} has " + _plural(ev.password_fields, "a password field", "{n} password fields"))
    elif ev.login_fields:
        reasons.append(
            f"{subject} has "
            + _plural(ev.login_fields, "a sign-in field", "{n} sign-in fields")
            + " (such as a one-time code)"
        )
    elif ev.post_forms and _LOGIN_PATH.search(urlsplit(final_url).path):
        reasons.append(f"{subject} has a form that posts to the server from a login address")
    if ev.cookies:
        reasons.append(f"{subject} " + _plural(ev.cookies, "sets a cookie", "sets {n} cookies"))
    detected: SiteKind = "dynamic" if reasons else "static"
    if detected == "static":
        if ev.forms:
            reasons.append(f"{subject} has a form with {ev.input_fields} input field(s) but no login or cookie")
        if ev.api_markers:
            reasons.append(f"{subject} has scripts that call an API")
        elif "json" in ctype:
            reasons.append(f"{subject} returns JSON data")
        detected = "static_api" if reasons else "static"
    if not reasons:
        reasons.append(f"{subject} has no forms, cookies or API calls")
    return PageProfile(detected, reasons, ev)


def _third_party(ev: Evidence, subject: str) -> list[str]:
    if not ev.third_party_script_hosts:
        return []
    return [f"{subject} loads scripts from {len(ev.third_party_script_hosts)} other host(s)"]


def _lower_first(reason: str) -> str:
    return reason[0].lower() + reason[1:] if reason.startswith(("This ", "The ", "None ")) else reason


def _declare(detected: SiteKind, declared: SiteKind | None, reasons: list[str]) -> tuple[SiteKind, list[str]]:
    """The owner's declaration can only raise the kind."""
    if declared is None or declared == detected:
        return detected, reasons
    if ORDER[declared] > ORDER[detected]:
        return declared, [*reasons, _RAISED[declared]]
    note = (
        f"You chose '{KIND_LABEL[declared]}', but {_lower_first(reasons[0])}, "
        f"so it was checked as {KIND_LABEL[detected]}."
    )
    return detected, [*reasons, note]


def _other_pages_hint(headers: dict[str, list[str]], ev: Evidence) -> list[str]:
    """Single-page scans cannot see other pages, but the page may point at them."""
    hints: list[str] = []
    if ev.login_links:
        hints.append(f"This page links to {ev.login_links[0]}, so the site likely has logins on other pages")
    for value in headers.get("content-security-policy", []):
        match = _FORM_ACTION.search(value)
        if match and any(src not in {"'self'", "'none'"} for src in match.group(1).split()):
            hints.append(
                "This page's policy lets forms send data to another host, so the site likely has forms on other pages"
            )
            break
    return hints


def profile_site(
    headers: dict[str, list[str]], body: bytes, final_url: str, declared: SiteKind | None = None
) -> SiteProfile:
    """The profile of a single-page scan; every reason describes this page only."""
    page = assess_page(headers, body, final_url, "This page")
    reasons = [*page.reasons, *_third_party(page.evidence, "This page")]
    kind, reasons = _declare(page.detected, declared, reasons)
    reasons += _other_pages_hint(headers, page.evidence) if kind != "dynamic" else []
    return SiteProfile(kind=kind, detected=page.detected, declared=declared, reasons=reasons, evidence=page.evidence)


def _sum_evidence(items: list[Evidence]) -> Evidence:
    total = Evidence(html=any(e.html for e in items))
    for name in (
        "forms",
        "post_forms",
        "password_fields",
        "login_fields",
        "input_fields",
        "cookies",
        "scripts_inline",
        "scripts_external",
        "iframes",
        "api_markers",
    ):
        setattr(total, name, sum(getattr(e, name) for e in items))
    total.third_party_script_hosts = sorted({h for e in items for h in e.third_party_script_hosts})[:20]
    total.login_links = [link for e in items for link in e.login_links][:5]
    return total


def combine_pages(pages: list[tuple[str, PageProfile]], declared: SiteKind | None = None) -> SiteProfile:
    """The site's profile from its pages (``(path, profile)``, the start page first): the most
    sensitive page sets the kind and its reasons are the site's reasons."""
    top_path, top = max(pages, key=lambda item: ORDER[item[1].detected])  # max keeps the first on a tie
    evidence = _sum_evidence([p.evidence for _, p in pages])
    if top.detected == "static":
        reasons = [f"None of the {len(pages)} pages checked has a form, a cookie or an API call"]
        decided_by = None
    else:
        reasons = list(top.reasons)
        decided_by = top_path
    if evidence.third_party_script_hosts:
        reasons.append(f"Pages load scripts from {len(evidence.third_party_script_hosts)} other host(s)")
    kind, reasons = _declare(top.detected, declared, reasons)
    return SiteProfile(
        kind=kind, detected=top.detected, declared=declared, reasons=reasons, evidence=evidence, decided_by=decided_by
    )
