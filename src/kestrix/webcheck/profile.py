"""Site profile: what kind of site the scanned page is, from evidence on the page itself.

A missing CSP or framing protection matters most where there is something to steal or click:
logins, forms, sessions and API calls. The profile reads the one HTML response the check already
fetched, with a bounded, non-executing parser (``html.parser``), and classifies the site:

- ``static``: pages only, with no forms, cookies or sign of API calls;
- ``static_api``: a backend but no accounts. That means data-entry forms (a contact form, say) or
  scripts that call APIs (``fetch``, XHR, ``/api/``, GraphQL), with no password field and no cookies;
- ``dynamic``: accounts or sessions, meaning a password field or cookies.

The page is untrusted data: nothing is executed, only tags, attributes and short inline-script
markers are counted, and every input is size-bounded. One page cannot see everything. A login
behind a link is invisible. So the owner may declare a type, but a declaration can only *raise*
the profile: it never lowers it below what the page shows.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel

SiteKind = Literal["static", "static_api", "dynamic"]
ORDER: dict[SiteKind, int] = {"static": 0, "static_api": 1, "dynamic": 2}
MAX_PARSE_BYTES = 1024 * 1024
MAX_INLINE_SCRIPT_CHARS = 200_000
_API = re.compile(r"\bfetch\s*\(|XMLHttpRequest|axios\.|/api/|graphql|\bwss?://", re.I)


class Evidence(BaseModel):
    html: bool = False
    forms: int = 0
    post_forms: int = 0
    password_fields: int = 0
    input_fields: int = 0
    cookies: int = 0
    scripts_inline: int = 0
    scripts_external: int = 0
    third_party_script_hosts: list[str] = []
    iframes: int = 0
    api_markers: int = 0


class SiteProfile(BaseModel):
    kind: SiteKind
    detected: SiteKind
    declared: SiteKind | None = None
    reasons: list[str]
    evidence: Evidence


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
            self.ev.input_fields += kind not in {"hidden", "submit", "button", "image", "reset"}
        elif tag in {"textarea", "select"}:
            self.ev.input_fields += 1
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


def _is_html(headers: dict[str, list[str]]) -> bool:
    ctype = (headers.get("content-type") or [""])[0].lower()
    return "html" in ctype or not ctype


def profile_site(
    headers: dict[str, list[str]], body: bytes, final_url: str, declared: SiteKind | None = None
) -> SiteProfile:
    host = urlsplit(final_url).hostname or ""
    ev = Evidence()
    if _is_html(headers) and body:
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
        reasons.append(f"{ev.password_fields} password field(s)")
    if ev.cookies:
        reasons.append(f"{ev.cookies} cookie(s) set")
    detected: SiteKind = "dynamic" if reasons else "static"
    if detected == "static":
        if ev.forms:
            reasons.append(f"{ev.forms} form(s) with {ev.input_fields} input field(s), no login or cookies")
        if ev.api_markers:
            reasons.append("scripts call APIs")
        elif "json" in ctype:
            reasons.append("the URL returns JSON")
        detected = "static_api" if reasons else "static"
    if not reasons:
        reasons.append("no forms, cookies or API calls on this page")
    if ev.third_party_script_hosts:
        reasons.append(f"scripts from {len(ev.third_party_script_hosts)} third-party host(s)")

    kind = detected
    if declared is not None:
        if ORDER[declared] >= ORDER[detected]:
            kind = declared
            if declared != detected:
                reasons.append(f"owner declared {declared}")
        else:
            reasons.append(f"owner declared {declared}, but the page shows {detected}; using {detected}")
    return SiteProfile(kind=kind, detected=detected, declared=declared, reasons=reasons, evidence=ev)
