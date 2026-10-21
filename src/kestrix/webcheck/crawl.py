# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Whole-site discovery and fetching for the web check.

Starting from the start page's final URL, the site is exactly that URL's scheme, host and port. Pages
come from, in order: the start page's ``<a href>`` links, ``/sitemap.xml`` and six common login
addresses (``LOGIN_PATHS``). Every page is fetched with a plain GET through :func:`fetch`, so each request
and each redirect hop passes ``netguard.check_url`` and the hosted port rule. Nothing is ever submitted,
no cookie is sent, no link to another site is followed.

Limits (see ``models.py`` for the numbers): at most ``PAGE_CAP`` page GETs (the start page and the
login probes included; probes keep their slots when a page has many links); ``EXTRA_REQUEST_CAP`` more GETs
for the sitemap and redirect hops; ``CRAWL_DEADLINE_S`` for the crawl as a whole; ``PAUSE_S`` between
requests; one response is read up to 1 MiB. HTML and XML are parsed with bounded, non-executing code:
``html.parser`` for links, and ``str.find`` over ``<loc>`` tags for the sitemap, which has no entity
or DTD handling at all and does not follow nested sitemaps. A page that fails is recorded and the
scan goes on.
"""

from __future__ import annotations

import html
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urldefrag, urljoin, urlsplit

from ..core.errors import Reason, Rejected
from .fetch import GENERIC_UNREACHABLE, TIMEOUT_S, FetchResult, Origin, RequestBudget, origin_of
from .models import LOGIN_PATHS, PAGE_CAP, Limit, PageOutcome, PageSource
from .profile import is_html

CRAWL_DEADLINE_S = 60.0
PAUSE_S = 0.15
MAX_LINKS = 1000  # <a href> values read from the start page
MAX_SITEMAP_ENTRIES = 500  # <loc> values read from the sitemap
MAX_SITEMAP_SCAN = 5000  # <loc> tags examined, whether or not they hold an address
MAX_URL = 2048
SKIP_EXTENSIONS = frozenset(
    [
        ".7z",
        ".aac",
        ".avi",
        ".bmp",
        ".css",
        ".csv",
        ".doc",
        ".docx",
        ".eot",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".json",
        ".m4a",
        ".mp3",
        ".mp4",
        ".mov",
        ".ogg",
        ".otf",
        ".pdf",
        ".png",
        ".ppt",
        ".pptx",
        ".rar",
        ".svg",
        ".tar",
        ".tgz",
        ".ttf",
        ".txt",
        ".wav",
        ".webm",
        ".webp",
        ".woff",
        ".woff2",
        ".xls",
        ".xlsx",
        ".xml",
        ".zip",
    ]
)

Getter = Callable[[str, float], FetchResult]  # (url, timeout in seconds) -> response; stays on the site


@dataclass
class Visit:
    """One page request and what became of it. ``result`` is set when a response arrived."""

    path: str
    url: str
    source: PageSource
    outcome: PageOutcome
    result: FetchResult | None = None
    detail: str | None = None


@dataclass
class Crawl:
    visits: list[Visit] = field(default_factory=list)
    limits: list[Limit] = field(default_factory=list)
    links_skipped: int = 0
    sitemap_entries: int = 0


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return ((parts.path or "/") + (f"?{parts.query}" if parts.query else ""))[:300]


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a" and len(self.hrefs) < MAX_LINKS:
            for name, value in attrs:
                if name == "href" and value:
                    self.hrefs.append(value)


def extract_links(body: bytes) -> list[str]:
    parser = _Links()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, AssertionError):
        pass  # malformed markup only means fewer links
    return parser.hrefs


def extract_sitemap(body: bytes) -> list[str]:
    """The ``<loc>`` addresses of a sitemap, read with ``str.find`` only: no XML parser, so no entity or
    DTD is ever resolved, and the work is linear in the (already 1 MiB-capped) body."""
    text = body.decode("utf-8", errors="replace")
    lower = text.lower()
    out: list[str] = []
    pos = 0
    for _ in range(MAX_SITEMAP_SCAN):
        start = lower.find("<loc>", pos)
        if start < 0:
            break
        end = lower.find("</loc>", start)
        if end < 0:
            break
        value = text[start + 5 : end].strip()
        pos = end + 6
        if value.startswith("<![CDATA[") and value.endswith("]]>"):
            value = value[9:-3].strip()
        if value and len(value) <= MAX_URL:
            out.append(html.unescape(value))
            if len(out) >= MAX_SITEMAP_ENTRIES:
                break
    return out


def normalize(base: str, href: str, site: Origin, netloc: str) -> str | None:
    """The canonical same-site URL for ``href``, or ``None`` for a link that is skipped: another site,
    port or scheme, ``mailto:`` and the like, or a file that is not a web page."""
    try:
        url = urldefrag(urljoin(base, href.strip()))[0]
        parts = urlsplit(url)
        same_site = origin_of(url) == site
    except ValueError:
        return None
    if not same_site or parts.username or parts.password or len(url) > MAX_URL:
        return None
    if PurePosixPath(parts.path).suffix.lower() in SKIP_EXTENSIONS:
        return None
    return f"{parts.scheme}://{netloc}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")


def _select(candidates: list[tuple[str, PageSource]], probes: list[str]) -> tuple[list[tuple[str, PageSource]], bool]:
    """At most ``PAGE_CAP - 1`` pages after the start page, every login probe keeping its slot."""
    slots = PAGE_CAP - 1
    probe_set = set(probes)
    chosen: list[tuple[str, PageSource]] = []
    chosen_urls: set[str] = set()
    capped = False
    for url, source in candidates:
        missing = len(probe_set - chosen_urls - {url})
        if len(chosen) + 1 + missing > slots:
            capped = True
            break
        chosen.append((url, source))
        chosen_urls.add(url)
    chosen += [(p, "probe") for p in probes if p not in chosen_urls]
    return chosen, capped


class _Crawler:
    def __init__(self, start: FetchResult, get: Getter, budget: RequestBudget, generic_errors: bool) -> None:
        self.start, self.get, self.budget, self.generic_errors = start, get, budget, generic_errors
        self.out = Crawl()
        self.deadline = time.monotonic() + CRAWL_DEADLINE_S
        self.site = origin_of(start.final_url)
        self.netloc = urlsplit(start.final_url).netloc
        key = normalize(start.final_url, start.final_url, self.site, self.netloc)
        assert key is not None
        self.start_key = key
        self.seen = {key}
        self.candidates: dict[str, PageSource] = {}

    def add(self, base: str, hrefs: list[str], source: PageSource) -> None:
        for href in hrefs:
            if not href.strip() or href.strip().startswith("#"):
                continue  # empty, or a place on the same page
            url = normalize(base, href, self.site, self.netloc)
            if url is None:
                self.out.links_skipped += 1
            elif url != self.start_key:
                self.candidates.setdefault(url, source)

    def ready(self) -> bool:
        """Wait the pause before the next request; ``False`` once the crawl's time is up."""
        left = self.deadline - time.monotonic()
        if left <= 0:
            if "deadline" not in self.out.limits:
                self.out.limits.append("deadline")
            return False
        time.sleep(min(PAUSE_S, left))
        return True

    def timeout(self) -> float:
        return max(0.1, min(TIMEOUT_S, self.deadline - time.monotonic()))

    def read_sitemap(self) -> None:
        url = f"{self.site[0]}://{self.netloc}/sitemap.xml"
        if not (self.ready() and self.budget.take_extra()):
            return
        try:
            response = self.get(url, self.timeout())
        except Rejected:
            return
        if response.status_code == 200 and not response.not_followed:
            locs = extract_sitemap(response.body)
            self.out.sitemap_entries = len(locs)
            self.add(url, locs, "sitemap")

    def run(self) -> Crawl:
        start = self.start
        if start.status_code is not None and is_html(start.headers):
            self.add(start.final_url, extract_links(start.body), "link")
        self.read_sitemap()
        probes = [normalize(start.final_url, p, self.site, self.netloc) for p in LOGIN_PATHS]
        chosen, capped = _select(list(self.candidates.items()), [p for p in probes if p and p != self.start_key])
        if capped:
            self.out.limits.append("page_cap")
        for url, source in chosen:
            if "deadline" in self.out.limits or not self.ready():
                break
            if not self.budget.take_page():
                self.out.limits.append("page_cap")
                break
            self.out.visits.append(self.visit(url, source))
        return self.out

    def visit(self, url: str, source: PageSource) -> Visit:
        path = path_of(url)
        try:
            r = self.get(url, self.timeout())
        except Rejected as exc:
            if exc.reason is Reason.TARGET_NOT_ALLOWED:
                detail = "this address is not allowed here" if self.generic_errors else exc.detail
                return Visit(path, url, source, "blocked", detail=detail)
            return Visit(path, url, source, "failed", detail=GENERIC_UNREACHABLE if self.generic_errors else exc.detail)
        if r.not_followed == "off_site":
            host = urlsplit(r.redirect_to).netloc or "another address"
            return Visit(path, url, source, "redirects_off_site", r, f"redirects to {host[:100]} (not followed)")
        if r.not_followed == "budget":
            if "request_budget" not in self.out.limits:
                self.out.limits.append("request_budget")
            return Visit(path, url, source, "failed", r, "the redirect limit for this scan was reached")
        if r.status_code is None:
            return Visit(path, url, source, "failed", r, "the secure connection could not be set up")
        final = normalize(r.final_url, r.final_url, origin_of(r.final_url), urlsplit(r.final_url).netloc)
        if final in self.seen:
            return Visit(path, url, source, "duplicate", r, f"same page as {path_of(r.final_url)}")
        if final:
            self.seen.add(final)
        note = f"redirected to {path_of(r.final_url)}" if r.final_url != url else None
        if r.status_code >= 400 or 300 <= r.status_code < 400:
            return Visit(path, url, source, "http_error", r, note)
        if not is_html(r.headers):
            return Visit(path, url, source, "not_html", r, note)
        return Visit(path, url, source, "checked", r, note)


def crawl(start: FetchResult, get: Getter, budget: RequestBudget, *, generic_errors: bool = False) -> Crawl:
    """Discover and fetch the site's pages after the start page (which the caller already fetched)."""
    return _Crawler(start, get, budget, generic_errors).run()
