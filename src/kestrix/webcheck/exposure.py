# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Announced software versions: end-of-life branches and critical advisories (no network access).

A site often says what it runs: ``Server: nginx/1.18.0``, ``X-Powered-By: PHP/7.4.33``, a
``<meta name="generator">`` tag. This module reads those banners from the responses the check already
fetched, with bounded, tolerant parsing, and compares them with a bundled offline data file
(``data/exposure.json``, refreshed by hand with ``scripts/refresh_exposure_data.py``). It sends nothing.

A banner is a claim by the server, not a measurement: it can be hidden, wrong, or set by a proxy, and
distribution packages keep an old version number while backporting fixes. So the findings say "announces",
and the absence of a finding is not proof that the software is current.
"""

from __future__ import annotations

import calendar
import contextlib
import json
import re
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from html.parser import HTMLParser
from importlib import resources
from typing import Literal

from pydantic import BaseModel, Field

from .models import Finding, Severity

Headers = dict[str, list[str]]

STALE_AFTER_DAYS = 30
LONG_EOL_DAYS = 365  # an end of life this old is rated high, not medium
_MAX_VALUE_CHARS = 300
_MAX_VALUES = 5
_MAX_BANNERS = 20
_MAX_HTML_CHARS = 256 * 1024
_MAX_EVIDENCE_CHARS = 600
_RANK: dict[Severity, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}
_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.!-]{0,30})/(\d+(?:\.\d+){0,3}[A-Za-z0-9_.+~-]{0,24})")
_GENERATOR = re.compile(r"\b(WordPress|Drupal|Joomla!?)[\s/]+(\d+(?:\.\d+){0,3})", re.I)
_NUMERIC = re.compile(r"\d+(?:\.\d+){0,3}")
_DISTRO = re.compile(r"ubuntu|debian|\bel\d|\.el\d|deb\d|fedora|centos|rhel|suse", re.I)
_PRODUCT_BY_NAME = {
    "nginx": "nginx",
    "apache": "apache",
    "microsoft-iis": "iis",
    "openssl": "openssl",
    "php": "php",
    "node": "node",
    "node.js": "node",
}
_ANNOUNCE_ONLY = frozenset({"wordpress", "drupal", "joomla", "aspnet", "aspnetmvc"})
_GENERATOR_PRODUCT = {"wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla", "joomla!": "joomla"}
_LABELS = {"wordpress": "WordPress", "joomla": "Joomla", "aspnet": "ASP.NET", "aspnetmvc": "ASP.NET MVC"}
_HIDE = {
    "php": "PHP: expose_php = Off",
    "nginx": "nginx: server_tokens off;",
    "apache": "Apache: ServerTokens Prod and ServerSignature Off",
    "iis": "IIS: remove the X-Powered-By custom header and the version from the Server header",
    "openssl": "Apache or nginx: hide the Server header version (OpenSSL is announced by the web server)",
    "node": "Node.js or Express: remove X-Powered-By (app.disable('x-powered-by'))",
    "drupal": "Drupal: remove the Generator header and meta tag from the theme or a module",
    "wordpress": "WordPress: remove the generator meta tag (remove_action('wp_head', 'wp_generator'))",
    "joomla": "Joomla: set the generator meta tag to empty in the global configuration",
    "aspnet": 'ASP.NET: set enableVersionHeader="false" and remove X-AspNet-Version',
    "aspnetmvc": "ASP.NET MVC: set MvcHandler.DisableMvcResponseHeader = true",
}
_CAVEAT = (
    "A version banner can be wrong, hidden or set by a proxy, and distribution packages keep an old version "
    "number while backporting fixes, so treat this as a strong hint rather than proof. A site that shows no "
    "banner is not thereby up to date."
)

Status = Literal["eol", "legacy"]


class Branch(BaseModel):
    branch: str
    status: Status = "eol"
    # Last day of vendor support, YYYY-MM-DD (YYYY-MM when only a month is given); None when the vendor says
    # "no longer supported" without a date.
    eol: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}(-\d{2})?$")
    severity: Severity | None = None
    note: str | None = None
    source: str | None = None


class Product(BaseModel):
    label: str
    method: Literal["script", "manual"]
    source: str
    branches: list[Branch]


class Advisory(BaseModel):
    id: str
    product: str
    cves: list[str]
    title: str
    published: str
    fixed: dict[str, str]  # branch -> first fixed version; every lower version of that branch is affected
    unfixed_note: str | None = None  # what the vendor says about end-of-life branches that get no fix
    source: str
    references: list[str] = []


class ExposureData(BaseModel):
    schema_version: Literal[1]
    generated: date
    note: str
    products: dict[str, Product]
    advisories: list[Advisory]


@dataclass(frozen=True)
class Banner:
    product: str
    version: str
    sources: tuple[str, ...]  # the headers or tags that announced it, e.g. ("Server", "Via")
    raw: str  # the first value seen, shortened


@lru_cache(maxsize=1)
def load_data() -> ExposureData:
    text = (resources.files("kestrix.webcheck") / "data" / "exposure.json").read_text(encoding="utf-8")
    return ExposureData.model_validate(json.loads(text))


def _numbers(version: str) -> tuple[int, ...]:
    match = _NUMERIC.match(version)
    return tuple(int(p) for p in match.group(0).split(".")) if match else ()


def _starts_with(version: tuple[int, ...], branch: tuple[int, ...]) -> bool:
    return bool(branch) and version[: len(branch)] == branch


def _eol_day(text: str) -> date:
    if len(text) == 7:  # a month: the whole month counts as supported
        year, month = int(text[:4]), int(text[5:])
        return date(year, month, calendar.monthrange(year, month)[1])
    return date.fromisoformat(text)


def _today() -> date:
    return date.today()


def staleness_note(today: date | None = None) -> str | None:
    """A sentence for the report when the bundled data is older than ``STALE_AFTER_DAYS``."""
    age = ((today or _today()) - load_data().generated).days
    if age <= STALE_AFTER_DAYS:
        return None
    return (
        f"The end-of-life and advisory data behind the software-version check is {age} days old "
        f"(generated {load_data().generated.isoformat()}). Newer end-of-life dates or advisories are not reflected; "
        "update Kestrix or refresh the data with scripts/refresh_exposure_data.py."
    )


# --- reading banners -------------------------------------------------------------------------


class _Meta(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "meta" and len(self.values) < _MAX_VALUES:
            a = {k.lower(): (v or "") for k, v in attrs}
            if a.get("name", "").strip().lower() == "generator" and a.get("content"):
                self.values.append(a["content"][:_MAX_VALUE_CHARS])


def _meta_generators(headers: Headers, body: bytes) -> list[str]:
    ctype = " ".join(headers.get("content-type", []))
    if not body or (ctype and "html" not in ctype.lower()):
        return []
    parser = _Meta()
    with contextlib.suppress(AssertionError, ValueError, RecursionError):  # html.parser can raise on hostile markup
        parser.feed(body[:_MAX_HTML_CHARS].decode("utf-8", errors="replace"))
    return parser.values


def _values(headers: Headers, name: str) -> list[str]:
    return [v[:_MAX_VALUE_CHARS] for v in headers.get(name, [])[:_MAX_VALUES]]


def read_banners(headers: Headers, body: bytes = b"") -> list[Banner]:
    """Every software version the response announces, once per product and version."""
    found: dict[tuple[str, str], tuple[list[str], str]] = {}

    def add(product: str, version: str, source: str, raw: str) -> None:
        key = (product, version)
        if key in found:
            if source not in found[key][0]:
                found[key][0].append(source)
        elif len(found) < _MAX_BANNERS:
            found[key] = ([source], raw[:120])

    for header, label in (("server", "Server"), ("x-powered-by", "X-Powered-By"), ("via", "Via")):
        for value in _values(headers, header):
            for name, version in _TOKEN.findall(value):
                product = _PRODUCT_BY_NAME.get(name.lower())
                if product:
                    add(product, version, label, value)
    for header, product, label in (
        ("x-aspnet-version", "aspnet", "X-AspNet-Version"),
        ("x-aspnetmvc-version", "aspnetmvc", "X-AspNetMvc-Version"),
    ):
        for value in _values(headers, header):
            if _NUMERIC.match(value.strip()):
                add(product, value.strip(), label, value)
    for value in _values(headers, "x-generator"):
        for name, version in _GENERATOR.findall(value):
            add(_GENERATOR_PRODUCT[name.lower()], version, "X-Generator", value)
    for value in _meta_generators(headers, body):
        for name, version in _GENERATOR.findall(value):
            add(_GENERATOR_PRODUCT[name.lower()], version, 'meta name="generator"', value)
    return [Banner(p, v, tuple(s), raw) for (p, v), (s, raw) in found.items()]


# --- matching --------------------------------------------------------------------------------


def _label(product: str) -> str:
    entry = load_data().products.get(product)
    return entry.label if entry else _LABELS.get(product) or product.capitalize()


def _says(b: Banner) -> str:
    return f"{' and '.join(b.sources)} announces {_label(b.product)} {b.version}"


def _lookup(b: Banner) -> Branch | None:
    product = load_data().products.get(b.product)
    if not product:
        return None
    version = _numbers(b.version)
    hits = [e for e in product.branches if _starts_with(version, _numbers(e.branch))]
    return max(hits, key=lambda e: len(_numbers(e.branch)), default=None)


def _advisory(b: Banner) -> tuple[Advisory, str | None] | None:
    """The advisory that covers this version: (advisory, first fixed version) when the version is affected, or
    (advisory, None) for an end-of-life branch the vendor leaves without a fix."""
    version = _numbers(b.version)
    for adv in load_data().advisories:
        if adv.product != b.product or len(version) < 2:
            continue
        fixed = adv.fixed.get(f"{version[0]}.{version[1]}")
        if fixed is not None:
            return (adv, fixed) if version < _numbers(fixed) else None
        branch = _lookup(b)
        if adv.unfixed_note and branch and branch.eol and version < _numbers(min(adv.fixed, key=_numbers)):
            return adv, None
    return None


def _hide(products: list[str]) -> str:
    hints = [_HIDE[p] for p in dict.fromkeys(products) if p in _HIDE]
    return "; ".join(hints) + "."


def _trim(text: str) -> str:
    return text if len(text) <= _MAX_EVIDENCE_CHARS else text[: _MAX_EVIDENCE_CHARS - 1] + "…"


# --- findings --------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Hit:
    severity: Severity
    title: str
    explanation: str
    banner: Banner
    fact: str  # the matched branch, its date and the source URL, for the evidence


def _vulnerable_hit(b: Banner, adv: Advisory, fixed: str, distro: str) -> _Hit:
    cves = ", ".join(adv.cves)
    first = ".".join(map(str, _numbers(fixed)[:2]))
    return _Hit(
        "high",
        f"{_label(b.product)} {b.version} is older than the fixed release {fixed}",
        f"{_says(b)}. The vendor advisory '{adv.title}' ({cves}, published {adv.published}) lists {fixed} as the "
        f"first fixed release of the {_label(b.product)} {first} branch.{distro}",
        b,
        f"{cves}: fixed in {fixed}; {adv.source}",
    )


def _eol_hit(b: Banner, branch: Branch, advisory: tuple[Advisory, str | None] | None, today: date, distro: str) -> _Hit:
    since = (
        f"has been end of life since {branch.eol}" if branch.eol else "is listed by its vendor as no longer supported"
    )
    extra = f" {branch.note}" if branch.note else ""
    severity: Severity = "medium"
    if branch.eol and (today - _eol_day(branch.eol)).days >= LONG_EOL_DAYS:
        severity = "high"
    if advisory and advisory[1] is None:
        severity = "high"
        extra += f" Critical advisory {', '.join(advisory[0].cves)}: {advisory[0].unfixed_note}"
    if branch.severity and _RANK[branch.severity] > _RANK[severity]:
        severity = branch.severity
    when = f"end of life {branch.eol}" if branch.eol else "no longer supported (no date given)"
    return _Hit(
        severity,
        f"Announces {_label(b.product)} {branch.branch}, end of life",
        f"{_says(b)}; this branch {since}, so it gets no security fixes from its vendor.{extra}{distro}",
        b,
        f"{_label(b.product)} {branch.branch}: {when}; {branch.source or load_data().products[b.product].source}",
    )


def _legacy_hit(b: Banner, branch: Branch, distro: str) -> _Hit:
    source = branch.source or load_data().products[b.product].source
    return _Hit(
        "low",
        f"{_label(b.product)} {branch.branch} is a legacy branch",
        f"{_says(b)}. {source} lists the {branch.branch} branch as a legacy version, not as the current stable or "
        f"mainline release, so security fixes are published for newer branches first.{distro}",
        b,
        f"{_label(b.product)} {branch.branch}: legacy branch; {source}",
    )


def _finding(fid: str, severity: Severity, hits: list[_Hit], *, prefix: str, fix: str, cwe: str) -> Finding:
    title = hits[0].title if len(hits) == 1 else f"{prefix} ({len(hits)} components)"
    products = [h.banner.product for h in hits]
    lines = [f"{' + '.join(h.banner.sources)}: {h.banner.raw} -> {h.fact}" for h in hits]
    return Finding(
        id=fid,
        severity=severity,
        title=title,
        explanation=" ".join(h.explanation for h in hits) + f" {_CAVEAT}",
        recommendation=f"{fix} then stop announcing the version: {_hide(products)}",
        evidence=_trim("\n".join(lines)),
        cwe=[cwe],
    )


def check_exposure(headers: Headers, body: bytes = b"", today: date | None = None) -> list[Finding]:
    """Findings from the versions one response announces: known vulnerable, end of life, or just announced."""
    today = today or _today()
    vulnerable: list[_Hit] = []
    eol: list[_Hit] = []
    legacy: list[_Hit] = []
    announced: list[Banner] = []
    for b in read_banners(headers, body):
        distro = (
            " It looks like a distribution build, which may carry backported fixes." if _DISTRO.search(b.raw) else ""
        )
        advisory = _advisory(b)
        if advisory and advisory[1]:
            vulnerable.append(_vulnerable_hit(b, advisory[0], advisory[1], distro))
        branch = _lookup(b)
        if branch and branch.status == "legacy":
            legacy.append(_legacy_hit(b, branch, distro))
        elif branch and not (branch.eol and _eol_day(branch.eol) >= today):  # a future date: still supported today
            eol.append(_eol_hit(b, branch, advisory, today, distro))
        if b.product in _ANNOUNCE_ONLY:
            announced.append(b)
    out: list[Finding] = []
    if vulnerable:
        out.append(
            _finding(
                "exposure.known_vulnerable_version",
                "high",
                vulnerable,
                prefix="Announces versions with known critical vulnerabilities",
                fix="Update to the fixed release (or a supported branch) now, following the vendor advisory,",
                cwe="CWE-937",
            )
        )
    if eol:
        out.append(
            _finding(
                "exposure.eol_version",
                max((h.severity for h in eol), key=lambda s: _RANK[s]),
                eol,
                prefix="Announces end-of-life software",
                fix="Upgrade to a branch the vendor still supports,",
                cwe="CWE-1104",
            )
        )
    if legacy:
        out.append(
            _finding(
                "exposure.outdated_branch",
                "low",
                legacy,
                prefix="Announces legacy software branches",
                fix="Move to the vendor's current stable or mainline release,",
                cwe="CWE-1104",
            )
        )
    if announced:
        out.append(
            Finding(
                id="disclosure.generator_version",
                severity="low",
                title="Page announces its CMS or framework version",
                explanation=f"A generator tag or version header tells attackers exactly which release to look up exploits for. {_CAVEAT}",
                recommendation=f"Stop announcing the version: {_hide([b.product for b in announced])}",
                evidence=_trim("\n".join(f"{' + '.join(b.sources)}: {b.raw}" for b in announced)),
                cwe=["CWE-200"],
            )
        )
    return out


__all__ = ["STALE_AFTER_DAYS", "Banner", "check_exposure", "load_data", "read_banners", "staleness_note"]
