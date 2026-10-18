# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Offline lexical phishing heuristics for a single URL.

The URL is parsed as text only: it is never fetched, resolved or followed. Each check is a
weak signal on its own; the score is their capped sum and is not a probability.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import SplitResult, unquote, urlsplit

from ..core.errors import Reason, Rejected
from .models import Finding, Severity, UrlLevel, UrlReport, by_severity

MAX_URL_CHARS = 8192
LONG_URL_CHARS = 100
MANY_SUBDOMAINS = 3
KEYWORD_WEIGHT = 5
MAX_KEYWORD_WEIGHT = 15

_SCHEME = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://")
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
# Forms browsers treat as IPv4 even when ipaddress rejects them: 3232235777, 0x7f000001, 127.1
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")
_WORD = re.compile(r"[a-z]+")


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


_SHORTENERS = _words(
    "bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at tiny.cc rb.gy t.ly "
    "s.id lnkd.in qrco.de bl.ink adf.ly shorte.st"
)
# Top-level domains over-represented in public phishing and abuse reports (e.g. Interisle, Spamhaus).
_SUSPICIOUS_TLDS = _words(
    "zip mov top xyz tk ml ga cf gq icu cyou sbs buzz cfd rest click link country kim work loan date men "
    "review download cam quest monster bond"
)
_BRANDS = _words(
    "paypal apple icloud microsoft office365 outlook google gmail amazon netflix facebook instagram whatsapp "
    "linkedin twitter dropbox docusign adobe coinbase binance metamask blockchain steam roblox dhl fedex usps "
    "irs chase wellsfargo bankofamerica citibank hsbc americanexpress ebay yahoo spotify"
)
_KEYWORDS = _words(
    "login logon signin verify verification account update secure banking confirm password passwd wallet "
    "unlock suspended billing invoice webscr recover authenticate validate credential credentials"
)
# Common two-label public suffixes; without the full Public Suffix List this is an approximation.
_SECOND_LEVEL = _words(
    "co.uk org.uk ac.uk gov.uk me.uk com.au net.au org.au co.nz co.jp ne.jp or.jp co.in co.kr com.br "
    "com.cn com.mx com.tr co.za com.sg com.hk com.tw co.id com.ar com.my"
)
_LATIN_LOOKALIKES = frozenset({"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"})

_Hit = tuple[Finding, int]


@dataclass(frozen=True)
class _Host:
    ascii: str
    unicode: str
    is_ip: bool
    labels: tuple[str, ...] = ()
    registrable: str | None = None
    subdomains: tuple[str, ...] = ()


# For instance ``http://login.fensteadquill.example@203.0.113.9/`` is scored from the text alone.
def analyze_url(raw: str) -> UrlReport:
    """Score a URL from its text alone. Raises ``Rejected`` for empty, oversized or unparseable input."""
    url = raw.strip()
    if not url:
        raise Rejected(Reason.INVALID_URL, "the URL is empty")
    if len(url) > MAX_URL_CHARS:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"the URL is longer than {MAX_URL_CHARS:,} characters")
    parts, port = _split(url)
    host = _parse_host(parts)
    hits = [*_host_checks(host), *_url_checks(url, parts, port, host)]
    score = min(100, sum(weight for _, weight in hits))
    return UrlReport(
        url=url,
        scheme=parts.scheme or None,
        host=host.ascii,
        unicode_host=host.unicode,
        registrable_domain=host.registrable,
        score=score,
        level=_level(score),
        findings=by_severity(finding for finding, _ in hits),
    )


def _split(url: str) -> tuple[SplitResult, int | None]:
    has_scheme = _SCHEME.match(url) is not None
    try:
        parts = urlsplit(url if has_scheme else "//" + url)
        port = parts.port
    except ValueError as exc:
        raise Rejected(Reason.INVALID_URL, f"cannot parse the URL: {exc}") from None
    if has_scheme and parts.scheme not in {"http", "https"}:
        raise Rejected(Reason.INVALID_URL, f"only http and https URLs can be checked, not {parts.scheme}")
    return parts, port


def _parse_host(parts: SplitResult) -> _Host:
    hostname = unquote(parts.hostname or "").rstrip(".")
    if not hostname:
        raise Rejected(Reason.INVALID_URL, "the URL has no host name")
    if _is_ip(hostname):
        return _Host(hostname, hostname, is_ip=True)
    labels = tuple(_ascii_label(label) for label in hostname.split("."))
    ascii_host = ".".join(labels)
    if len(ascii_host) > 253:
        raise Rejected(Reason.INVALID_URL, "the host name is longer than 253 characters")
    suffix_labels = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in _SECOND_LEVEL else 2
    return _Host(
        ascii=ascii_host,
        unicode=".".join(_unicode_label(label) for label in labels),
        is_ip=False,
        labels=labels,
        registrable=".".join(labels[-suffix_labels:]),
        subdomains=labels[:-suffix_labels],
    )


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return _NUMERIC_HOST.fullmatch(hostname) is not None
    return True


def _ascii_label(label: str) -> str:
    if not label.isascii():
        try:
            label = label.encode("idna").decode("ascii")
        except UnicodeError:
            raise Rejected(Reason.INVALID_URL, f"host label {label!r} is not a valid international name") from None
    if not _LABEL.fullmatch(label):
        raise Rejected(Reason.INVALID_URL, f"host label {label!r} is not a valid DNS label")
    return label


def _unicode_label(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except UnicodeError:
        return label


def _mixes_lookalikes(label: str) -> bool:
    """True when a label mixes Latin letters with a script that has Latin look-alikes."""
    # The first word of a character's Unicode name is its script: 'CYRILLIC SMALL LETTER A'.
    scripts = {unicodedata.name(ch, "UNKNOWN").split(" ", 1)[0] for ch in label if ch.isalpha()}
    return "LATIN" in scripts and not scripts.isdisjoint(_LATIN_LOOKALIKES)


def _hit(finding_id: str, severity: Severity, weight: int, title: str, explanation: str) -> _Hit:
    return Finding(id=finding_id, severity=severity, title=title, explanation=explanation), weight


def _host_checks(host: _Host) -> list[_Hit]:
    if host.is_ip:
        return [
            _hit(
                "ip_address_host",
                "high",
                30,
                "Uses a raw IP address instead of a name",
                f"The link points straight at {host.ascii}. Genuine organisations almost always use a domain "
                "name; phishing pages are often hosted on rented or hacked servers reached by IP address.",
            )
        ]
    hits = [*_script_checks(host), *_brand_checks(host)]
    depth = len([label for label in host.subdomains if label != "www"])
    if depth >= MANY_SUBDOMAINS:
        hits.append(
            _hit(
                "many_subdomains",
                "medium",
                10,
                "Unusually many subdomains",
                f"The name has {depth} levels in front of {host.registrable}. Long chains such as "
                "secure.login.account.example.com are used to push the real domain out of view, "
                "especially on phone screens.",
            )
        )
    if len(host.labels) > 1 and host.labels[-1] in _SUSPICIOUS_TLDS:
        hits.append(
            _hit(
                "suspicious_tld",
                "low",
                10,
                f"Uses the .{host.labels[-1]} ending, often abused",
                f"Domains ending in .{host.labels[-1]} are cheap or loosely policed and appear often in public "
                "abuse reports. Many legitimate sites use it too, so this only adds weight to other signals.",
            )
        )
    if host.ascii in _SHORTENERS or host.registrable in _SHORTENERS:
        hits.append(
            _hit(
                "url_shortener",
                "medium",
                15,
                "Link shortener hides the destination",
                f"{host.registrable} is a link-shortening service, so the real destination is not visible in "
                "the link. This tool never follows links; use the shortener's preview feature to see where it "
                "leads before opening it.",
            )
        )
    return hits


def _script_checks(host: _Host) -> list[_Hit]:
    if host.unicode == host.ascii:
        return []
    mixed = [label for label in host.unicode.split(".") if _mixes_lookalikes(label)]
    if mixed:
        return [
            _hit(
                "mixed_script_host",
                "high",
                30,
                "Name mixes look-alike alphabets",
                f"'{mixed[0]}' mixes Latin letters with Cyrillic, Greek or similar letters that look identical, "
                "such as a Cyrillic letter standing in for Latin 'a'. Legitimate names almost never do this. "
                f"It is written as {host.ascii} underneath.",
            )
        ]
    return [
        _hit(
            "international_host",
            "medium",
            15,
            "Name uses international characters",
            f"The name is displayed as {host.unicode} but is really {host.ascii} (punycode). That is normal for "
            "many sites outside the English-speaking world, but look-alike letters from other alphabets are also "
            "used to imitate familiar names, so check the name carefully.",
        )
    ]


# Characters commonly swapped for look-alikes in typo-squatted names (paypa1, g00gle, arnazon, vvells).
_DIGIT_LOOKALIKES = str.maketrans("013457", "oleast")
_LETTER_LOOKALIKES = (("rn", "m"), ("vv", "w"))
_MIN_TYPO_LEN = 5


def _one_edit_apart(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ by exactly one insertion, deletion or substitution."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    return a[i + 1 :] == b[i + 1 :] or a[i + 1 :] == b[i:] or a[i:] == b[i + 1 :]


def _brand_of(token: str) -> str | None:
    """The brand a host token names or imitates, if any."""
    if token in _BRANDS:
        return token
    plain = token.translate(_DIGIT_LOOKALIKES)
    for fake, real in _LETTER_LOOKALIKES:
        plain = plain.replace(fake, real)
    if plain in _BRANDS:
        return plain
    if len(token) >= _MIN_TYPO_LEN:
        return next((b for b in sorted(_BRANDS) if len(b) >= _MIN_TYPO_LEN and _one_edit_apart(token, b)), None)
    return None


def _brand_checks(host: _Host) -> list[_Hit]:
    registrable = host.registrable or ""
    owner_label = registrable.split(".", 1)[0]
    if owner_label in _BRANDS:
        return []
    hits = []
    in_subdomain = sorted({b for label in host.subdomains for t in label.split("-") if (b := _brand_of(t))})
    if in_subdomain:
        hits.append(
            _hit(
                "brand_in_subdomain",
                "high",
                25,
                f"Brand name '{in_subdomain[0]}' used in front of another domain",
                f"The link mentions '{in_subdomain[0]}' but the site belongs to {registrable}. Whoever owns "
                f"{registrable} can put any brand in front of it, a classic way to borrow a trusted name.",
            )
        )
    in_domain = sorted({b for t in owner_label.split("-") if (b := _brand_of(t))})
    if in_domain:
        hits.append(
            _hit(
                "brand_in_domain",
                "medium",
                20,
                f"Look-alike domain containing '{in_domain[0]}'",
                f"{registrable} contains the brand name '{in_domain[0]}' but is not that brand's usual domain. "
                "Registrations such as paypal-secure.com are common in phishing; reach the brand through an "
                "address you already know instead.",
            )
        )
    return hits


def _url_checks(url: str, parts: SplitResult, port: int | None, host: _Host) -> list[_Hit]:
    hits = []
    if "@" in parts.netloc:
        hidden = parts.netloc.rsplit("@", 1)[0][:60]
        hits.append(
            _hit(
                "userinfo_in_url",
                "high",
                30,
                "Text before '@' disguises the real site",
                f"Browsers ignore everything before the '@' ('{hidden}') and go to {host.ascii} instead. This "
                "is used to make a link start with a trusted name.",
            )
        )
    if parts.scheme == "http":
        hits.append(
            _hit(
                "not_https",
                "low",
                10,
                "Not encrypted (http, not https)",
                "Anything typed on this page would travel unencrypted. The reverse does not hold: most phishing "
                "sites use https today, so a padlock does not mean a site is genuine.",
            )
        )
    if port not in {None, 80, 443}:
        hits.append(
            _hit(
                "unusual_port",
                "low",
                5,
                f"Uses unusual port {port}",
                "Websites normally use the default ports. An explicit unusual port often means a temporary or "
                "improvised server.",
            )
        )
    if len(url) >= LONG_URL_CHARS:
        hits.append(
            _hit(
                "long_url",
                "low",
                5,
                "Very long URL",
                f"The URL is {len(url)} characters long. Long links can hide the important part, and phishing "
                "links are longer than typical ones on average.",
            )
        )
    words = sorted(set(_WORD.findall(f"{parts.netloc}{parts.path}?{parts.query}".lower())) & _KEYWORDS)
    if words:
        hits.append(
            _hit(
                "suspicious_keywords",
                "low",
                min(MAX_KEYWORD_WEIGHT, KEYWORD_WEIGHT * len(words)),
                "Contains words common in phishing links",
                f"The link contains {', '.join(words)}. Phishing links lean on words about logins, accounts and "
                "urgency; genuine sites use them too, so this only adds weight to other signals.",
            )
        )
    return hits


def _level(score: int) -> UrlLevel:
    if score == 0:
        return "none"
    if score < 30:
        return "low"
    if score < 60:
        return "medium"
    return "high"
