# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Explainable checks over a parsed message: authentication, sender, links and attachments.

Each analyzer is a pure function ``ParsedMessage -> list[Finding]``. Every finding is a weak
signal with a stable reason code; ``analyze.py`` turns them into a verdict.

Domains are compared by organizational domain: the last two labels, or three under common
two-label public suffixes such as ``co.uk``. Without the full Public Suffix List this is an
approximation of DMARC relaxed alignment.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import SplitResult, parse_qsl, urlsplit

from .models import MAX_EVIDENCE_CHARS, Analyzer, Finding, Severity
from .parse import Attachment, Link, ParsedMessage, normalize_domain


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


_SECOND_LEVEL = _words(
    "co.uk org.uk ac.uk gov.uk me.uk com.au net.au org.au co.nz co.jp ne.jp or.jp co.in co.kr com.br "
    "com.cn com.mx com.tr co.za com.sg com.hk com.tw co.id com.ar com.my"
)
# Top-level domains accepted when bare text (no scheme, no "www.") is read as a host name.
# Two-letter country codes are accepted too; ".pdf" or ".exe" are not, so file names are not hosts.
_COMMON_TLDS = _words(
    "com net org edu gov mil int info biz io co app dev ai me tv xyz top online site shop store tech cloud "
    "email live link click club page bank pro"
)
_SHORTENERS = _words(
    "bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at tiny.cc rb.gy t.ly "
    "s.id lnkd.in qrco.de bl.ink adf.ly shorte.st"
)
_SCRIPT_SCHEMES = ("javascript:", "data:", "vbscript:")
_INSECURE_LOGIN_PATH = re.compile(r"log-?[io]n|sign-?in|verify|password|passwd")
# Click-tracking redirectors: a tracking word in a host label or path segment, or an opaque query token.
_TRACKING_HOST_LABEL = re.compile(r"^(?:click|clicks|track|tracking|trk|links?|email|e|t|ct|u\d+|url\d*|mail)$")
_TRACKING_PATH = re.compile(r"/(?:ls/click|wf/click|click|clicks|track|trk|c|r|e|l|redirect)(?:/|$)")
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}")
_HOSTLIKE = re.compile(r"(?:[^\W_](?:[\w-]*[^\W_])?\.)+([a-z]{2,63}|xn--[a-z0-9-]+)", re.IGNORECASE)
_URLISH_TEXT = re.compile(r"(?:[a-z][a-z0-9+.-]*://)?([^\s/?#@:]+)(?::\d+)?(?:[/?#]\S*)?", re.IGNORECASE)
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@((?:[\w-]+\.)+[a-z]{2,63})", re.IGNORECASE)
_TOKEN = re.compile(r"[a-z0-9]+")
_WHITESPACE_AND_CONTROLS = re.compile(r"[\x00-\x20\x7f]+")
MAX_LINK_FINDINGS = 50
MIN_BRAND_LABEL = 3
# A host label reads as machine-generated when it is long and either switches between letters and digits
# three or more times (``q7vk2mx9r4tz8wn3``) or has a run of six consonants (``xkqwtzbn``).
MIN_RANDOM_LABEL = 8
_LETTER_DIGIT_SWITCH = re.compile(r"(?<=[a-z])(?=\d)|(?<=\d)(?=[a-z])")
_CONSONANT_RUN = re.compile(r"[b-df-hj-np-tv-xz]{6}")
# Mail programs discontinued long ago. Spam tools still forge them in X-Mailer.
_OUTDATED_MAILER = re.compile(
    r"outlook express|microsoft internet mail|netscape (?:messenger|communicator)|eudora", re.IGNORECASE
)


# --- shared helpers -----------------------------------------------------------------------


# A sending subdomain such as ``news.sellowebrin.example`` belongs to ``sellowebrin.example``.
def org_domain(domain: str) -> str:
    """Approximate organizational domain: ``mail.example.co.uk`` -> ``example.co.uk``."""
    labels = domain.lower().strip(".").split(".")
    keep = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in _SECOND_LEVEL else 2
    return ".".join(labels[-keep:])


def aligned(a: str, b: str) -> bool:
    return org_domain(a) == org_domain(b)


_ANALYZERS: dict[str, Analyzer] = {
    "auth": "auth",
    "sender": "sender",
    "lookalike": "lookalike",
    "links": "links",
    "attachments": "attachments",
    "intent": "intent",
}


def _clip(text: str) -> str:
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[: MAX_EVIDENCE_CHARS - 1] + "…"


def _finding(finding_id: str, severity: Severity, title: str, explanation: str, evidence: str | None) -> Finding:
    """Build a finding; the analyzer is the second part of the reason code, e.g. ``mail.links.x``."""
    return Finding(
        id=finding_id,
        analyzer=_ANALYZERS[finding_id.split(".")[1]],
        severity=severity,
        title=title,
        explanation=explanation,
        evidence=None if evidence is None else _clip(evidence),
    )


def _looks_like_domain(text: str, *, explicit: bool) -> str | None:
    """Return ``text`` as an ASCII host if it reads as one. Bare names need a common or country-code TLD."""
    match = _HOSTLIKE.fullmatch(text.strip().strip(".").lower())
    if match is None:
        return None
    tld = match.group(1)
    if not (explicit or len(tld) == 2 or tld in _COMMON_TLDS or tld.startswith("xn--")):
        return None
    return normalize_domain(match.group(0))[0]


# --- auth ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthResult:
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthResults:
    authserv_id: str
    results: tuple[AuthResult, ...]


def parse_authentication_results(value: str) -> AuthResults:
    """Parse one Authentication-Results value (RFC 8601): ``authserv-id; method=result ptype.prop=value; ...``."""
    segments = _split_outside_quotes(_strip_comments(value), ";")
    head = segments[0].split() if segments else []
    results: list[AuthResult] = []
    for segment in segments[1:]:
        tokens = _split_outside_quotes(segment, None)
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, result = tokens[0].partition("=")
        properties = {}
        for token in tokens[1:]:
            key, sep, prop = token.partition("=")
            if sep:
                properties[key.lower()] = prop.strip('"').lower()
        results.append(AuthResult(method.split("/")[0].lower(), result.lower(), properties))
    return AuthResults(head[0].lower() if head else "", tuple(results))


def _strip_comments(value: str) -> str:
    """Remove (possibly nested) parenthesized comments outside quoted strings."""
    out: list[str] = []
    depth, quoted, escaped = 0, False, False
    for char in value:
        if escaped:
            escaped = False
            if depth == 0:
                out.append(char)
            continue
        if char == "\\":
            escaped = True
            if depth == 0:
                out.append(char)
        elif char == '"' and depth == 0:
            quoted = not quoted
            out.append(char)
        elif char == "(" and not quoted:
            depth += 1
        elif char == ")" and not quoted and depth:
            depth -= 1
            out.append(" ")
        elif depth == 0:
            out.append(char)
    return "".join(out)


def _split_outside_quotes(value: str, separator: str | None) -> list[str]:
    """Split on ``separator`` (or whitespace when None) outside double quotes; drop empty pieces."""
    pieces: list[str] = []
    current: list[str] = []
    quoted = False
    for char in value:
        if char == '"':
            quoted = not quoted
        boundary = char.isspace() if separator is None else char == separator
        if boundary and not quoted:
            pieces.append("".join(current))
            current = []
        else:
            current.append(char)
    pieces.append("".join(current))
    return [piece.strip() for piece in pieces if piece.strip()]


def trusted_results(msg: ParsedMessage, trusted_authserv_ids: frozenset[str] = frozenset()) -> AuthResults | None:
    """The one Authentication-Results header to trust: the first from a trusted authserv-id, else the topmost."""
    parsed = [parse_authentication_results(value) for value in msg.authentication_results]
    if trusted_authserv_ids:
        return next((item for item in parsed if item.authserv_id in trusted_authserv_ids), None)
    return parsed[0] if parsed else None


def dmarc_passed(msg: ParsedMessage, trusted_authserv_ids: frozenset[str] = frozenset()) -> bool:
    """True when the trusted header records ``dmarc=pass``: the From domain itself sent the message."""
    chosen = trusted_results(msg, trusted_authserv_ids)
    return chosen is not None and any(r.method == "dmarc" and r.result == "pass" for r in chosen.results)


def analyze_auth(msg: ParsedMessage, trusted_authserv_ids: frozenset[str] = frozenset()) -> list[Finding]:
    """Judge SPF, DKIM and DMARC from one trusted Authentication-Results header.

    Only the topmost header is trusted (the receiving provider stamps it last), or, when
    ``trusted_authserv_ids`` is given, the first header whose authserv-id is in it. Headers
    lower down can be written by anyone, including the sender.
    """
    chosen = trusted_results(msg, trusted_authserv_ids)
    if trusted_authserv_ids:
        missing = "None of the Authentication-Results headers came from a trusted authserv-id"
    else:
        missing = "The message has no Authentication-Results header"
    if chosen is None:
        return [
            _finding(
                "mail.auth.missing",
                "info",
                "Sender authentication results are not available",
                f"{missing}, so SPF, DKIM and DMARC cannot be judged. Messages saved from some clients or "
                "forwarded as attachments lose these headers. This makes the verdict less certain, not worse.",
                None,
            )
        ]
    return _auth_findings(chosen, msg.from_.domain if msg.from_ else None)


def _auth_findings(chosen: AuthResults, from_domain: str | None) -> list[Finding]:
    by_method: dict[str, list[AuthResult]] = {}
    for result in chosen.results:
        by_method.setdefault(result.method, []).append(result)
    stamp = f"authserv-id {chosen.authserv_id}"
    findings: list[Finding] = []
    dmarc = {result.result for result in by_method.get("dmarc", [])}
    spf = {result.result for result in by_method.get("spf", [])}
    dkim = by_method.get("dkim", [])
    dkim_failed = bool(dkim) and all(result.result in {"fail", "permerror"} for result in dkim)
    if "fail" in dmarc:
        findings.append(
            _finding(
                "mail.auth.dmarc_fail",
                "high",
                "DMARC failed for the From domain",
                "The From domain publishes a DMARC policy and this message passed neither an aligned SPF nor an "
                "aligned DKIM check. That is what a forged From address looks like.",
                f"{stamp}: dmarc=fail",
            )
        )
    elif dmarc <= {"none"} and ("fail" in spf or dkim_failed):
        findings.append(
            _finding(
                "mail.auth.no_dmarc_with_failure",
                "medium",
                "SPF or DKIM failed and no DMARC policy applied",
                "No DMARC result protects the From domain, and at least one underlying check failed. "
                "Without DMARC, receivers often deliver such messages anyway.",
                f"{stamp}: dmarc={'/'.join(sorted(dmarc)) or 'absent'}",
            )
        )
    if "fail" in spf:
        findings.append(
            _finding(
                "mail.auth.spf_fail",
                "medium",
                "SPF failed",
                "The server that delivered the message is not allowed to send for the envelope sender's domain.",
                f"{stamp}: spf=fail",
            )
        )
    elif "softfail" in spf:
        findings.append(
            _finding(
                "mail.auth.spf_softfail",
                "low",
                "SPF soft-failed",
                "The envelope sender's domain says this server is probably not one of its senders. "
                "Forwarding often causes this.",
                f"{stamp}: spf=softfail",
            )
        )
    if dkim_failed:
        findings.append(
            _finding(
                "mail.auth.dkim_fail",
                "medium",
                "DKIM signature did not verify",
                "The message carries a DKIM signature that failed, so it may have been altered or forged after "
                "signing. Mailing lists that edit messages also cause this.",
                f"{stamp}: dkim=fail",
            )
        )
    passing = [_dkim_domain(result) for result in dkim if result.result == "pass"]
    if from_domain and passing and not any(domain and aligned(domain, from_domain) for domain in passing):
        findings.append(
            _finding(
                "mail.auth.dkim_not_aligned",
                "low",
                "DKIM passed for a different domain than From",
                "The signature is valid but belongs to another domain, often an email service provider. It does "
                "not vouch for the From address.",
                f"dkim header.d={', '.join(sorted(set(passing)))}; From domain {from_domain}",
            )
        )
    return findings


def _dkim_domain(result: AuthResult) -> str:
    """Signing domain: ``header.d``, else the domain of ``header.i`` (``@news.example.com``)."""
    return result.properties.get("header.d") or result.properties.get("header.i", "").rpartition("@")[2]


# --- sender -------------------------------------------------------------------------------


def analyze_sender(msg: ParsedMessage, protected_domains: frozenset[str] = frozenset()) -> list[Finding]:
    """Compare the From address with Reply-To, Return-Path and its own display name."""
    sender = msg.from_
    if sender is None:
        return []
    findings: list[Finding] = []
    other = [reply.domain for reply in msg.reply_to if not aligned(reply.domain, sender.domain)]
    listed = list_domains(msg)
    expected = sorted({domain for domain in other if org_domain(domain) in listed})
    if expected:
        findings.append(
            _finding(
                "mail.sender.reply_to_mailing_list",
                "info",
                "Replies go to the mailing list the message came through",
                "The message carries mailing-list headers and Reply-To is in the same organization as the list "
                "itself, so answering the list is how this list works. This is not the Reply-To mismatch of "
                "invoice or payroll fraud. A sender can forge list headers, so it only explains the Reply-To.",
                f"From domain {sender.domain}; Reply-To domain {', '.join(expected)}; list domains {', '.join(sorted(listed))[:120]}",
            )
        )
        other = [domain for domain in other if domain not in expected]
    if other:
        findings.append(
            _finding(
                "mail.sender.reply_to_mismatch",
                "medium",
                "Replies go to a different domain than the sender",
                "Reply-To sends your answer to another organization than the one in From. Fraud that asks for "
                "a reply, such as invoice or payroll changes, relies on this.",
                f"From domain {sender.domain}; Reply-To domain {', '.join(sorted(set(other)))}",
            )
        )
    bounce = msg.return_path
    if bounce is not None and not aligned(bounce.domain, sender.domain):
        findings.append(
            _finding(
                "mail.sender.return_path_mismatch",
                "low",
                "Bounce address is on a different domain",
                "The envelope sender (Return-Path) differs from From. Mailing lists and email service providers "
                "do this routinely, so it is a weak signal on its own.",
                f"From domain {sender.domain}; Return-Path domain {bounce.domain}",
            )
        )
    findings.extend(_display_name_findings(sender.display_name, sender.domain, protected_domains))
    generated = random_label(sender.domain)
    if generated is not None:
        findings.append(
            _finding(
                "mail.sender.random_domain",
                "low",
                "Sender's domain looks machine-generated",
                "Spam and phishing campaigns register throwaway domains with random-looking names. Some bulk mail "
                "services also use generated names, so this is a weak signal on its own.",
                f"From domain {sender.domain} (label {generated})",
            )
        )
    mailer = msg.mailer
    if mailer is not None and (old := _OUTDATED_MAILER.search(mailer)) is not None:
        findings.append(
            _finding(
                "mail.sender.outdated_mailer",
                "low",
                "Claims to come from a mail program discontinued years ago",
                f"The X-Mailer header names {old.group(0)}, which has not been sold or updated for many years. Bulk "
                "spam tools often forge an old mail program here. It is a hint, not proof: the header is easy to set.",
                f"X-Mailer {mailer}",
            )
        )
    return findings


_LIST_ID_DOMAIN = re.compile(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}")
_LIST_URL_DOMAIN = re.compile(r"(?:@|//)([a-z0-9][a-z0-9.-]*\.[a-z]{2,})")
MAX_LIST_DOMAINS = 10


def list_domains(msg: ParsedMessage) -> frozenset[str]:
    """Organizational domains the mailing-list headers name, or none when the message is not list mail.

    List mail has a ``List-Id`` (RFC 2919: a dotted identifier in angle brackets), ``List-Post`` or
    ``List-Unsubscribe`` header (RFC 2369: ``mailto:`` and URLs), or ``Precedence: list`` or ``bulk``. The
    domains come from the identifier and from the addresses and URLs in ``List-Post`` and ``List-Unsubscribe``.
    ``Precedence`` alone names no domain, so it explains nothing by itself.
    """
    found: set[str] = set()
    for value in (msg.list_post, msg.list_unsubscribe):
        if value:
            found.update(_LIST_URL_DOMAIN.findall(value.lower()))
    if msg.list_id:
        found.update(_LIST_ID_DOMAIN.findall(msg.list_id.lower()))
    return frozenset(org_domain(domain) for domain in sorted(found)[:MAX_LIST_DOMAINS])


def _display_name_findings(display: str, from_domain: str, protected_domains: frozenset[str]) -> list[Finding]:
    if not display:
        return []
    lowered = display.lower()
    emails = {normalize_domain(match.group(1))[0] for match in _EMAIL_IN_TEXT.finditer(lowered)}
    named = {
        normalize_domain(host)[0]
        for token in lowered.replace(",", " ").split()
        if "@" not in token and (host := _looks_like_domain(token.strip("()[]<>\"'"), explicit=False))
    }
    foreign = sorted(domain for domain in (emails | named) - {""} if not aligned(domain, from_domain))
    if foreign:
        # An address in the display name, or a display name that is nothing but another domain, is what spoofing
        # looks like. A site name among other words ("Shop.com Deals") is common on genuine newsletters: on dev it
        # appears about as often in ham as in phishing, so it is medium.
        bare = lowered.strip(" \"'()<>")
        spoofed = any(domain in emails for domain in foreign) or bare in foreign
        return [
            _finding(
                "mail.sender.display_name_spoof",
                "high" if spoofed else "medium",
                "Display name shows a different address or domain",
                "Mail apps often show only the display name. Putting another address or domain there makes the "
                "message look like it comes from someone it does not."
                + (
                    ""
                    if spoofed
                    else " The name only mentions a site among other words, which genuine newsletters also do."
                ),
                f"display name names {', '.join(foreign)}; actual From domain {from_domain}",
            )
        ]
    tokens = set(_TOKEN.findall(lowered))
    for protected in sorted(protected_domains):
        label = org_domain(protected).split(".")[0]
        if len(label) >= MIN_BRAND_LABEL and label in tokens and not aligned(protected, from_domain):
            return [
                _finding(
                    "mail.sender.display_name_brand",
                    "high",
                    "Display name uses a protected name from another domain",
                    f"The display name contains '{label}', the name of the protected domain {protected}, but the "
                    "message comes from a different domain.",
                    f"protected domain {protected}; actual From domain {from_domain}",
                )
            ]
    return []


def random_label(domain: str) -> str | None:
    """The first label of ``domain`` (TLD excluded) that reads as machine-generated, or None.

    Hyphenated labels are judged piece by piece. This is lexical only: a pronounceable random name such as
    ``velomarquintasy`` passes, and a few real brands with digits in their names can trip it.
    """
    for label in domain.lower().split(".")[:-1]:
        if label.startswith("xn--"):  # punycode is judged by mail.links.punycode_host
            continue
        for piece in label.split("-"):
            if len(piece) < MIN_RANDOM_LABEL:
                continue
            if len(_LETTER_DIGIT_SWITCH.findall(piece)) >= 3 or _CONSONANT_RUN.search(piece):
                return label
    return None


# --- links --------------------------------------------------------------------------------


def analyze_links(msg: ParsedMessage) -> list[Finding]:
    """Lexical link checks. Links are never visited. One finding per host and reason, at most 50."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    from_domain = msg.from_.domain if msg.from_ else None
    for link in msg.links:
        for finding_id, host, finding in _link_findings(link, from_domain):
            if (finding_id, host) in seen:
                continue
            seen.add((finding_id, host))
            findings.append(finding)
            if len(findings) >= MAX_LINK_FINDINGS:
                return findings
    plain = _plain_http_finding(msg)
    if plain is not None:
        findings.append(plain)
    return findings


def _plain_http_finding(msg: ParsedMessage) -> Finding | None:
    """One finding when at least half of the message's web links use plain HTTP."""
    schemes = [scheme for link in msg.links if (scheme := _web_scheme(link.href)) is not None]
    plain = schemes.count("http")
    if not plain or plain * 2 < len(schemes):
        return None
    return _finding(
        "mail.links.plain_http",
        "low",
        "Links use plain HTTP instead of HTTPS",
        "Almost every legitimate sender links over HTTPS today. Unencrypted links are common in spam and throwaway "
        "campaigns, and anyone on the network path can change what they open.",
        f"{plain} of {len(schemes)} web links use http",
    )


def _web_scheme(href: str) -> str | None:
    try:
        parts = urlsplit(href.strip())
        scheme = parts.scheme.lower()
        return scheme if scheme in {"http", "https"} and parts.hostname else None
    except ValueError:
        return None


def _link_findings(link: Link, from_domain: str | None) -> list[tuple[str, str, Finding]]:
    compact = _WHITESPACE_AND_CONTROLS.sub("", link.href).lower()
    scheme = next((scheme for scheme in _SCRIPT_SCHEMES if compact.startswith(scheme)), None)
    if scheme is not None:
        return [
            (
                "mail.links.script_scheme",
                scheme,
                _finding(
                    "mail.links.script_scheme",
                    "high",
                    f"Link uses the {scheme} scheme",
                    "Clicking it runs code or opens content embedded in the message instead of going to a website. "
                    "Legitimate mail does not need this.",
                    f"scheme {scheme}",
                ),
            )
        ]
    try:
        parts = urlsplit(link.href.strip())
        hostname = parts.hostname
    except ValueError:
        return []
    if parts.scheme.lower() not in {"http", "https"} or not hostname:
        return []
    host, display = normalize_domain(hostname)
    hits: list[tuple[str, str, Finding]] = []

    def hit(finding_id: str, severity: Severity, title: str, explanation: str, evidence: str) -> None:
        hits.append((finding_id, host, _finding(finding_id, severity, title, explanation, evidence)))

    shown = _shown_host(link)
    own_domain_text = shown is not None and not aligned(shown, host) and from_domain and aligned(shown, from_domain)
    if own_domain_text and _looks_like_tracking(host, parts.path):
        hit(
            "mail.links.sender_domain_redirect",
            "low",
            "Link text shows the sender's own site but routes through a click tracker",
            "Newsletters route links through a click-tracking service this way. It matters only if the sender "
            "itself is in doubt, which the authentication findings cover.",
            f"text shows {shown}; link goes to {host}",
        )
    elif own_domain_text:
        hit(
            "mail.links.sender_domain_mismatch",
            "medium",
            "Link text shows the sender's own site but goes to another site",
            "The link does not look like click tracking. A compromised or forged sender can disguise a link "
            "this way; check the real destination before clicking.",
            f"text shows {shown}; link goes to {host}{parts.path[:80]}",
        )
    elif shown is not None and not aligned(shown, host):
        hit(
            "mail.links.text_href_mismatch",
            "high",
            "Link text shows one site but the link goes to another",
            "The visible text names a site that is neither the destination nor the sender's own domain. "
            "That is how phishing links disguise where they go.",
            f"text shows {shown}; link goes to {host}",
        )
    if parts.username is not None or "@" in parts.netloc:
        hit(
            "mail.links.userinfo",
            "high",
            "Link hides its real destination before an @",
            "Everything before '@' in a web address is a user name, not the site. 'https://bank.com@evil.example' "
            "opens evil.example.",
            f"real host {host}",
        )
    if _is_ip(host):
        hit(
            "mail.links.ip_host",
            "medium",
            "Link points to a raw IP address",
            "Legitimate organizations link to their domain names. Raw addresses are common in phishing kits.",
            f"host {host}",
        )
    if any(label.startswith("xn--") for label in host.split(".")):
        hit(
            "mail.links.punycode_host",
            "medium",
            "Link host uses internationalized (punycode) letters",
            "Letters from other alphabets can imitate a familiar domain, for example a Cyrillic letter that looks like a Latin 'a'.",
            f"host {host} (displayed as {display})",
        )
    generated = None if _is_ip(host) else random_label(host)
    if generated is not None:
        hit(
            "mail.links.random_host",
            "low",
            "Link goes to a machine-generated host name",
            "Random-looking host names such as 'q7vk2mx9r4tz8wn3' are typical of throwaway spam and phishing "
            "infrastructure. Some click trackers use them too, so this is a weak signal on its own.",
            f"host {host} (label {generated})",
        )
    if host in _SHORTENERS:
        hit(
            "mail.links.shortener",
            "low",
            "Link uses a URL shortener",
            "Shorteners hide the destination until the link is opened.",
            f"host {host}",
        )
    redirect = _redirect_target(parts)
    if redirect is not None:
        hit(
            "mail.links.redirect_param",
            "low",
            "Link carries another web address in a parameter",
            "Redirect parameters can bounce a trusted-looking link to another site.",
            f"host {host} redirects to {redirect}",
        )
    if parts.scheme.lower() == "http" and _INSECURE_LOGIN_PATH.search(parts.path.lower()):
        hit(
            "mail.links.insecure_login",
            "low",
            "Login or verification link without HTTPS",
            "A page that asks for a password over plain HTTP is either careless or not what it claims.",
            f"host {host}",
        )
    return hits


# Anchor text like ``www.dunholtquill.example`` counts as a shown host; plain words do not.
def _looks_like_tracking(host: str, path: str) -> bool:
    return any(_TRACKING_HOST_LABEL.match(label) for label in host.split(".")[:-2]) or bool(
        _TRACKING_PATH.search(path.lower())
    )


def _shown_host(link: Link) -> str | None:
    """The host an HTML anchor's visible text shows, when the text reads as a web address."""
    if link.source != "html" or not link.text or any(char.isspace() for char in link.text.strip()):
        return None
    match = _URLISH_TEXT.fullmatch(link.text.strip())
    if match is None:
        return None
    text = link.text.strip().lower()
    explicit = "://" in text or text.startswith("www.")
    return _looks_like_domain(match.group(1), explicit=explicit)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return _NUMERIC_HOST.fullmatch(host) is not None
    return True


def _redirect_target(parts: SplitResult) -> str | None:
    for _, value in parse_qsl(parts.query, keep_blank_values=False)[:100]:
        candidate = value.strip()
        if re.match(r"(?:https?:)?//", candidate, re.IGNORECASE):
            try:
                target = urlsplit(candidate).hostname
            except ValueError:
                continue
            if target:
                return normalize_domain(target)[0]
    return None


# --- attachments --------------------------------------------------------------------------

_HIGH_RISK_EXTENSIONS = _words(
    "exe scr com pif bat cmd js jse vbs vbe wsf wsh ps1 hta lnk iso img vhd vhdx msi jar one chm cpl reg"
)
_MEDIUM_RISK_EXTENSIONS = _words("html htm svg")
_DECOY_EXTENSIONS = _words("pdf doc docx xls xlsx ppt pptx txt rtf csv jpg jpeg png gif zip rar mp3 mp4")
_MACRO_EXTENSIONS = _words("docm dotm xlsm xltm xlam pptm potm ppsm")
_PROGRAM_EXTENSIONS = _words("exe dll scr com cpl sys ocx efi drv msi")
_MAGIC = (
    (b"MZ", "pe", "a Windows program"),
    (b"PK\x03\x04", "zip", "a ZIP-based file"),
    (b"%PDF", "pdf", "a PDF"),
    (b"\xd0\xcf\x11\xe0", "ole", "a legacy Office (OLE) file"),
)
# Which detected kind each extension is expected to have; extensions not listed are not judged.
_EXPECTED_KIND = {
    "pdf": "pdf",
    **dict.fromkeys(("doc", "xls", "ppt", "msg"), "ole"),
    **dict.fromkeys(("zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "odt", "ods", "odp", "epub"), "zip"),
    **dict.fromkeys(_PROGRAM_EXTENSIONS, "pe"),
    **dict.fromkeys(("txt", "csv", "jpg", "jpeg", "png", "gif", "rtf", "html", "htm"), "other"),
}
_MIME_KIND = {
    "application/pdf": "pdf",
    "application/zip": "zip",
    "application/x-zip-compressed": "zip",
    "application/msword": "ole",
    "application/vnd.ms-excel": "ole",
    "application/vnd.ms-powerpoint": "ole",
    "image/jpeg": "other",
    "image/png": "other",
    "text/plain": "other",
}


def analyze_attachments(msg: ParsedMessage) -> list[Finding]:
    """Type, name and archive checks on each attachment. Attachments are never opened or extracted."""
    findings: list[Finding] = []
    for attachment in msg.attachments:
        findings.extend(_attachment_findings(attachment))
    return findings


def _extensions(name: str | None) -> list[str]:
    if not name or "." not in name:
        return []
    return [part.lower().strip() for part in name.split(".")[1:]]


def _attachment_findings(attachment: Attachment) -> list[Finding]:
    name = attachment.filename
    label = name or f"unnamed {attachment.content_type} part"
    extensions = _extensions(name)
    ext = extensions[-1] if extensions else None
    kind, kind_label = next(
        ((kind, text) for magic, kind, text in _MAGIC if attachment.head.startswith(magic)), ("", "")
    )
    findings: list[Finding] = []

    def add(finding_id: str, severity: Severity, title: str, explanation: str, evidence: str) -> None:
        findings.append(_finding(finding_id, severity, title, explanation, evidence))

    if ext in _HIGH_RISK_EXTENSIONS or ext in _MEDIUM_RISK_EXTENSIONS:
        add(
            "mail.attachments.dangerous_type",
            "high" if ext in _HIGH_RISK_EXTENSIONS else "medium",
            f"Attachment type .{ext} can run code or open a fake page",
            "Programs, scripts, shortcuts, disk images and HTML or SVG files are common ways to deliver malware "
            "or a local phishing page by email.",
            label,
        )
    if len(extensions) >= 2 and extensions[-2] in _DECOY_EXTENSIONS and ext in _HIGH_RISK_EXTENSIONS:
        add(
            "mail.attachments.double_extension",
            "high",
            f"Name disguises a .{ext} file as .{extensions[-2]}",
            "Windows hides known extensions by default, so 'invoice.pdf.exe' shows as 'invoice.pdf'.",
            label,
        )
    expected = _EXPECTED_KIND.get(ext or "") or _MIME_KIND.get(attachment.content_type)
    if kind and expected and kind != expected:
        add(
            "mail.attachments.magic_mismatch",
            "high" if kind == "pe" else "medium",
            "Attachment content does not match its name or type",
            f"The file is declared as .{ext or attachment.content_type} but its first bytes are those of {kind_label}.",
            f"{label}; declared {attachment.content_type}; content is {kind_label}",
        )
    archive = attachment.archive
    members = archive.members if archive else ()
    if (
        ext in _MACRO_EXTENSIONS
        or (kind == "ole" and ext != "msg")
        or any(m.endswith("vbaProject.bin") for m in members)
    ):
        add(
            "mail.attachments.macro_office",
            "medium",
            "Office document that can carry macros",
            "Macro-enabled and legacy Office formats can run code when opened and editing is enabled.",
            label,
        )
    if archive is not None and archive.encrypted:
        add(
            "mail.attachments.encrypted_archive",
            "medium",
            "Password-protected archive",
            "Encrypted archives cannot be scanned by mail filters, which is why malware is often sent this way "
            "with the password in the message.",
            label,
        )
    risky = [
        member for member in members if (_extensions(member.rsplit("/", 1)[-1]) or [""])[-1] in _HIGH_RISK_EXTENSIONS
    ]
    if risky:
        add(
            "mail.attachments.archive_dangerous_member",
            "high",
            "Archive contains a program or script",
            "The archive listing includes files that run code when opened. Nothing was extracted.",
            f"{label}: {', '.join(risky[:5])}" + (f" and {len(risky) - 5} more" if len(risky) > 5 else ""),
        )
    return findings
