# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Analyze one saved message: parse, run every analyzer, and derive a verdict.

Verdict rules, applied in order:

1. ``malicious``: any high finding from the sender, lookalike, links, attachments or intent
   analyzers, or a DMARC failure together with any other medium or high finding.
2. ``suspicious``: any other medium or high finding (a DMARC failure on its own lands here).
3. ``suspicious`` by weak-signal combination: at least 3 distinct low findings from at least 2 different
   analyzers. Info findings never count, and neither does ``mail.sender.return_path_mismatch``, which mailing
   lists and email service providers produce routinely (on dev it alone turned list mail into false alarms).
   Each counted finding is weak on its own, and a message that trips several unrelated checks is still worth
   a look; the report's ``verdict_reason`` names the findings.
4. ``insufficient_evidence``: no trusted authentication results and no other finding above info.
5. ``clean``: none of the above. It means no check fired, not that the message is safe.

The heuristic score is the sum of per-severity weights (high 35, medium 15, low 5, info 0),
capped at 100. It orders messages for attention; it is not a probability.
"""

from __future__ import annotations

import re
from typing import BinaryIO

from ..core.errors import Reason, Rejected
from .analyzers import analyze_attachments, analyze_auth, analyze_links, analyze_sender, dmarc_passed
from .intent import analyze_intent
from .lookalike import analyze_lookalike
from .models import MAX_SUBJECT_CHARS, Counts, Finding, MailReport, Verdict, by_severity
from .parse import MAX_MESSAGE_BYTES, normalize_domain, parse_message

MAX_PROTECTED_DOMAINS = 20
MAX_TRUSTED_AUTHSERV_IDS = 5
_WEIGHTS = {"high": 35, "medium": 15, "low": 5, "info": 0}
_HOSTNAME = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}")
_AUTHSERV_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?")
_CONTENT_ANALYZERS = frozenset({"sender", "lookalike", "links", "attachments", "intent"})
MIN_WEAK_FINDINGS = 3
MIN_WEAK_ANALYZERS = 2
# Low findings that never count toward the combination: routine on legitimate list and bulk mail.
_NOT_COMBINED = frozenset({"mail.sender.return_path_mismatch"})


def analyze(
    raw: bytes,
    *,
    protected_domains: frozenset[str] = frozenset(),
    trusted_authserv_ids: frozenset[str] = frozenset(),
) -> MailReport:
    """Analyze RFC 5322 bytes. Raises ``Rejected`` for invalid options, oversized or non-message input.

    ``protected_domains``: domains whose name in a display name, or whose look-alike in the From
    domain or a link host, is flagged.
    ``trusted_authserv_ids``: authserv-ids of your own provider; when set, the first
    Authentication-Results header stamped by one of them is read and trusted. When empty, the topmost
    header is read but unverified (``mail.auth.unverified``): its failures are reported, its pass lowers nothing.
    """
    protected = validate_protected_domains(protected_domains)
    trusted = validate_authserv_ids(trusted_authserv_ids)
    msg = parse_message(raw)
    findings = by_severity(
        [
            *analyze_auth(msg, trusted),
            *analyze_sender(msg, protected),
            *analyze_lookalike(msg, protected),
            *analyze_links(msg),
            *analyze_attachments(msg),
            *_authenticated_alerts(analyze_intent(msg), dmarc_passed(msg, trusted)),
        ]
    )
    result = verdict(findings)
    weak = weak_signal_ids(findings)
    return MailReport(
        sha256=msg.sha256,
        subject=msg.subject[:MAX_SUBJECT_CHARS] if msg.subject is not None else None,
        from_address=msg.from_.address if msg.from_ else None,
        verdict=result,
        verdict_reason=(
            f"{len(weak)} weak findings from different analyzers add up: {', '.join(weak)}."
            if result == "suspicious" and weak and not _serious(findings)
            else None
        ),
        heuristic_score=min(100, sum(_WEIGHTS[finding.severity] for finding in findings)),
        findings=findings,
        counts=Counts(
            parts=msg.part_count,
            links=len(msg.links),
            attachments=len(msg.attachments),
            text_truncated=msg.text_truncated,
            links_truncated=msg.links_truncated,
        ),
    )


def _authenticated_alerts(findings: list[Finding], authenticated: bool) -> list[Finding]:
    """Genuine account alerts ("unusual sign-in", "verify your account") come from the provider's
    own domain. When the header from a trusted authserv-id records DMARC pass, the From domain sent the
    message and a credential request alone is low: the risk that remains is the link, which the links
    and lookalike analyzers judge. An unverified header never gets here (``dmarc_passed``)."""
    if not authenticated:
        return findings
    return [
        finding.model_copy(
            update={
                "severity": "low",
                "explanation": finding.explanation
                + " DMARC passed in the header from your trusted authserv-id, so the From domain sent this message; "
                "check where the links go before signing in.",
            }
        )
        if finding.id == "mail.intent.credential_request" and finding.severity == "medium"
        else finding
        for finding in findings
    ]


def analyze_stream(
    stream: BinaryIO,
    *,
    protected_domains: frozenset[str] = frozenset(),
    trusted_authserv_ids: frozenset[str] = frozenset(),
) -> MailReport:
    """Read at most one byte past the size limit from ``stream`` and analyze it."""
    raw = stream.read(MAX_MESSAGE_BYTES + 1)
    if len(raw) > MAX_MESSAGE_BYTES:
        raise Rejected(Reason.INPUT_TOO_LARGE, f"message is larger than the {MAX_MESSAGE_BYTES:,} byte limit")
    return analyze(raw, protected_domains=protected_domains, trusted_authserv_ids=trusted_authserv_ids)


def _serious(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.severity in {"medium", "high"}]


def weak_signal_ids(findings: list[Finding]) -> list[str]:
    """Ids of the distinct low findings when they are numerous and varied enough to combine, else none."""
    low = {
        finding.id: finding.analyzer
        for finding in findings
        if finding.severity == "low" and finding.id not in _NOT_COMBINED
    }
    if len(low) >= MIN_WEAK_FINDINGS and len(set(low.values())) >= MIN_WEAK_ANALYZERS:
        return sorted(low)
    return []


def verdict(findings: list[Finding]) -> Verdict:
    """Apply the verdict rules in the module docstring."""
    serious = _serious(findings)
    dmarc_fail = any(finding.id == "mail.auth.dmarc_fail" for finding in findings)
    if any(finding.severity == "high" and finding.analyzer in _CONTENT_ANALYZERS for finding in findings) or (
        dmarc_fail and len(serious) > 1
    ):
        return "malicious"
    if serious or weak_signal_ids(findings):
        return "suspicious"
    auth_missing = any(finding.id == "mail.auth.missing" for finding in findings)
    if auth_missing and not any(finding.severity != "info" for finding in findings):
        return "insufficient_evidence"
    return "clean"


def validate_protected_domains(domains: frozenset[str]) -> frozenset[str]:
    """Normalize to lower-case ASCII host names; at most 20."""
    if len(domains) > MAX_PROTECTED_DOMAINS:
        raise Rejected(Reason.INVALID_INPUT, f"at most {MAX_PROTECTED_DOMAINS} protected domains are allowed")
    normalized = set()
    for domain in domains:
        host = normalize_domain(domain)[0]
        if not _HOSTNAME.fullmatch(host):
            raise Rejected(Reason.INVALID_INPUT, f"protected domain {domain[:100]!r} is not a valid host name")
        normalized.add(host)
    return frozenset(normalized)


def validate_authserv_ids(ids: frozenset[str]) -> frozenset[str]:
    """Normalize to lower case; at most 5, each a host-like token."""
    if len(ids) > MAX_TRUSTED_AUTHSERV_IDS:
        raise Rejected(Reason.INVALID_INPUT, f"at most {MAX_TRUSTED_AUTHSERV_IDS} trusted authserv-ids are allowed")
    normalized = frozenset(value.strip().lower() for value in ids)
    for value in normalized:
        if not _AUTHSERV_ID.fullmatch(value):
            raise Rejected(Reason.INVALID_INPUT, f"authserv-id {value[:100]!r} is not valid")
    return normalized
