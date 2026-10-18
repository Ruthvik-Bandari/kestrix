# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import pytest
from mail_samples import message

from kestrix.mail import analyze
from kestrix.mail.lookalike import MAX_LOOKALIKE_FINDINGS, edit_distance, skeleton
from kestrix.mail.models import MailReport

PROTECTED = frozenset({"paypal.com", "microsoft.com"})
CYRILLIC_A = "\N{CYRILLIC SMALL LETTER A}"
AUTH = ("mx.example.net; spf=pass; dkim=pass header.d=sender.example; dmarc=pass",)


def lookalike(report: MailReport) -> list[tuple[str, str]]:
    return [(f.id, f.severity) for f in report.findings if f.analyzer == "lookalike"]


def from_report(domain: str, protected: frozenset[str] = PROTECTED) -> MailReport:
    return analyze(message(sender=f"Billing <billing@{domain}>", auth=AUTH), protected_domains=protected)


def link_report(host: str, protected: frozenset[str] = PROTECTED) -> MailReport:
    return analyze(message(html=f'<a href="https://{host}/login">Open</a>'), protected_domains=protected)


# --- folding helpers ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "folded"),
    [
        (f"p{CYRILLIC_A}ypal", "paypal"),
        ("paypa1", "paypal"),
        ("rnicrosoft", "microsoft"),
        ("vvells", "wells"),
        ("c1oudflare", "doudflare"),  # both sides fold the same way, so "cl" -> "d" is symmetric
        ("\N{FULLWIDTH LATIN SMALL LETTER P}aypal", "paypal"),
        ("\N{GREEK SMALL LETTER OMICRON}ffice", "office"),
    ],
)
def test_skeleton(text: str, folded: str) -> None:
    assert skeleton(text) == folded


@pytest.mark.parametrize(
    ("a", "b", "limit", "expected"),
    [
        ("microsoft", "microsoft", 1, 0),
        ("micrsoft", "microsoft", 1, 1),
        ("micorsoft", "microsoft", 1, 1),  # a transposition is one edit
        ("mircosfot", "microsoft", 2, 2),  # two transpositions
        ("macrohard", "microsoft", 2, 3),  # beyond the limit reports limit + 1
        ("paypal", "pay", 1, 2),
    ],
)
def test_edit_distance(a: str, b: str, limit: int, expected: int) -> None:
    assert edit_distance(a, b, limit) == expected


# --- genuine hosts --------------------------------------------------------------------------


@pytest.mark.parametrize("domain", ["paypal.com", "mail.paypal.com", "e.microsoft.com", "paypal.de", "example.com"])
def test_genuine_and_unrelated_from_domains_do_not_fire(domain: str) -> None:
    assert lookalike(from_report(domain)) == []


@pytest.mark.parametrize("host", ["paypal.com", "www.paypal.com", "login.microsoftonline.com", "example.org"])
def test_genuine_and_unrelated_link_hosts_do_not_fire(host: str) -> None:
    assert lookalike(link_report(host)) == []


def test_nothing_but_mixed_script_without_protected_domains() -> None:
    assert lookalike(from_report("paypa1.com", frozenset())) == []
    assert lookalike(link_report("paypal.com.secure-login.example", frozenset())) == []


# --- homograph and mixed script -------------------------------------------------------------


def test_cyrillic_homograph_from_domain() -> None:
    report = from_report(f"p{CYRILLIC_A}ypal.com")
    assert lookalike(report) == [("mail.lookalike.homograph", "high"), ("mail.lookalike.mixed_script", "medium")]
    assert report.verdict == "malicious"
    homograph = report.findings[0]
    assert homograph.evidence == f"from domain p{CYRILLIC_A}ypal.com (xn--pypal-4ve.com) vs protected domain paypal.com"


def test_homograph_link_host_written_as_punycode() -> None:
    report = link_report("xn--pypal-4ve.com")
    assert ("mail.lookalike.homograph", "high") in lookalike(report)
    assert report.verdict == "malicious"


def test_all_cyrillic_homograph_is_not_mixed_script() -> None:
    # A name written entirely in Cyrillic look-alikes still folds to the protected label.
    host = "\N{CYRILLIC SMALL LETTER ER}\N{CYRILLIC SMALL LETTER A}\N{CYRILLIC SMALL LETTER U}.com"
    assert lookalike(from_report(host, frozenset({"pay.com"}))) == [("mail.lookalike.homograph", "high")]


def test_mixed_script_fires_without_protected_domains() -> None:
    report = link_report(f"secure-b{CYRILLIC_A}nk.example", frozenset())
    assert lookalike(report) == [("mail.lookalike.mixed_script", "medium")]
    assert report.verdict == "suspicious"


def test_non_latin_single_script_and_accented_latin_are_not_mixed() -> None:
    assert lookalike(link_report("\N{CYRILLIC SMALL LETTER ER}\N{CYRILLIC SMALL LETTER U}.example", frozenset())) == []
    assert lookalike(link_report("bücher.example", frozenset())) == []


# --- ASCII look-alikes ----------------------------------------------------------------------


@pytest.mark.parametrize("domain", ["paypa1.com", "rnicrosoft.com", "micrsoft.com", "rnicrosoft.net", "paypall.com"])
def test_ascii_lookalike_from_domain_is_high(domain: str) -> None:
    report = from_report(domain)
    assert lookalike(report) == [("mail.lookalike.domain", "high")]
    assert report.verdict == "malicious"


def test_ascii_lookalike_link_host_is_medium() -> None:
    report = link_report("secure.paypa1.com")
    assert lookalike(report) == [("mail.lookalike.domain", "medium")]
    assert report.findings[0].evidence == "link host secure.paypa1.com vs protected domain paypal.com"
    assert report.verdict == "suspicious"


def test_edit_distance_budget_depends_on_length() -> None:
    long_protected = frozenset({"cloudflare.com"})  # 10 characters: two edits allowed
    assert lookalike(from_report("clowdflair.com", long_protected)) == []
    assert lookalike(from_report("cloudflar.com", long_protected)) == [("mail.lookalike.domain", "high")]
    assert lookalike(from_report("clodflar.com", long_protected)) == [("mail.lookalike.domain", "high")]
    short_protected = frozenset({"ups.com"})  # under 5 characters: folding only, no edits
    assert lookalike(from_report("upss.com", short_protected)) == []
    assert lookalike(from_report("up5.com", short_protected)) == [("mail.lookalike.domain", "high")]


# --- brand inside another host --------------------------------------------------------------


@pytest.mark.parametrize(
    "host", ["paypal.com.account-verify.example", "paypal-secure.example", "login.paypal.evil.example"]
)
def test_brand_in_host(host: str) -> None:
    report = link_report(host)
    assert lookalike(report) == [("mail.lookalike.brand_in_host", "medium")]


def test_brand_in_from_domain() -> None:
    report = from_report("paypal.com.secure-login.example")
    assert lookalike(report) == [("mail.lookalike.brand_in_host", "medium")]
    assert report.verdict == "suspicious"


# --- dedupe and cap -------------------------------------------------------------------------


def test_findings_are_deduplicated_per_host_and_capped() -> None:
    same = analyze(
        message(html='<a href="https://paypa1.com/a">x</a><a href="https://paypa1.com/b">y</a>'),
        protected_domains=PROTECTED,
    )
    assert lookalike(same) == [("mail.lookalike.domain", "medium")]
    many = "".join(f'<a href="https://paypal-{i}.example/">x</a>' for i in range(MAX_LOOKALIKE_FINDINGS + 10))
    report = analyze(message(html=many), protected_domains=PROTECTED)
    assert len(lookalike(report)) == MAX_LOOKALIKE_FINDINGS


def test_from_and_link_on_the_same_host_report_once() -> None:
    raw = message(sender="Billing <billing@paypa1.com>", auth=AUTH, html='<a href="https://paypa1.com/">Pay</a>')
    report = analyze(raw, protected_domains=PROTECTED)
    assert lookalike(report) == [("mail.lookalike.domain", "high")]


def test_ip_link_hosts_are_ignored() -> None:
    assert lookalike(link_report("192.0.2.10")) == []
