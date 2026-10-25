# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import io
import sys

import pytest
from mail_samples import BODY_SENTINEL, PASS_ALL, mark_encrypted, message, zip_bytes

from kestrix.core.errors import Reason, Rejected
from kestrix.mail import analyze, analyze_stream
from kestrix.mail.analyzers import MAX_LINK_FINDINGS, parse_authentication_results
from kestrix.mail.models import MailReport

MZ = b"MZ" + b"\x00" * 64

SPOOFED = "p\N{CYRILLIC SMALL LETTER A}ypal.com"


def ids(report: MailReport) -> list[str]:
    """Finding ids, without ``mail.auth.unverified``: every message read without a trusted authserv-id carries
    that info finding (its own tests are in ``test_mail_analyze.py``)."""
    return [finding.id for finding in report.findings if finding.id != "mail.auth.unverified"]


def severity_of(report: MailReport, finding_id: str) -> str:
    return next(finding.severity for finding in report.findings if finding.id == finding_id)


def link_report(html: str) -> MailReport:
    return analyze(message(html=html))


# --- verdicts -------------------------------------------------------------------------------


PROVIDER = frozenset({"mx.example.net"})  # the authserv-id that pass_all() stamps


def test_clean_message() -> None:
    report = analyze(message(), trusted_authserv_ids=PROVIDER)
    assert report.verdict == "clean"
    assert report.findings == []
    assert report.heuristic_score == 0
    assert report.from_address == "alice@example.com"
    assert report.subject == "Quarterly update"


def test_missing_authentication_results_is_insufficient_evidence() -> None:
    report = analyze(message(auth=()))
    assert report.verdict == "insufficient_evidence"
    assert ids(report) == ["mail.auth.missing"]
    assert report.findings[0].severity == "info"


def test_missing_auth_with_a_low_finding_is_clean() -> None:
    report = analyze(message(auth=(), headers=[("Return-Path", "<b@lists.example>")]))
    assert report.verdict == "clean"


def test_dmarc_fail_alone_is_suspicious() -> None:
    report = analyze(message(auth=("mx.example.net; spf=pass; dkim=pass header.d=example.com; dmarc=fail",)))
    assert ids(report) == ["mail.auth.dmarc_fail"]
    assert severity_of(report, "mail.auth.dmarc_fail") == "high"
    assert report.verdict == "suspicious"


def test_dmarc_fail_with_another_medium_is_malicious() -> None:
    report = analyze(message(auth=("mx.example.net; dmarc=fail",), headers=[("Reply-To", "pay@other.example")]))
    assert report.verdict == "malicious"


def test_any_content_high_is_malicious() -> None:
    report = analyze(message(attachments=[("setup.exe", MZ, "application/octet-stream")]))
    assert report.verdict == "malicious"


def test_heuristic_score_weights_are_capped() -> None:
    assert analyze(message(headers=[("Reply-To", "x@other.example")])).heuristic_score == 15
    many = [(f"f{i}.exe", MZ, "application/octet-stream") for i in range(5)]
    assert analyze(message(attachments=many)).heuristic_score == 100


def test_findings_are_ordered_by_severity() -> None:
    report = analyze(
        message(
            headers=[("Return-Path", "<b@lists.example>"), ("Reply-To", "x@other.example")],
            attachments=[("run.exe", MZ, "application/octet-stream")],
        )
    )
    assert [finding.severity for finding in report.findings] == ["high", "medium", "low", "info"]


# --- auth -----------------------------------------------------------------------------------


def test_authentication_results_parser_handles_comments_and_quotes() -> None:
    parsed = parse_authentication_results(
        'mx.Google.com (v1); dkim=pass (good sig) header.i=@example.com header.d="Example.com"; '
        'spf=softfail (domain of "a;b") smtp.mailfrom=x.example; dmarc=fail (p=REJECT) header.from=example.com'
    )
    assert parsed.authserv_id == "mx.google.com"
    assert [(r.method, r.result) for r in parsed.results] == [("dkim", "pass"), ("spf", "softfail"), ("dmarc", "fail")]
    assert parsed.results[0].properties["header.d"] == "example.com"


def test_authentication_results_none() -> None:
    assert parse_authentication_results("mx.example.net; none").results == ()


def test_spf_fail_and_softfail() -> None:
    fail = analyze(message(auth=("mx.example.net; spf=fail; dkim=pass header.d=example.com; dmarc=pass",)))
    assert ids(fail) == ["mail.auth.spf_fail"]
    assert fail.verdict == "suspicious"
    soft = analyze(message(auth=("mx.example.net; spf=softfail; dkim=pass header.d=example.com; dmarc=pass",)))
    assert ids(soft) == ["mail.auth.spf_softfail"]
    assert soft.verdict == "clean"


def test_dkim_fail() -> None:
    report = analyze(message(auth=("mx.example.net; spf=pass; dkim=fail header.d=example.com; dmarc=pass",)))
    assert ids(report) == ["mail.auth.dkim_fail"]
    assert severity_of(report, "mail.auth.dkim_fail") == "medium"


def test_one_passing_dkim_signature_outweighs_a_broken_one() -> None:
    auth = "mx.example.net; dkim=fail header.d=list.example; dkim=pass header.d=example.com; dmarc=pass"
    assert ids(analyze(message(auth=(auth,)))) == []


def test_no_dmarc_with_spf_failure() -> None:
    report = analyze(message(auth=("mx.example.net; spf=fail; dmarc=none",)))
    assert ids(report) == ["mail.auth.no_dmarc_with_failure", "mail.auth.spf_fail"]
    absent = analyze(message(auth=("mx.example.net; dkim=fail header.d=example.com",)))
    assert ids(absent) == ["mail.auth.no_dmarc_with_failure", "mail.auth.dkim_fail"]


def test_dkim_pass_for_unaligned_domain_is_low() -> None:
    auth = "mx.example.net; spf=pass; dkim=pass header.d=esp-mailer.example; dmarc=pass"
    report = analyze(message(auth=(auth,)))
    assert ids(report) == ["mail.auth.dkim_not_aligned"]
    assert report.verdict == "clean"
    aligned = "mx.example.net; dkim=pass header.d=mail.example.com; dmarc=pass"
    assert ids(analyze(message(auth=(aligned,)))) == []
    by_identity = "mx.example.net; dkim=pass header.i=@news.example.com; dmarc=pass"
    assert ids(analyze(message(auth=(by_identity,)))) == []  # header.i stands in when header.d is absent


def test_only_the_topmost_header_is_trusted_by_default() -> None:
    spoofed_lower = analyze(message(auth=(PASS_ALL, "attacker.example; dmarc=fail")))
    assert spoofed_lower.verdict == "clean"


def test_trusted_authserv_id_selects_a_lower_header() -> None:
    raw = message(auth=("attacker.example; spf=pass; dkim=pass; dmarc=pass", "mx.trusted.example; dmarc=fail"))
    assert analyze(raw).verdict == "clean"
    trusted = analyze(raw, trusted_authserv_ids=frozenset({"MX.trusted.example"}))
    assert ids(trusted) == ["mail.auth.dmarc_fail"]


def test_without_a_trusted_authserv_id_the_topmost_header_is_read_but_unverified() -> None:
    report = analyze(message())
    assert report.verdict == "clean"
    assert report.heuristic_score == 0
    assert [(f.id, f.severity) for f in report.findings] == [("mail.auth.unverified", "info")]
    assert report.findings[0].evidence == "topmost header, authserv-id mx.example.net: spf=pass dkim=pass dmarc=pass"
    assert "a pass does not lower" in report.findings[0].explanation
    empty = analyze(message(auth=("mx.example.net",)))
    assert [f.evidence for f in empty.findings] == ["topmost header, authserv-id mx.example.net: no results"]


def test_a_trusted_header_is_not_reported_as_unverified() -> None:
    assert "mail.auth.unverified" not in [f.id for f in analyze(message(), trusted_authserv_ids=PROVIDER).findings]


def test_a_failure_in_an_unverified_header_still_raises() -> None:
    """Raising is the safe direction: an unverified dmarc=fail is still reported, next to the unverified note."""
    report = analyze(message(auth=("mx.example.net; dmarc=fail header.from=example.com",)))
    assert [f.id for f in report.findings] == ["mail.auth.dmarc_fail", "mail.auth.unverified"]
    assert report.verdict == "suspicious"


def test_untrusted_headers_only_count_as_missing() -> None:
    report = analyze(message(), trusted_authserv_ids=frozenset({"mx.trusted.example"}))
    assert ids(report) == ["mail.auth.missing"]
    assert report.verdict == "insufficient_evidence"
    assert "trusted authserv-id" in report.findings[0].explanation


# --- sender ---------------------------------------------------------------------------------


def test_reply_to_mismatch() -> None:
    report = analyze(message(headers=[("Reply-To", "Accounts <pay@other.example>")]))
    assert ids(report) == ["mail.sender.reply_to_mismatch"]
    assert report.verdict == "suspicious"
    assert report.findings[0].evidence == "From domain example.com; Reply-To domain other.example"


def test_reply_to_in_the_same_organization_is_fine() -> None:
    assert ids(analyze(message(headers=[("Reply-To", "help@support.example.com")]))) == []


def test_return_path_mismatch_is_low() -> None:
    report = analyze(message(headers=[("Return-Path", "<bounce@lists.example>")]))
    assert ids(report) == ["mail.sender.return_path_mismatch"]
    assert severity_of(report, "mail.sender.return_path_mismatch") == "low"


@pytest.mark.parametrize("sender", ['"support@paypal.com" <x@evil.example>', '"PayPal.com" <x@evil.example>'])
def test_display_name_that_is_another_address_or_domain_is_malicious(sender: str) -> None:
    report = analyze(message(sender=sender))
    assert ids(report) == ["mail.sender.display_name_spoof"]
    assert severity_of(report, "mail.sender.display_name_spoof") == "high"
    assert report.verdict == "malicious"
    assert "paypal.com" in (report.findings[0].evidence or "")


def test_display_name_with_a_site_name_among_other_words_is_medium() -> None:
    """Genuine newsletters put their site name in the display name, so a bare domain flags without condemning."""
    report = analyze(message(sender='"PayPal.com Billing" <x@evil.example>'))
    assert ids(report) == ["mail.sender.display_name_spoof"]
    assert severity_of(report, "mail.sender.display_name_spoof") == "medium"
    assert report.verdict == "suspicious"
    assert "paypal.com" in (report.findings[0].evidence or "")


@pytest.mark.parametrize(
    "sender",
    [
        '"Alice (alice@example.com)" <alice@example.com>',
        '"Example.com Support" <help@mail.example.com>',
        '"Dr. Alice Smith Jr." <alice@example.com>',
        '"invoice.pdf" <alice@example.com>',
    ],
)
def test_display_names_that_are_not_spoofs(sender: str) -> None:
    assert ids(analyze(message(sender=sender))) == []


def test_display_name_using_a_protected_brand() -> None:
    protected = frozenset({"paypal.com"})
    spoof = analyze(message(sender='"PayPal Billing" <billing@evil.example>'), protected_domains=protected)
    assert ids(spoof) == ["mail.sender.display_name_brand"]
    assert spoof.verdict == "malicious"
    genuine = analyze(message(sender='"PayPal Billing" <billing@mail.paypal.com>'), protected_domains=protected)
    assert ids(genuine) == []
    assert ids(analyze(message(sender='"PayPal Billing" <billing@evil.example>'))) == []


# --- links ----------------------------------------------------------------------------------


def test_tracking_redirect_behind_the_senders_own_domain_is_low() -> None:
    """A newsletter showing its own site through a click tracker is not phishing on its own."""
    report = link_report('<a href="https://u1.ct.tracker.example/ls/click?upn=x">www.example.com</a>')
    assert ids(report) == ["mail.links.sender_domain_redirect"]
    assert report.verdict == "clean"


def test_senders_own_domain_text_on_a_non_tracking_link_is_medium() -> None:
    report = link_report('<a href="https://evil.example/login">www.example.com</a>')
    assert ids(report) == ["mail.links.sender_domain_mismatch"]
    assert report.verdict == "suspicious"


def test_link_text_showing_another_host() -> None:
    report = link_report('<a href="https://evil.example/login">www.paypal.com</a>')
    assert ids(report) == ["mail.links.text_href_mismatch"]
    assert report.findings[0].evidence == "text shows www.paypal.com; link goes to evil.example"
    assert report.verdict == "malicious"


@pytest.mark.parametrize(
    "html",
    [
        '<a href="https://example.com/a">www.example.com</a>',
        '<a href="https://click.example.com/a">https://example.com/</a>',
        '<a href="https://files.example/x">invoice.pdf</a>',
        '<a href="https://files.example/x">Read the report</a>',
        '<a href="mailto:a@example.com">a@example.com</a>',
    ],
)
def test_links_without_findings(html: str) -> None:
    assert ids(link_report(html)) == []


def test_userinfo_link() -> None:
    report = link_report('<a href="https://bank.com@evil.tld/">Your bank</a>')
    assert ids(report) == ["mail.links.userinfo"]
    assert report.findings[0].evidence == "real host evil.tld"


@pytest.mark.parametrize(
    "href",
    ["javascript:alert(1)", " Java\tScript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "vbscript:msgbox"],
)
def test_script_scheme_links(href: str) -> None:
    report = link_report(f'<a href="{href}">open</a>')
    assert ids(report) == ["mail.links.script_scheme"]
    assert severity_of(report, "mail.links.script_scheme") == "high"
    assert "alert" not in (report.findings[0].evidence or "")


def test_punycode_link() -> None:
    # The Cyrillic letter in a Latin label also raises the lookalike analyzer's mixed-script finding.
    report = link_report('<a href="https://xn--pypal-4ve.com/">PayPal</a>')
    assert ids(report) == ["mail.lookalike.mixed_script", "mail.links.punycode_host"]
    assert report.findings[1].evidence == f"host xn--pypal-4ve.com (displayed as {SPOOFED})"
    unicode_host = link_report(f'<a href="https://{SPOOFED}/">PayPal</a>')
    assert ids(unicode_host) == ["mail.lookalike.mixed_script", "mail.links.punycode_host"]


@pytest.mark.parametrize(
    ("href", "finding_id", "severity"),
    [
        ("https://192.168.10.5/x", "mail.links.ip_host", "info"),  # private
        ("http://3232235777/x", "mail.links.ip_host", "medium"),
        ("https://[2001:db8::1]/x", "mail.links.ip_host", "info"),  # documentation range: not global
        ("https://bit.ly/abc", "mail.links.shortener", "low"),
        ("https://example.com/r?next=https%3A%2F%2Fevil.example%2F", "mail.links.redirect_param", "low"),
        ("http://example.com/account/login", "mail.links.insecure_login", "low"),
    ],
)
def test_single_link_checks(href: str, finding_id: str, severity: str) -> None:
    report = link_report(f'<a href="{href}">here</a>')
    # A lone http:// link is also all of the message's web links over plain HTTP.
    plain = ["mail.links.plain_http"] if href.startswith("http:") else []
    assert ids(report) == [finding_id, *plain]
    assert severity_of(report, finding_id) == severity


def test_plain_text_links_are_checked() -> None:
    report = analyze(message(text="Reset at http://203.0.113.9/login now"))
    assert set(ids(report)) == {"mail.links.ip_host", "mail.links.insecure_login", "mail.links.plain_http"}


def test_link_findings_are_deduplicated_and_capped() -> None:
    same = link_report('<a href="https://bit.ly/a">x</a><a href="https://bit.ly/b">y</a>')
    assert ids(same) == ["mail.links.shortener"]
    many = "".join(f'<a href="https://10.0.{i // 250}.{i % 250}/">x</a>' for i in range(MAX_LINK_FINDINGS + 20))
    assert len([f for f in link_report(many).findings if f.analyzer == "links"]) == MAX_LINK_FINDINGS


# --- attachments ----------------------------------------------------------------------------


def test_double_extension() -> None:
    report = analyze(message(attachments=[("invoice.pdf.exe", MZ, "application/octet-stream")]))
    assert set(ids(report)) == {"mail.attachments.dangerous_type", "mail.attachments.double_extension"}
    assert report.verdict == "malicious"


def test_magic_mismatch_program_named_pdf() -> None:
    report = analyze(message(attachments=[("statement.pdf", MZ, "application/pdf")]))
    assert ids(report) == ["mail.attachments.magic_mismatch"]
    assert severity_of(report, "mail.attachments.magic_mismatch") == "high"
    assert report.verdict == "malicious"


def test_magic_mismatch_from_declared_type_is_medium() -> None:
    report = analyze(message(attachments=[("statement", zip_bytes(["a.txt"]), "application/pdf")]))
    assert ids(report) == ["mail.attachments.magic_mismatch"]
    assert severity_of(report, "mail.attachments.magic_mismatch") == "medium"


def test_matching_magic_is_fine() -> None:
    assert ids(analyze(message(attachments=[("report.pdf", b"%PDF-1.7\n", "application/pdf")]))) == []


def test_html_attachment_is_medium() -> None:
    report = analyze(message(attachments=[("login.html", b"<form></form>", "text/html")]))
    assert ids(report) == ["mail.attachments.dangerous_type"]
    assert severity_of(report, "mail.attachments.dangerous_type") == "medium"
    assert report.verdict == "suspicious"


def test_encrypted_zip() -> None:
    data = mark_encrypted(zip_bytes(["invoice.pdf"]))
    report = analyze(message(attachments=[("invoice.zip", data, "application/zip")]))
    assert ids(report) == ["mail.attachments.encrypted_archive"]
    assert report.verdict == "suspicious"


def test_zip_with_program_member() -> None:
    data = zip_bytes(["docs/readme.txt", "docs/invoice.pdf.exe"])
    report = analyze(message(attachments=[("invoice.zip", data, "application/zip")]))
    assert ids(report) == ["mail.attachments.archive_dangerous_member"]
    assert report.findings[0].evidence == "invoice.zip: docs/invoice.pdf.exe"
    assert report.verdict == "malicious"


def test_macro_office_documents() -> None:
    docm = analyze(message(attachments=[("q3.docm", zip_bytes(["word/document.xml"]), "application/octet-stream")]))
    assert ids(docm) == ["mail.attachments.macro_office"]
    ole = analyze(message(attachments=[("q3.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/msword")]))
    assert ids(ole) == ["mail.attachments.macro_office"]
    hidden = analyze(message(attachments=[("q3.docx", zip_bytes(["word/vbaProject.bin"]), "application/octet-stream")]))
    assert ids(hidden) == ["mail.attachments.macro_office"]
    assert docm.verdict == "suspicious"


# --- privacy and options --------------------------------------------------------------------


def test_report_never_contains_body_or_script_text() -> None:
    html = f"<p>{BODY_SENTINEL}</p><script>var s = 'SCRIPT-SENTINEL-9X';</script><a href='https://evil.example'>www.paypal.com</a>"
    report = analyze(
        message(
            html=html,
            headers=[("Reply-To", "x@other.example")],
            attachments=[("a.pdf.exe", MZ + b"ATTACHMENT-SENTINEL", "application/octet-stream")],
        )
    )
    dumped = report.model_dump_json()
    assert report.findings
    assert "ZEBRA-SENTINEL" not in dumped
    assert "SCRIPT-SENTINEL" not in dumped
    assert "ATTACHMENT-SENTINEL" not in dumped


def test_subject_is_truncated() -> None:
    report = analyze(message(headers=[("X-Pad", "1")]).replace(b"Subject: Quarterly update", b"Subject: " + b"s" * 500))
    assert report.subject == "s" * 200


def test_counts() -> None:
    report = analyze(
        message(html='<a href="https://example.com/">x</a>', attachments=[("a.txt", b"hi", "application/octet-stream")])
    )
    assert report.counts.links == 1
    assert report.counts.attachments == 1
    assert report.counts.parts == 5


@pytest.mark.parametrize(
    "kwargs",
    [
        {"protected_domains": frozenset({f"d{i}.example" for i in range(21)})},
        {"protected_domains": frozenset({"not a domain"})},
        {"protected_domains": frozenset({"https://paypal.com"})},
        {"trusted_authserv_ids": frozenset({f"mx{i}.example" for i in range(6)})},
        {"trusted_authserv_ids": frozenset({"bad id;"})},
    ],
)
def test_invalid_options_are_rejected(kwargs: dict[str, frozenset[str]]) -> None:
    with pytest.raises(Rejected) as exc:
        analyze(message(), **kwargs)
    assert exc.value.reason is Reason.INVALID_INPUT


def test_protected_domains_accept_idn() -> None:
    report = analyze(message(sender='"bücher" <a@evil.example>'), protected_domains=frozenset({"BÜCHER.de"}))
    assert ids(report) == []


def test_analyze_stream_refuses_oversized(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``kestrix.mail.analyze`` the attribute is the function; patch the module itself.
    monkeypatch.setattr(sys.modules["kestrix.mail.analyze"], "MAX_MESSAGE_BYTES", 100)
    with pytest.raises(Rejected) as exc:
        analyze_stream(io.BytesIO(message()))
    assert exc.value.reason is Reason.INPUT_TOO_LARGE


def test_undecodable_header_bytes_do_not_break_the_report() -> None:
    raw = b"From: a@b.example\r\nAuthentication-Results: mx.example; dmarc=fail header.from=b.ex\xff\xffample\r\nSubject: s\xff\r\n\r\nhi\r\n"
    report = analyze(raw)
    assert report.model_dump_json()  # lone surrogates were replaced, so the report serializes


@pytest.mark.parametrize(
    "raw",
    [
        b'From: a@b.example\r\nContent-Type: text/plain; charset="ut\x00f"\r\n\r\nhi\r\n',
        b"From: a@b.example\r\nContent-Type: application/x; name*=\r\n\r\nhi\r\n",
        b"From: a@b.example\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: a/b; x*0*=utf-8''a; x*1*=\x00\r\nContent-Disposition: attachment; filename*=\x00''a\r\n\r\nx\r\n--B--\r\n",
    ],
    ids=["nul-charset", "empty-parameter", "nul-parameter"],
)
def test_malformed_mime_parameters_are_rejected_or_tolerated_never_a_crash(raw: bytes) -> None:
    try:
        analyze(raw)
    except Rejected as exc:
        assert exc.reason is Reason.INVALID_INPUT
