# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rule changes of benchmark round 1: mailing-list Reply-To, weak-signal combination, spam offers, private
link addresses. Every message here is synthetic."""

import pytest
from mail_samples import message

from kestrix.mail import analyze
from kestrix.mail.models import MailReport
from kestrix.mail.parse import parse_message


def ids(report: MailReport) -> list[str]:
    return [finding.id for finding in report.findings]


def severity_of(report: MailReport, finding_id: str) -> str:
    return next(finding.severity for finding in report.findings if finding.id == finding_id)


# ----- mailing lists


def test_list_headers_are_parsed_and_bounded() -> None:
    msg = parse_message(
        message(
            headers=[
                ("List-Id", "Dev list <dev.lists.example.org>"),
                ("List-Post", "<mailto:dev@lists.example.org>"),
                ("List-Unsubscribe", "<mailto:dev-request@lists.example.org?subject=unsubscribe>"),
                ("Precedence", "bulk"),
            ]
        )
    )
    assert msg.list_id == "Dev list <dev.lists.example.org>"
    assert msg.list_post == "<mailto:dev@lists.example.org>"
    assert msg.list_unsubscribe is not None and msg.list_unsubscribe.startswith("<mailto:dev-request@")
    assert msg.precedence == "bulk"
    assert parse_message(message()).list_id is None
    assert len(parse_message(message(headers=[("List-Id", "<" + "a" * 900 + ".example.org>")])).list_id or "") == 300


def test_reply_to_the_list_itself_is_not_a_mismatch() -> None:
    report = analyze(
        message(
            headers=[
                ("Reply-To", "dev@lists.example.org"),
                ("List-Id", "<dev.lists.example.org>"),
            ]
        )
    )
    assert ids(report) == ["mail.sender.reply_to_mailing_list"]
    assert severity_of(report, "mail.sender.reply_to_mailing_list") == "info"
    assert report.verdict == "clean"
    assert (
        report.findings[0].evidence is not None and "Reply-To domain lists.example.org" in report.findings[0].evidence
    )


def test_list_post_names_the_list_domain() -> None:
    report = analyze(
        message(headers=[("Reply-To", "talk@talk.example.net"), ("List-Post", "<mailto:talk@talk.example.net>")])
    )
    assert ids(report) == ["mail.sender.reply_to_mailing_list"]


def test_reply_to_elsewhere_still_flags_on_list_mail() -> None:
    report = analyze(
        message(
            headers=[
                ("Reply-To", "billing@payments.example"),
                ("List-Id", "<dev.lists.example.org>"),
                ("List-Unsubscribe", "<mailto:dev-request@lists.example.org>"),
            ]
        )
    )
    assert ids(report) == ["mail.sender.reply_to_mismatch"]
    assert report.verdict == "suspicious"


def test_mixed_reply_to_keeps_the_foreign_domain_flagged() -> None:
    report = analyze(
        message(
            headers=[
                ("Reply-To", "dev@lists.example.org, boss@payments.example"),
                ("List-Id", "<dev.lists.example.org>"),
            ]
        )
    )
    assert ids(report) == ["mail.sender.reply_to_mismatch", "mail.sender.reply_to_mailing_list"]
    assert "payments.example" in (report.findings[0].evidence or "")


@pytest.mark.parametrize("precedence", ["bulk", "list"])
def test_precedence_alone_does_not_explain_a_reply_to(precedence: str) -> None:
    report = analyze(message(headers=[("Reply-To", "dev@lists.example.org"), ("Precedence", precedence)]))
    assert ids(report) == ["mail.sender.reply_to_mismatch"]


# ----- weak-signal combination

BOUNCE = ("Return-Path", "<bounce@lists.example>")
OLD_MAILER = ("X-Mailer", "Microsoft Outlook Express 6.00")
HTTP_LINK = '<p><a href="http://news.example.net/a">read</a></p>'
URGENT = "Please reply, this is urgent.\n"
THREE_LINKS = (
    '<p><a href="https://bit.ly/abc">a</a> <a href="https://news.example.net/go?u=https://other.example/x">b</a> '
    '<a href="https://q7vk2mx9r4tz8wn3.example/x">c</a></p>'
)


def test_three_low_findings_from_different_analyzers_make_a_message_suspicious() -> None:
    report = analyze(message(headers=[OLD_MAILER], text=URGENT, html=HTTP_LINK))
    assert sorted(ids(report)) == ["mail.intent.urgency", "mail.links.plain_http", "mail.sender.outdated_mailer"]
    assert report.verdict == "suspicious"
    assert report.verdict_reason == (
        "3 weak findings from different analyzers add up: "
        "mail.intent.urgency, mail.links.plain_http, mail.sender.outdated_mailer."
    )
    assert report.heuristic_score == 15


def test_low_findings_from_one_analyzer_do_not_combine() -> None:
    report = analyze(message(html=THREE_LINKS))
    assert {finding.analyzer for finding in report.findings} == {"links"}
    assert [f.severity for f in report.findings] == ["low", "low", "low"]
    assert report.verdict == "clean"
    assert report.verdict_reason is None


def test_two_low_findings_do_not_combine() -> None:
    report = analyze(message(headers=[OLD_MAILER], html=HTTP_LINK))
    assert report.verdict == "clean"


def test_a_routine_return_path_difference_does_not_count() -> None:
    report = analyze(message(headers=[BOUNCE, OLD_MAILER], html=HTTP_LINK))
    assert "mail.sender.return_path_mismatch" in ids(report)
    assert report.verdict == "clean"


def test_info_findings_do_not_count_toward_the_combination() -> None:
    report = analyze(
        message(
            headers=[OLD_MAILER, ("Reply-To", "dev@lists.example.org"), ("List-Id", "<dev.lists.example.org>")],
            html=HTTP_LINK,
        )
    )
    assert "mail.sender.reply_to_mailing_list" in ids(report)
    assert report.verdict == "clean"


def test_a_medium_finding_keeps_its_own_reason() -> None:
    report = analyze(message(headers=[OLD_MAILER, ("Reply-To", "pay@other.example")], text=URGENT, html=HTTP_LINK))
    assert report.verdict == "suspicious"
    assert report.verdict_reason is None


def test_without_authentication_results_the_combination_still_applies() -> None:
    report = analyze(message(auth=(), headers=[OLD_MAILER], text=URGENT, html=HTTP_LINK))
    assert "mail.auth.missing" in ids(report)
    assert report.verdict == "suspicious"


# ----- spam offers


@pytest.mark.parametrize(
    "text",
    [
        "Get a mortgage rates quote today.",
        "Click to lose weight fast with our pills.",
        "Are you tired of bad credit?",
        "Stay home: this home-based business pays.",
        "We send bulk e-mail to a million addresses.",
    ],
)
def test_spam_offer_phrases_are_medium(text: str) -> None:
    report = analyze(message(text=text))
    assert ids(report) == ["mail.intent.spam_offer"]
    assert severity_of(report, "mail.intent.spam_offer") == "medium"
    assert report.verdict == "suspicious"


@pytest.mark.parametrize(
    "text",
    [
        "Lunch at noon? The mortgage broker called back about the house.",
        "Our quarterly weight room schedule is attached.",
        "The loss of weight in the shipment was 3 kg.",
        "Good credit history helps with the loan.",
    ],
)
def test_ordinary_business_wording_is_not_a_spam_offer(text: str) -> None:
    assert ids(analyze(message(text=text))) == []
