# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: RUF001  # Russian sample text is meant to contain Cyrillic letters
"""Spam signals: machine-generated hosts, plain-HTTP links, outdated mailers, gambling and prize offers,
and invisible-character padding. Every message here is synthetic."""

import pytest
from mail_samples import BODY_SENTINEL, message

from kestrix.mail import analyze
from kestrix.mail.analyzers import random_label
from kestrix.mail.models import MailReport

ZWNJ = "‌"


def ids(report: MailReport) -> list[str]:
    return [finding.id for finding in report.findings]


def evidence(report: MailReport, finding_id: str) -> str | None:
    return next(finding.evidence for finding in report.findings if finding.id == finding_id)


# ----- machine-generated names


@pytest.mark.parametrize(
    ("domain", "label"),
    [
        ("q7vk2mx9r4tz8wn3.velomarquintasy.example", "q7vk2mx9r4tz8wn3"),
        ("k7f3q9zt2.example", "k7f3q9zt2"),
        ("go.xkqwtzbnmr.example", "xkqwtzbnmr"),
        ("promo-a1b2c3d4.example", "promo-a1b2c3d4"),
    ],
)
def test_random_labels_are_recognized(domain: str, label: str) -> None:
    assert random_label(domain) == label


@pytest.mark.parametrize(
    "domain",
    [
        "www.example.com",
        "news.example-shop.com",
        "strengths.example",  # five consonants in a row, not six
        "u1234567.ct.sendgrid.net",  # one letter-digit switch
        "web2print.example",
        "velomarquintasy.example",  # pronounceable random names pass: a documented limit
        "xn--pypal-4ve.com",  # punycode is judged elsewhere
        "covid19tracker.example",  # digits once in a word
    ],
)
def test_ordinary_labels_are_not_random(domain: str) -> None:
    assert random_label(domain) is None


def test_link_to_a_generated_host_is_low() -> None:
    report = analyze(message(html='<a href="https://q7vk2mx9r4tz8wn3.velomarquintasy.example/x">Open</a>'))
    assert ids(report) == ["mail.links.random_host"]
    assert report.findings[0].severity == "low"
    assert evidence(report, "mail.links.random_host") == (
        "host q7vk2mx9r4tz8wn3.velomarquintasy.example (label q7vk2mx9r4tz8wn3)"
    )
    assert report.verdict == "clean"


def test_ip_hosts_are_not_also_called_generated() -> None:
    report = analyze(message(html='<a href="https://192.168.10.5/x">here</a>'))
    assert "mail.links.random_host" not in ids(report)


def test_sender_on_a_generated_domain_is_low() -> None:
    report = analyze(message(sender="Promo <deals@k7f3q9zt2.example>"))
    assert ids(report) == ["mail.sender.random_domain"]
    assert evidence(report, "mail.sender.random_domain") == "From domain k7f3q9zt2.example (label k7f3q9zt2)"


# ----- plain-HTTP links


def test_mostly_plain_http_links_raise_one_finding() -> None:
    html = (
        '<a href="http://shop.example.com/a">A</a> <a href="http://shop.example.com/b">B</a>'
        ' <a href="https://shop.example.com/c">C</a>'
    )
    report = analyze(message(html=html))
    assert ids(report) == ["mail.links.plain_http"]
    assert evidence(report, "mail.links.plain_http") == "2 of 3 web links use http"


def test_mostly_https_links_do_not_raise_it() -> None:
    html = (
        '<a href="http://shop.example.com/a">A</a> <a href="https://shop.example.com/b">B</a>'
        ' <a href="https://shop.example.com/c">C</a>'
    )
    assert "mail.links.plain_http" not in ids(analyze(message(html=html)))
    assert "mail.links.plain_http" not in ids(analyze(message(html='<a href="mailto:a@example.com">mail</a>')))


# ----- outdated mail programs


@pytest.mark.parametrize(
    "mailer", ["Microsoft Outlook Express 6.00.2900.5931", "Microsoft Internet Mail 4.70", "Eudora 7.1"]
)
def test_outdated_mailer_is_low(mailer: str) -> None:
    report = analyze(message(headers=[("X-Mailer", mailer)]))
    assert ids(report) == ["mail.sender.outdated_mailer"]
    assert evidence(report, "mail.sender.outdated_mailer") == f"X-Mailer {mailer}"


@pytest.mark.parametrize("mailer", ["Microsoft Outlook 16.0", "Apple Mail (2.3774)", "Thunderbird 128.3"])
def test_current_mailers_are_fine(mailer: str) -> None:
    assert ids(analyze(message(headers=[("X-Mailer", mailer)]))) == []


# ----- gambling and prize offers


@pytest.mark.parametrize(
    ("text", "cue"),
    [
        ("Claim 50 free spins today", "free spins"),
        ("Your no-deposit bonus is waiting", "no-deposit bonus"),
        ("Up to 150 FS and cashback", "150 FS"),
        ("Unlock your casino bonus", "casino bonus"),
        ("Начни с бесплатных спинов", "бесплатных спинов"),
        ("100 фриспинов каждую неделю", "фриспинов"),
        ("Играй без депозита", "без депозита"),
        ("Бонус на первый депозит 200%", "Бонус на первый депозит"),
    ],
)
def test_gambling_offers_are_medium(text: str, cue: str) -> None:
    report = analyze(message(text=text))
    assert ids(report) == ["mail.intent.gambling_offer"]
    assert evidence(report, "mail.intent.gambling_offer") == cue
    assert report.verdict == "suspicious"


@pytest.mark.parametrize(
    "text",
    [
        "No deposit required to book your room.",
        "Earn a welcome bonus with our savings account.",
        "The pulse lasted 100 fs in the experiment.",
        "Casino night raises money for the school.",
    ],
)
def test_ordinary_mail_is_not_a_gambling_offer(text: str) -> None:
    assert "mail.intent.gambling_offer" not in ids(analyze(message(text=text)))


@pytest.mark.parametrize(
    ("text", "cue"),
    [
        ("Congratulations, you have won a cruise", "you have won"),
        ("Claim your prize before Friday", "Claim your prize"),
        ("You are our lottery winner", "lottery winner"),
        ("Поздравляем, вы выиграли iPhone", "вы выиграли"),
        ("Заберите ваш приз сегодня", "Заберите ваш приз"),
    ],
)
def test_prize_claims_are_medium(text: str, cue: str) -> None:
    report = analyze(message(text=text))
    assert ids(report) == ["mail.intent.prize_claim"]
    assert evidence(report, "mail.intent.prize_claim") == cue


def test_you_wont_believe_is_not_a_prize() -> None:
    assert ids(analyze(message(text="You won't believe these prices."))) == []


# ----- invisible characters


def test_invisible_padding_is_low_with_a_count() -> None:
    report = analyze(message(text="Weekly deals" + ZWNJ * 30 + f"\n{BODY_SENTINEL}\n"))
    assert ids(report) == ["mail.intent.hidden_text"]
    assert evidence(report, "mail.intent.hidden_text") == "30 invisible characters, mostly U+200C"
    assert BODY_SENTINEL not in report.model_dump_json()


def test_a_few_invisible_characters_are_ignored() -> None:
    assert ids(analyze(message(text="Weekly deals" + ZWNJ * 5))) == []


# ----- together


def test_casino_spam_is_suspicious_not_malicious() -> None:
    """The shape of a real campaign, rebuilt from scratch: Russian casino promo, generated hosts, http links,
    an Outlook Express X-Mailer and a padded preview line. Authentication passes because the spammer owns the
    domain, so nothing here is malicious; it is spam to be careful with."""
    sender = "Менеджер <promo@velomarquintasy.example>"
    html = (
        "<p>До 150 FS и кэшбэк каждую неделю" + ZWNJ * 40 + "</p>"
        '<a href="http://q7vk2mx9r4tz8wn3.velomarquintasy.example/r?t=1">Открыть набор</a>'
        '<a href="http://k7f3q9zt2.velomarquintasy.example/u">Отписаться</a>'
    )
    report = analyze(
        message(
            sender=sender,
            headers=[("X-Mailer", "Microsoft Outlook Express 6.00.2900.5931")],
            text="До 150 FS без депозита",
            html=html,
        )
    )
    assert report.verdict == "suspicious"
    assert set(ids(report)) == {
        "mail.intent.gambling_offer",
        "mail.intent.hidden_text",
        "mail.sender.outdated_mailer",
        "mail.links.random_host",
        "mail.links.plain_http",
    }
    assert ids(report).count("mail.links.random_host") == 2
