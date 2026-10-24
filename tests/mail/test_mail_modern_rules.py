# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Rule changes measured on modern list mail: URL-rewriting gateways, private link addresses and list Reply-To at
free-mail providers. Every message here is synthetic."""

import pytest
from mail_samples import message

from kestrix.mail import analyze
from kestrix.mail.models import MailReport

LIST = [("List-Id", "Dev list <dev.lists.example.org>")]


def find(report: MailReport, finding_id: str) -> list[str]:
    return [f.severity for f in report.findings if f.id == finding_id]


def link(href: str, text: str) -> str:
    return f'<p><a href="{href}">{text}</a></p>'


# ----- P1: URL-rewriting gateways


@pytest.mark.parametrize(
    "gateway",
    [
        "https://eur01.safelinks.protection.outlook.com/",
        "https://urldefense.com/v1/url",
        "https://urldefense.proofpoint.com/v2/url",
        "https://protect-us.mimecast.com/s/x",
        "https://us-smtp.mimecastprotect.com/x",
        "https://linkprotect.cudasvc.com/url",
        "https://secure-web.cisco.com/url",
    ],
)
def test_gateway_link_is_judged_by_wrapped_address(gateway: str) -> None:
    same = analyze(message(html=link(f"{gateway}?url=https%3A%2F%2Fwww.docs.example%2Fa&data=1", "www.docs.example")))
    assert find(same, "mail.links.text_href_mismatch") == []
    other = analyze(message(html=link(f"{gateway}?url=https%3A%2F%2Fevil.example%2Fa", "www.docs.example")))
    assert find(other, "mail.links.text_href_mismatch") == ["high"]


def test_gateway_link_without_readable_address_skips_text_comparison() -> None:
    report = analyze(
        message(html=link("https://urldefense.com/v3/__https://www.docs.example/a__;!!x$", "www.docs.example"))
    )
    assert find(report, "mail.links.text_href_mismatch") == []


def test_wrapped_ip_address_is_still_checked() -> None:
    report = analyze(
        message(html=link("https://nam02.safelinks.protection.outlook.com/?url=http%3A%2F%2F8.8.8.8%2F", "Open"))
    )
    assert find(report, "mail.links.ip_host") == ["medium"]


@pytest.mark.parametrize(
    "host",
    [
        "eur01.not-safelinks.example",  # regional prefix alone is not a gateway
        "safelinks.protection.outlook.com.evil.example",
        "protect.mimecast.com.evil.example",
        "mimecastprotect.com.evil.example",
        "www.mimecast.com",
        "us-phishalarm.proofpoint.com",  # Proofpoint's reporting button, not a link rewriter
        "linkprotect.cudasvc.com.evil.example",
    ],
)
def test_lookalike_gateway_hosts_are_not_unwrapped(host: str) -> None:
    report = analyze(message(html=link(f"https://{host}/?url=https%3A%2F%2Fwww.docs.example%2F", "www.docs.example")))
    assert find(report, "mail.links.text_href_mismatch") == ["high"]


# ----- P3: private link addresses


@pytest.mark.parametrize("host", ["192.168.1.20", "10.0.0.5", "127.0.0.1", "169.254.1.1", "[::1]", "[2001:db8::1]"])
def test_unroutable_ip_link_is_info(host: str) -> None:
    assert find(analyze(message(html=link(f"http://{host}/status", "Open"))), "mail.links.ip_host") == ["info"]


@pytest.mark.parametrize("host", ["8.8.8.8", "[2606:4700::1111]", "3232235777"])
def test_public_or_numeric_host_stays_medium(host: str) -> None:
    # 3232235777 is the decimal form of 192.168.1.1 but is not parsed as an address, so it keeps medium.
    assert find(analyze(message(html=link(f"http://{host}/status", "Open"))), "mail.links.ip_host") == ["medium"]


# ----- P6: list Reply-To at a free-mail provider


def test_list_mail_reply_to_freemail_is_low() -> None:
    report = analyze(message(headers=[*LIST, ("Reply-To", "Dev Person <dev.person@gmail.com>")]))
    assert find(report, "mail.sender.reply_to_mismatch") == ["low"]


def test_freemail_reply_to_without_list_headers_stays_medium() -> None:
    report = analyze(message(headers=[("Reply-To", "dev.person@gmail.com")]))
    assert find(report, "mail.sender.reply_to_mismatch") == ["medium"]


def test_list_mail_reply_to_other_domain_stays_medium() -> None:
    report = analyze(message(headers=[*LIST, ("Reply-To", "a@gmail.com, pay@other.example")]))
    assert find(report, "mail.sender.reply_to_mismatch") == ["medium"]
