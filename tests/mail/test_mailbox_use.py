# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""List, search, check one message, error outcomes and the network rules of the mailbox connector."""

import socket

import httpx
import pytest
from mail_samples import BODY_SENTINEL, message
from mailbox_support import Msg, connect

from kestrix.core.errors import RateLimited, Reason, Rejected
from kestrix.mail.mailbox import MailboxService, providers
from kestrix.mail.mailbox.http import ALLOWED_HOSTS, MailboxHttp
from kestrix.mail.mailbox.models import MAX_SNIPPET_CHARS
from kestrix.mail.parse import MAX_MESSAGE_BYTES

BIDI = chr(0x202E)  # right-to-left override


@pytest.fixture(params=["gmail", "outlook"])
def connected(request: pytest.FixtureRequest, service: MailboxService, fake_mail):
    connect(service, fake_mail, request.param)
    return request.param


def test_search_rows_carry_only_the_pick_fields(connected: str, service: MailboxService, fake_mail) -> None:
    rows = fake_mail.gmail if connected == "gmail" else fake_mail.graph
    rows[0].snippet = "x" * 500 + BIDI
    rows[0].subject = "S" * 500
    result = service.search(connected, "", "inbox", None, 20)
    assert len(result.messages) == 1
    row = result.messages[0]
    assert set(row.model_dump()) == {"id", "sender", "subject", "date", "snippet"}
    assert len(row.snippet) <= MAX_SNIPPET_CHARS and len(row.subject) <= 200 and len(row.sender) <= 200
    assert "alice@example.com" in row.sender and row.date and row.date.startswith("2026-")
    assert BIDI not in row.snippet
    assert BODY_SENTINEL not in result.model_dump_json()  # only the preview field is ever read


def test_gmail_snippet_entities_are_decoded(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "gmail")
    assert service.search("gmail", "", "inbox", None, 20).messages[0].snippet == "Hello 'Bob', here are the numbers"


def test_search_text_folders_and_pages(connected: str, service: MailboxService, fake_mail) -> None:
    rows = fake_mail.gmail if connected == "gmail" else fake_mail.graph
    id_prefix = "g" if connected == "gmail" else "m-"
    rows[:] = [
        Msg(
            f"{id_prefix}{i}",
            message(),
            subject=f"Invoice {i}" if i % 2 else f"Lunch {i}",
            folder="inbox" if i < 5 else "junk",
        )
        for i in range(8)
    ]
    found = service.search(connected, "invoice", "all", None, 20)
    assert {m.subject for m in found.messages} == {"Invoice 1", "Invoice 3", "Invoice 5", "Invoice 7"}
    junk = service.search(connected, "", "junk", None, 20)
    assert [m.id for m in junk.messages] == [f"{id_prefix}{i}" for i in (5, 6, 7)]
    first = service.search(connected, "", "inbox", None, 2)
    second = service.search(connected, "", "inbox", first.next_page_token, 2)
    assert [m.id for m in first.messages] == [f"{id_prefix}0", f"{id_prefix}1"]
    assert [m.id for m in second.messages] == [f"{id_prefix}2", f"{id_prefix}3"]


def test_search_inputs_are_bounded(connected: str, service: MailboxService) -> None:
    with pytest.raises(Rejected):
        service.search(connected, "q" * 201, "inbox", None, 20)
    with pytest.raises(Rejected):
        service.search(connected, "", "inbox", None, 51)


def test_graph_search_text_is_quoted_not_injected(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "outlook")
    service.search("outlook", 'a" OR from:x \\', "all", None, 5)
    request = fake_mail.requests[-1]
    assert request.url.params["$search"] == '"a\\" OR from:x \\\\"'


def test_graph_next_link_must_stay_on_graph(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "outlook")
    import base64

    for link in (
        "https://evil.example/v1.0/me/messages",
        "https://graph.microsoft.com.evil.example/v1.0/me/",
        "http://graph.microsoft.com/v1.0/me/x",
    ):
        token = base64.urlsafe_b64encode(link.encode()).decode().rstrip("=")
        with pytest.raises(Rejected):
            service.search("outlook", "", "inbox", token, 5)
    with pytest.raises(Rejected):
        service.search("outlook", "", "inbox", "!!not-base64!!", 5)
    assert not [r for r in fake_mail.requests if "evil" in str(r.url)]


def test_check_fetches_raw_mime_and_analyses_it_in_memory(connected: str, service: MailboxService, fake_mail) -> None:
    rows = fake_mail.gmail if connected == "gmail" else fake_mail.graph
    rows[0].raw = message(headers=[("Reply-To", "pay@other.example")])
    report = service.check(connected, rows[0].id)
    assert report.verdict == "suspicious" and report.findings[0].id == "mail.sender.reply_to_mismatch"
    assert report.subject == "Quarterly update" and BODY_SENTINEL not in report.model_dump_json()
    last = fake_mail.requests[-1]
    assert last.method == "GET"
    assert ("format=raw" in str(last.url)) if connected == "gmail" else last.url.path.endswith("/$value")


def test_check_options_reach_the_analyzer(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "gmail")
    fake_mail.gmail[0].raw = message(sender='"PayPal" <a@evil.example>')
    report = service.check("gmail", fake_mail.gmail[0].id, protected_domains=frozenset({"paypal.com"}))
    assert any(f.id == "mail.sender.display_name_brand" for f in report.findings)


def test_every_provider_call_is_a_get_except_token_calls(service: MailboxService, fake_mail) -> None:
    for provider in ("gmail", "outlook"):
        connect(service, fake_mail, provider)
        service.search(provider, "x", "inbox", None, 5)
        rows = fake_mail.gmail if provider == "gmail" else fake_mail.graph
        service.check(provider, rows[0].id)
    api_calls = [r for r in fake_mail.requests if r.url.host in {"gmail.googleapis.com", "graph.microsoft.com"}]
    assert api_calls and {r.method for r in api_calls} == {"GET"}
    assert not any(r.content for r in api_calls)


def test_invalid_message_id_is_refused_before_any_request(connected: str, service: MailboxService, fake_mail) -> None:
    before = len(fake_mail.requests)
    for bad in ("../../etc", "a/b", "a b", "x?y=1", "", ".."):
        with pytest.raises(Rejected):
            service.check(connected, bad)
    assert len(fake_mail.requests) == before


def test_unknown_message_is_invalid_input(connected: str, service: MailboxService) -> None:
    with pytest.raises(Rejected) as raised:
        service.check(connected, "nosuchmessage")
    assert raised.value.reason is Reason.INVALID_INPUT and "not found" in raised.value.detail


def test_message_over_the_cap_is_refused(connected: str, service: MailboxService, fake_mail) -> None:
    rows = fake_mail.gmail if connected == "gmail" else fake_mail.graph
    fake_mail.raw_override = b"X" * (MAX_MESSAGE_BYTES + 1)
    with pytest.raises(Rejected) as raised:
        service.check(connected, rows[0].id)
    assert raised.value.reason is Reason.INPUT_TOO_LARGE


def test_gmail_size_estimate_stops_the_download(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "gmail")
    fake_mail.size_estimate = MAX_MESSAGE_BYTES + 1
    with pytest.raises(Rejected) as raised:
        service.check("gmail", fake_mail.gmail[0].id)
    assert raised.value.reason is Reason.INPUT_TOO_LARGE
    assert not [r for r in fake_mail.requests if "format=raw" in str(r.url)]


def test_content_that_is_not_a_message_gets_the_analyzer_error(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "outlook")
    fake_mail.raw_override = b"\x00\x01garbage"
    with pytest.raises(Rejected) as raised:  # not a message: the normal analyzer error, not a connector error
        service.check("outlook", fake_mail.graph[0].id)
    assert raised.value.reason is Reason.INVALID_INPUT


def test_an_expired_access_token_is_refreshed_once_and_retried(
    connected: str, service: MailboxService, fake_mail
) -> None:
    fake_mail.valid_access.clear()  # the provider no longer accepts the cached token
    assert service.search(connected, "", "inbox", None, 5).messages
    grants = [f["grant_type"] for f in fake_mail.token_forms]
    assert grants == ["authorization_code", "refresh_token"]


def test_a_token_refused_twice_means_reconnect(connected: str, service: MailboxService, fake_mail) -> None:
    original = fake_mail.handler

    def deny(request: httpx.Request) -> httpx.Response:
        if request.url.host in {"gmail.googleapis.com", "graph.microsoft.com"}:
            return httpx.Response(401)
        return original(request)

    service._http._transport = httpx.MockTransport(deny)
    with pytest.raises(Rejected) as raised:
        service.search(connected, "", "inbox", None, 5)
    assert raised.value.reason is Reason.MAILBOX_RECONNECT_REQUIRED


def test_rate_limit_carries_retry_after(connected: str, service: MailboxService, fake_mail) -> None:
    fake_mail.rate_limit_path = "/gmail/v1" if connected == "gmail" else "/v1.0"
    with pytest.raises(RateLimited) as raised:
        service.search(connected, "", "inbox", None, 5)
    assert raised.value.reason is Reason.RATE_LIMITED and raised.value.retry_after == 17


def test_google_quota_403_is_a_rate_limit() -> None:
    from kestrix.mail.mailbox.http import Reply

    reply = Reply(403, {"retry-after": "9999999"}, b'{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}')
    with pytest.raises(RateLimited) as raised:
        providers.check_reply(reply, "Google")
    assert raised.value.retry_after == providers.MAX_RETRY_S
    api_off = Reply(403, {}, b'{"error":{"errors":[{"reason":"accessNotConfigured"}]}}')
    with pytest.raises(Rejected, match="not enabled"):
        providers.check_reply(api_off, "Google")


def test_network_off_is_target_unreachable(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "gmail")

    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    service._http._transport = httpx.MockTransport(offline)
    with pytest.raises(Rejected) as raised:
        service.search("gmail", "", "inbox", None, 5)
    assert raised.value.reason is Reason.TARGET_UNREACHABLE and "gmail.googleapis.com" in raised.value.detail
    service._http._transport = httpx.MockTransport(
        lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=r))
    )
    with pytest.raises(Rejected, match="did not answer in time"):
        service.search("gmail", "", "inbox", None, 5)


def test_provider_5xx_is_upstream_error(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "gmail")
    service._http._transport = httpx.MockTransport(lambda r: httpx.Response(503))
    with pytest.raises(Rejected) as raised:
        service.search("gmail", "", "inbox", None, 5)
    assert raised.value.reason is Reason.UPSTREAM_ERROR


# Network rules ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/token",
        "https://gmail.googleapis.com.evil.example/x",
        "http://gmail.googleapis.com/gmail/v1/users/me/profile",
        "https://gmail.googleapis.com:8443/x",
        "https://user:pw@gmail.googleapis.com/x",
        "https://127.0.0.1/x",
        "https://accounts.google.com@evil.example/x",
        "ftp://graph.microsoft.com/x",
    ],
)
def test_hosts_outside_the_allow_list_are_refused_before_any_request(url: str, public_dns) -> None:
    sent: list[httpx.Request] = []

    def spy(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200)

    with pytest.raises(Rejected) as raised:
        MailboxHttp(httpx.MockTransport(spy)).request("GET", url)
    assert raised.value.reason in {Reason.TARGET_NOT_ALLOWED, Reason.INVALID_URL}
    assert sent == []


def test_the_allow_list_is_exactly_the_five_provider_hosts() -> None:
    assert {
        "accounts.google.com",
        "oauth2.googleapis.com",
        "gmail.googleapis.com",
        "login.microsoftonline.com",
        "graph.microsoft.com",
    } == ALLOWED_HOSTS


def test_netguard_runs_and_refuses_a_provider_name_that_resolves_privately(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "kestrix.core.netguard._resolve",
        lambda host, port, timeout: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))],
    )
    sent: list[httpx.Request] = []
    http = MailboxHttp(httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    with pytest.raises(Rejected) as raised:
        http.request("GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile")
    assert raised.value.reason is Reason.TARGET_NOT_ALLOWED and sent == []


def test_redirects_are_never_followed(service: MailboxService, fake_mail) -> None:
    connect(service, fake_mail, "gmail")
    fake_mail.redirect_path = "/gmail/v1"
    with pytest.raises(Rejected, match="redirect"):
        service.search("gmail", "", "inbox", None, 5)
    assert not [r for r in fake_mail.requests if r.url.host == "evil.example"]


def test_responses_are_size_capped(public_dns) -> None:
    http = MailboxHttp(httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 5000)))
    with pytest.raises(Rejected):
        http.request("GET", "https://graph.microsoft.com/v1.0/me/messages", max_bytes=1000)
