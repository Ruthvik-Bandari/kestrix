# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""mempool.space client, exercised only through httpx.MockTransport."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from kestrix.bitcoin import chain
from kestrix.bitcoin.address import parse_address
from kestrix.bitcoin.chain import MAX_RESPONSE_BYTES, MempoolClient
from kestrix.bitcoin.models import PublicTestnet
from kestrix.core.errors import Reason, Rejected
from tests.bitcoin.btc_helpers import GENESIS_P2PKH, P2WPKH_MAIN, P2WPKH_TEST, bech32_encode, stats_body

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler, **kwargs: object) -> MempoolClient:
    return MempoolClient(transport=httpx.MockTransport(handler), **kwargs)


def _ok(body: bytes) -> Handler:
    return lambda request: httpx.Response(200, content=body)


def test_reports_confirmed_and_pending_activity() -> None:
    body = stats_body(funded=3, spent=1, funded_sum=9000, spent_sum=4000, pending_spent=1)
    with _client(_ok(body)) as client:
        activity = client.activity(parse_address(P2WPKH_MAIN))
    assert (activity.chain, activity.funded_outputs, activity.spent_outputs, activity.balance_sats) == (
        "mainnet",
        3,
        2,
        5000,
    )


@pytest.mark.parametrize(
    ("address", "testnet", "path"),
    [
        (P2WPKH_MAIN, PublicTestnet.TESTNET4, f"/api/address/{P2WPKH_MAIN}"),
        (P2WPKH_TEST, PublicTestnet.TESTNET4, f"/testnet4/api/address/{P2WPKH_TEST}"),
        (P2WPKH_TEST, PublicTestnet.SIGNET, f"/signet/api/address/{P2WPKH_TEST}"),
        (GENESIS_P2PKH, PublicTestnet.SIGNET, f"/api/address/{GENESIS_P2PKH}"),
    ],
)
def test_requests_the_right_chain_endpoint(address: str, testnet: PublicTestnet, path: str, no_dns: list[str]) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=stats_body())

    with _client(handler, testnet=testnet) as client:
        client.activity(parse_address(address))
    assert seen[0].url.host == "mempool.space"
    assert seen[0].url.path == path
    assert no_dns == [str(seen[0].url)]


def test_base_url_is_injectable() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, content=stats_body())

    with _client(handler, base_url="https://explorer.example/") as client:
        client.activity(parse_address(P2WPKH_MAIN))
    assert seen == [f"https://explorer.example/api/address/{P2WPKH_MAIN}"]


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(429), "rate limit"),
        (httpx.Response(503), "server error"),
        (httpx.Response(400, text="Invalid Bitcoin address"), "HTTP 400"),
        (httpx.Response(301, headers={"Location": "https://evil.example/"}), "HTTP 301"),
        (httpx.Response(200, content=b"not json"), "unexpected response"),
        (httpx.Response(200, content=b'{"chain_stats": {}}'), "unexpected response"),
        (httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)), "size limit"),
    ],
)
def test_upstream_failures_are_rejected(response: httpx.Response, message: str) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return response

    with _client(handler) as client, pytest.raises(Rejected, match=message) as info:
        client.activity(parse_address(P2WPKH_MAIN))
    assert info.value.reason is Reason.UPSTREAM_ERROR
    assert len(calls) == 1  # redirects are not followed


@pytest.mark.parametrize(
    ("error", "message"),
    [(httpx.ReadTimeout("slow"), "did not respond"), (httpx.ConnectError("refused"), "could not reach")],
)
def test_transport_errors_are_rejected(error: httpx.HTTPError, message: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    with _client(handler) as client, pytest.raises(Rejected, match=message) as info:
        client.activity(parse_address(P2WPKH_MAIN))
    assert info.value.reason is Reason.UPSTREAM_ERROR


def test_netguard_refusal_stops_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(url: str, *, allow_private: bool = False) -> tuple[str, int, list[str]]:
        raise Rejected(Reason.TARGET_NOT_ALLOWED, "private address")

    monkeypatch.setattr(chain, "check_url", refuse)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request after a netguard refusal")

    with _client(handler) as client, pytest.raises(Rejected) as info:
        client.activity(parse_address(P2WPKH_MAIN))
    assert info.value.reason is Reason.TARGET_NOT_ALLOWED


def test_regtest_cannot_be_looked_up() -> None:
    with _client(_ok(stats_body())) as client, pytest.raises(Rejected) as info:
        client.activity(parse_address(bech32_encode("bcrt", 0, bytes(20))))
    assert info.value.reason is Reason.INVALID_INPUT
