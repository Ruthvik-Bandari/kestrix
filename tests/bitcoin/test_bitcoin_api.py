"""HTTP routes. Uses the full app when every module imports; otherwise the router on a bare FastAPI."""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from kestrix.bitcoin import api, guardian
from kestrix.bitcoin.chain import MempoolClient
from kestrix.bitcoin.guardian import _ModelIntent
from kestrix.bitcoin.models import GuardianIntent, PublicTestnet
from kestrix.core import config
from kestrix.core.errors import Reason, Rejected
from tests.bitcoin.btc_helpers import (
    G_COMPRESSED,
    P2TR_MAIN,
    P2WPKH_MAIN,
    P2WPKH_TEST,
    FakeAnthropic,
    FakeMessages,
    stats_body,
)


def _bare_app() -> FastAPI:
    app = FastAPI()
    status = {Reason.AI_KEY_MISSING: 503, Reason.UPSTREAM_ERROR: 502, Reason.INPUT_TOO_LARGE: 413}

    @app.exception_handler(Rejected)
    async def _rejected(_: Request, exc: Rejected) -> JSONResponse:
        return JSONResponse({"reason": exc.reason.value, "detail": exc.detail}, status_code=status.get(exc.reason, 400))

    app.include_router(api.router)
    return app


def _make_app() -> FastAPI:
    try:
        from kestrix.server.app import create_app
    except ImportError:  # sibling modules not built yet
        return _bare_app()
    return create_app(extra_hosts=frozenset({"testserver"}))


@pytest.fixture
def app() -> Iterator[FastAPI]:
    application = _make_app()
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _use_chain(app: FastAPI, handler: httpx.MockTransport) -> list[PublicTestnet]:
    used: list[PublicTestnet] = []

    def factory() -> api.ChainClientFactory:
        def make(testnet: PublicTestnet) -> MempoolClient:
            used.append(testnet)
            return MempoolClient(testnet=testnet, transport=handler)

        return make

    app.dependency_overrides[api.chain_client_factory] = factory
    return used


def test_scan_without_lookup(client: TestClient) -> None:
    response = client.post("/api/bitcoin/scan", json={"addresses": [G_COMPRESSED, P2TR_MAIN, P2WPKH_MAIN]})
    assert response.status_code == 200
    body = response.json()
    assert [r["risk"] for r in body["results"]] == ["critical", "high", "unknown"]
    assert body["summary"] == {"total": 3, "by_risk": {"critical": 1, "high": 1, "low": 0, "unknown": 1}}
    first = body["results"][0]
    assert set(first) == {
        "input",
        "address_type",
        "network",
        "risk",
        "key_exposure",
        "explanation",
        "recommendation",
        "chain_activity",
    }
    assert (first["address_type"], first["network"], first["chain_activity"]) == ("P2PK", None, None)


def test_scan_with_lookup_uses_the_chain_client(app: FastAPI, client: TestClient) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=stats_body(spent=1)))
    used = _use_chain(app, transport)
    response = client.post(
        "/api/bitcoin/scan", json={"addresses": [P2WPKH_MAIN, P2WPKH_TEST], "lookup_chain": True, "testnet": "signet"}
    )
    assert response.status_code == 200
    results = response.json()["results"]
    assert [r["risk"] for r in results] == ["high", "high"]
    assert results[1]["chain_activity"] == {
        "source": "mempool.space",
        "chain": "signet",
        "funded_outputs": 1,
        "spent_outputs": 1,
        "balance_sats": 5000,
    }
    assert used == [PublicTestnet.SIGNET]


def test_scan_lookup_upstream_failure_is_502(app: FastAPI, client: TestClient) -> None:
    _use_chain(app, httpx.MockTransport(lambda request: httpx.Response(429)))
    response = client.post("/api/bitcoin/scan", json={"addresses": [P2WPKH_MAIN], "lookup_chain": True})
    assert response.status_code == 502
    assert response.json()["reason"] == "upstream_error"


def test_scan_invalid_address_is_400(client: TestClient) -> None:
    response = client.post("/api/bitcoin/scan", json={"addresses": [P2WPKH_MAIN, "bc1qbad"]})
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"
    assert "address #2" in response.json()["detail"]


@pytest.mark.parametrize(
    "payload",
    [{"addresses": []}, {"addresses": [P2WPKH_MAIN] * 101}, {"addresses": ["x" * 201]}, {"addresses": [], "extra": 1}],
)
def test_scan_request_validation(client: TestClient, payload: dict[str, object]) -> None:
    assert client.post("/api/bitcoin/scan", json=payload).status_code == 422


def test_migration_plan(client: TestClient) -> None:
    response = client.get("/api/bitcoin/migration/p2tr")
    assert response.status_code == 200
    assert set(response.json()) == {"address_type", "urgency", "summary", "steps", "cautions"}
    assert response.json()["address_type"] == "P2TR"


def test_migration_unknown_type_is_400(client: TestClient) -> None:
    response = client.get("/api/bitcoin/migration/p2qrh")
    assert response.status_code == 400
    assert response.json()["reason"] == "invalid_input"


def test_guardian(app: FastAPI, client: TestClient) -> None:
    output = _ModelIntent(
        intent=GuardianIntent.SCAN_ADDRESSES, addresses=[P2TR_MAIN], address_type=None, summary="Scan."
    )
    fake = FakeAnthropic(FakeMessages(output))
    app.dependency_overrides[api.guardian_classifier] = lambda: lambda message: guardian.classify_intent(message, fake)
    response = client.post("/api/bitcoin/guardian", json={"message": f"check {P2TR_MAIN}"})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "intent",
        "addresses",
        "ignored_addresses",
        "address_type",
        "model_summary",
        "next_step",
        "model",
    }
    assert (body["intent"], body["addresses"]) == ("scan_addresses", [P2TR_MAIN])


def test_guardian_without_key_is_503(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "anthropic_key", lambda: None)
    response = client.post("/api/bitcoin/guardian", json={"message": "hello"})
    assert response.status_code == 503
    assert response.json()["reason"] == "ai_key_missing"


@pytest.mark.parametrize("payload", [{"message": ""}, {"message": "x" * 2001}, {}])
def test_guardian_request_validation(client: TestClient, payload: dict[str, object]) -> None:
    assert client.post("/api/bitcoin/guardian", json=payload).status_code == 422
