# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json

import httpx
import pytest
from typer.testing import CliRunner

from kestrix.bitcoin import cli
from kestrix.bitcoin.chain import MempoolClient
from kestrix.bitcoin.guardian import _ModelIntent
from kestrix.bitcoin.models import GuardianIntent, PublicTestnet
from kestrix.core import config
from tests.bitcoin.btc_helpers import G_COMPRESSED, P2TR_MAIN, P2WPKH_MAIN, FakeAnthropic, FakeMessages, stats_body

runner = CliRunner()


def _patch_chain(monkeypatch: pytest.MonkeyPatch, response: httpx.Response) -> None:
    transport = httpx.MockTransport(lambda request: response)

    def make(*, testnet: PublicTestnet) -> MempoolClient:
        return MempoolClient(testnet=testnet, transport=transport)

    monkeypatch.setattr(cli, "MempoolClient", make)


def test_scan_human_output() -> None:
    result = runner.invoke(cli.app, ["scan", G_COMPRESSED, P2TR_MAIN])
    assert result.exit_code == 0
    assert "[CRITICAL]" in result.output
    assert "[HIGH]" in result.output
    assert "What to do:" in result.output
    assert "2 scanned: critical 1, high 1, low 0, unknown 0" in result.output


def test_scan_json_with_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_chain(monkeypatch, httpx.Response(200, content=stats_body()))
    result = runner.invoke(cli.app, ["scan", P2WPKH_MAIN, "--lookup-chain", "--json"])
    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["results"][0]["risk"] == "low"
    assert body["results"][0]["chain_activity"]["chain"] == "mainnet"


def test_scan_invalid_address_exits_2() -> None:
    result = runner.invoke(cli.app, ["scan", "bc1qbad"])
    assert result.exit_code == 2
    assert "invalid_input" in result.output


def test_scan_upstream_failure_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_chain(monkeypatch, httpx.Response(503))
    result = runner.invoke(cli.app, ["scan", P2WPKH_MAIN, "--lookup-chain"])
    assert result.exit_code == 3
    assert "upstream_error" in result.output


def test_migration_human_and_json() -> None:
    human = runner.invoke(cli.app, ["migration", "p2pk"])
    assert human.exit_code == 0
    assert "P2PK (urgency: now)" in human.output
    assert "Cautions:" in human.output
    as_json = runner.invoke(cli.app, ["migration", "P2WSH", "--json"])
    assert json.loads(as_json.output)["urgency"] == "if_spent"


def test_migration_unknown_type_exits_2() -> None:
    assert runner.invoke(cli.app, ["migration", "p2qrh"]).exit_code == 2


def test_ask_without_key_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "anthropic_key", lambda: None)
    result = runner.invoke(cli.app, ["ask", "is my address safe?"])
    assert result.exit_code == 3
    assert "set-anthropic-key" in result.output


def test_ask_prints_intent(monkeypatch: pytest.MonkeyPatch) -> None:
    output = _ModelIntent(
        intent=GuardianIntent.SCAN_ADDRESSES, addresses=[P2WPKH_MAIN, "bc1qfake"], address_type=None, summary="Scan it."
    )
    monkeypatch.setattr(cli.guardian, "build_client", lambda: FakeAnthropic(FakeMessages(output)))
    result = runner.invoke(cli.app, ["ask", f"check {P2WPKH_MAIN} and bc1qfake"])
    assert result.exit_code == 0
    assert "Intent: scan_addresses" in result.output
    assert f"Addresses: {P2WPKH_MAIN}" in result.output
    assert "Ignored (not valid or not in your message): bc1qfake" in result.output
    assert "Understood as (model-written): Scan it." in result.output
