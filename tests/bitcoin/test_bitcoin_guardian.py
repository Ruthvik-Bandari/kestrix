# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Guardian intent classification with a fake Anthropic client; no API calls."""

from __future__ import annotations

import sys

import anthropic
import httpx2
import pytest

from kestrix.bitcoin import guardian
from kestrix.bitcoin.guardian import DEFAULT_MODEL, MODEL_ENV, _ModelIntent, build_client, classify_intent
from kestrix.bitcoin.models import AddressType, GuardianIntent
from kestrix.core import config
from kestrix.core.errors import Reason, Rejected
from tests.bitcoin.btc_helpers import G_COMPRESSED, P2TR_MAIN, P2WPKH_MAIN, FakeAnthropic, FakeMessages

_REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def _output(
    intent: GuardianIntent, addresses: list[str] | None = None, address_type: AddressType | None = None
) -> _ModelIntent:
    return _ModelIntent(intent=intent, addresses=addresses or [], address_type=address_type, summary="  You asked.  ")


def _classify(output: _ModelIntent | None, message: str, **kwargs: object) -> tuple[object, FakeMessages]:
    messages = FakeMessages(output, **kwargs)
    return classify_intent(message, FakeAnthropic(messages)), messages


@pytest.fixture(autouse=True)
def _no_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(MODEL_ENV, raising=False)


def test_scan_intent_keeps_only_validated_addresses_from_the_message() -> None:
    invented = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    message = f"Is {P2WPKH_MAIN} safe? Also {P2WPKH_MAIN.upper()} and bc1qnotreal and {G_COMPRESSED}"
    result, _ = _classify(
        _output(
            GuardianIntent.SCAN_ADDRESSES,
            [P2WPKH_MAIN, P2WPKH_MAIN.upper(), "bc1qnotreal", invented, G_COMPRESSED, " "],
        ),
        message,
    )
    assert result.intent is GuardianIntent.SCAN_ADDRESSES
    assert result.addresses == [P2WPKH_MAIN, G_COMPRESSED]  # deduplicated after normalization
    assert result.ignored_addresses == ["bc1qnotreal", invented]
    assert "Nothing has been scanned yet" in result.next_step
    assert result.model_summary == "You asked."


def test_request_uses_structured_output_default_model_and_fallbacks() -> None:
    _, messages = _classify(_output(GuardianIntent.UNKNOWN), "  hello  ")
    call = messages.calls[0]
    assert call["model"] == DEFAULT_MODEL
    assert call["output_format"] is _ModelIntent
    assert call["system"] == guardian.SYSTEM_PROMPT
    assert call["messages"] == [{"role": "user", "content": "hello"}]
    assert call["fallbacks"] == "default"
    assert call["betas"] == ["server-side-fallback-2026-07-01"]


def test_model_comes_from_environment_without_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MODEL_ENV, "claude-sonnet-5-5")
    result, messages = _classify(_output(GuardianIntent.UNKNOWN), "hello")
    assert result.model == "claude-sonnet-5-5"
    assert messages.calls[0]["model"] == "claude-sonnet-5-5"
    assert messages.calls[0]["fallbacks"] is anthropic.omit
    assert messages.calls[0]["betas"] is anthropic.omit


def test_migration_intent_points_to_the_plan() -> None:
    result, _ = _classify(_output(GuardianIntent.MIGRATION_HELP, address_type=AddressType.P2TR), "move my taproot")
    assert result.address_type is AddressType.P2TR
    assert "kestrix bitcoin migration P2TR" in result.next_step


def test_address_type_is_dropped_for_other_intents() -> None:
    result, _ = _classify(_output(GuardianIntent.EXPLAIN_RISK, address_type=AddressType.P2TR), "why is taproot risky")
    assert result.address_type is None
    assert "Shor's algorithm" in result.next_step


def test_wallet_actions_are_declined_as_read_only() -> None:
    result, _ = _classify(_output(GuardianIntent.SET_POLICY_REQUEST, [P2TR_MAIN]), f"send 1 BTC to {P2TR_MAIN}")
    assert result.intent is GuardianIntent.SET_POLICY_REQUEST
    assert "read-only" in result.next_step


def test_scan_without_addresses_asks_for_one() -> None:
    result, _ = _classify(_output(GuardianIntent.SCAN_ADDRESSES), "scan my wallet")
    assert "No valid Bitcoin address" in result.next_step


def test_summary_is_truncated() -> None:
    output = _ModelIntent(intent=GuardianIntent.UNKNOWN, addresses=[], address_type=None, summary="x" * 5000)
    result, _ = _classify(output, "hi")
    assert len(result.model_summary) == guardian.MAX_SUMMARY_CHARS


@pytest.mark.parametrize(("message", "reason"), [("   ", Reason.INVALID_INPUT), ("x" * 2001, Reason.INPUT_TOO_LARGE)])
def test_message_limits(message: str, reason: Reason) -> None:
    with pytest.raises(Rejected) as info:
        _classify(_output(GuardianIntent.UNKNOWN), message)
    assert info.value.reason is reason


@pytest.mark.parametrize(("output", "stop_reason"), [(None, "end_turn"), (_output(GuardianIntent.UNKNOWN), "refusal")])
def test_unusable_model_answers_are_upstream_errors(output: _ModelIntent | None, stop_reason: str) -> None:
    with pytest.raises(Rejected) as info:
        _classify(output, "hi", stop_reason=stop_reason)
    assert info.value.reason is Reason.UPSTREAM_ERROR


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (
            anthropic.AuthenticationError("bad key", response=httpx2.Response(401, request=_REQUEST), body=None),
            Reason.AI_KEY_MISSING,
        ),
        (
            anthropic.RateLimitError("slow down", response=httpx2.Response(429, request=_REQUEST), body=None),
            Reason.UPSTREAM_ERROR,
        ),
        (
            anthropic.InternalServerError("boom", response=httpx2.Response(500, request=_REQUEST), body=None),
            Reason.UPSTREAM_ERROR,
        ),
        (anthropic.APIConnectionError(request=_REQUEST), Reason.UPSTREAM_ERROR),
    ],
)
def test_api_errors_are_mapped(error: Exception, reason: Reason) -> None:
    with pytest.raises(Rejected) as info:
        _classify(_output(GuardianIntent.UNKNOWN), "hi", error=error)
    assert info.value.reason is reason


def test_build_client_requires_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "anthropic_key", lambda: None)
    with pytest.raises(Rejected) as info:
        build_client()
    assert info.value.reason is Reason.AI_KEY_MISSING
    assert "kestrix config set-anthropic-key" in info.value.detail


def test_build_client_uses_the_configured_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "anthropic_key", lambda: "sk-ant-test-key-not-real")
    client = build_client()
    assert isinstance(client, anthropic.Anthropic)
    assert client.api_key == "sk-ant-test-key-not-real"


def test_build_client_without_the_ai_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "anthropic_key", lambda: "sk-ant-test-key-not-real")
    monkeypatch.setitem(sys.modules, "anthropic", None)
    with pytest.raises(Rejected) as info:
        build_client()
    assert info.value.reason is Reason.AI_KEY_MISSING
    assert 'pip install "kestrix[ai]"' in info.value.detail
