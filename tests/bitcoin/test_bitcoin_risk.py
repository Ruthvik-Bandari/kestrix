from __future__ import annotations

import pytest

from kestrix.bitcoin.address import ParsedAddress, parse_address
from kestrix.bitcoin.models import ChainActivity, KeyExposure, Risk
from kestrix.bitcoin.risk import MAX_BATCH, assess, scan
from kestrix.core.errors import Reason, Rejected
from tests.bitcoin.btc_helpers import (
    G_COMPRESSED,
    GENESIS_P2PKH,
    P2SH_MAIN,
    P2TR_MAIN,
    P2WPKH_MAIN,
    P2WSH_MAIN,
    bech32_encode,
)

HASH_ADDRESSES = [GENESIS_P2PKH, P2SH_MAIN, P2WPKH_MAIN, P2WSH_MAIN]


def _activity(spent: int, balance: int = 0) -> ChainActivity:
    return ChainActivity(chain="mainnet", funded_outputs=max(spent, 1), spent_outputs=spent, balance_sats=balance)


def test_raw_public_key_is_critical_and_exposed() -> None:
    result = assess(parse_address(G_COMPRESSED))
    assert (result.risk, result.key_exposure) == (Risk.CRITICAL, KeyExposure.EXPOSED)
    assert "Shor's algorithm" in result.explanation
    assert "No such computer is publicly known" in result.explanation


def test_taproot_is_high_because_output_key_is_in_the_address() -> None:
    result = assess(parse_address(P2TR_MAIN), _activity(0))
    assert (result.risk, result.key_exposure) == (Risk.HIGH, KeyExposure.EXPOSED)
    assert "BIP-341" in result.explanation
    assert "script-only" in result.explanation


@pytest.mark.parametrize("address", HASH_ADDRESSES)
def test_hash_types_without_lookup_are_unknown(address: str) -> None:
    result = assess(parse_address(address))
    assert (result.risk, result.key_exposure) == (Risk.UNKNOWN, KeyExposure.UNKNOWN)
    assert result.explanation.lower().count("unknown: depends on whether this address has ever spent") == 1
    assert "chain lookup" in result.explanation


@pytest.mark.parametrize("address", HASH_ADDRESSES)
def test_hash_types_never_spent_are_low(address: str) -> None:
    result = assess(parse_address(address), _activity(0, balance=1000))
    assert (result.risk, result.key_exposure) == (Risk.LOW, KeyExposure.NOT_EXPOSED)
    assert "has not been revealed" in result.explanation


@pytest.mark.parametrize("address", HASH_ADDRESSES)
def test_hash_types_spent_from_are_high(address: str) -> None:
    result = assess(parse_address(address), _activity(2, balance=1500))
    assert (result.risk, result.key_exposure) == (Risk.HIGH, KeyExposure.EXPOSED)
    assert "1500 sats" in result.recommendation


def test_spent_and_empty_address_says_not_to_reuse() -> None:
    result = assess(parse_address(P2WPKH_MAIN), _activity(1, balance=0))
    assert "Do not receive to it again" in result.recommendation


def test_scripts_are_described_as_revealing_their_keys() -> None:
    result = assess(parse_address(P2WSH_MAIN), _activity(1))
    assert "script and the public keys inside it" in result.explanation


def test_scan_looks_up_only_hash_types_on_public_chains() -> None:
    looked_up: list[str] = []

    def lookup(parsed: ParsedAddress) -> ChainActivity:
        looked_up.append(parsed.text)
        return _activity(1)

    result = scan([G_COMPRESSED, P2TR_MAIN, P2WPKH_MAIN], lookup=lookup)
    assert looked_up == [P2WPKH_MAIN]
    assert [r.risk for r in result.results] == [Risk.CRITICAL, Risk.HIGH, Risk.HIGH]
    assert result.summary.total == 3
    assert result.summary.by_risk == {Risk.CRITICAL: 1, Risk.HIGH: 2, Risk.LOW: 0, Risk.UNKNOWN: 0}
    assert result.results[2].chain_activity is not None


def test_scan_without_lookup_reports_unknown_for_hash_types() -> None:
    result = scan([P2WPKH_MAIN, GENESIS_P2PKH])
    assert result.summary.by_risk[Risk.UNKNOWN] == 2
    assert all(r.chain_activity is None for r in result.results)


def test_regtest_with_lookup_explains_no_public_explorer() -> None:
    regtest = bech32_encode("bcrt", 0, bytes(20))

    def lookup(parsed: ParsedAddress) -> ChainActivity:
        raise AssertionError("regtest must not be looked up")

    result = scan([regtest], lookup=lookup).results[0]
    assert result.risk is Risk.UNKNOWN
    assert "private local chain" in result.explanation


@pytest.mark.parametrize("inputs", [[], [P2WPKH_MAIN] * (MAX_BATCH + 1)])
def test_scan_enforces_batch_limits(inputs: list[str]) -> None:
    with pytest.raises(Rejected) as info:
        scan(inputs)
    assert info.value.reason is Reason.INVALID_INPUT


def test_scan_accepts_exactly_the_batch_limit() -> None:
    assert scan([P2WPKH_MAIN] * MAX_BATCH).summary.total == MAX_BATCH


def test_scan_names_the_invalid_entry_and_does_no_lookups() -> None:
    def lookup(parsed: ParsedAddress) -> ChainActivity:
        raise AssertionError("no lookup before every input is validated")

    with pytest.raises(Rejected, match="address #2"):
        scan([P2WPKH_MAIN, "not-an-address"], lookup=lookup)
