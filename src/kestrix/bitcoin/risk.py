# SPDX-FileCopyrightText: 2026 Ruthvik Bandari and the BitShield (Team ACE) contributors
# SPDX-License-Identifier: Apache-2.0
"""Quantum-exposure risk for Bitcoin addresses, with plain-language explanations.

The threat model: a sufficiently large quantum computer running Shor's algorithm could
derive a private key from its public key. Coins are therefore most exposed when their
public key is already visible on the blockchain ("long exposure", BIP-360 terminology).
No such computer is publicly known to exist, and estimates of when one might are
uncertain, so this module reports exposure rather than attack timelines.

* P2PK outputs (raw public keys) show the key in the output itself: critical.
* P2TR outputs show the taproot output key, a tweaked public key (BIP-341), in the
  address itself. Whoever learns its private key can spend through the key path, even
  if the internal key is an unspendable NUMS point: high.
* P2PKH, P2WPKH, P2SH and P2WSH show only a hash. The key (or the script containing
  keys) is revealed when the address is spent from: low before that, high after.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ..core.errors import Reason, Rejected
from .address import ParsedAddress, parse_address
from .models import (
    AddressAssessment,
    AddressType,
    ChainActivity,
    KeyExposure,
    Network,
    Risk,
    ScanResult,
    ScanSummary,
)

MAX_BATCH = 100

ChainLookup = Callable[[ParsedAddress], ChainActivity]

HASH_TYPES = frozenset({AddressType.P2PKH, AddressType.P2WPKH, AddressType.P2SH, AddressType.P2WSH})

THREAT = (
    "A sufficiently large quantum computer running Shor's algorithm could derive the private key "
    "from an exposed public key. No such computer is publicly known to exist today."
)

_DESCRIPTIONS = {
    AddressType.P2PK: "This is a raw public key, the lock used by early pay-to-public-key (P2PK) outputs.",
    AddressType.P2PKH: "This is a legacy pay-to-public-key-hash (P2PKH) address.",
    AddressType.P2SH: "This is a pay-to-script-hash (P2SH) address, often used for multisig or wrapped SegWit.",
    AddressType.P2WPKH: "This is a native SegWit pay-to-witness-public-key-hash (P2WPKH) address.",
    AddressType.P2WSH: "This is a native SegWit pay-to-witness-script-hash (P2WSH) address, often used for multisig.",
    AddressType.P2TR: "This is a Taproot (P2TR) address.",
}

_REVEALED_ON_SPEND = {
    AddressType.P2PKH: "its public key",
    AddressType.P2WPKH: "its public key",
    AddressType.P2SH: "its script and the public keys inside it",
    AddressType.P2WSH: "its script and the public keys inside it",
}

_FRESH_ADDRESS = "a fresh address you have never used (for example a P2WPKH address starting bc1q)"


def _p2pk() -> tuple[Risk, KeyExposure, str, str]:
    explanation = (
        "The public key itself is the lock on the coins, so it is permanently visible on the blockchain "
        f"to anyone. {THREAT} Coins locked this way would be among the first at risk if one is built."
    )
    recommendation = (
        f"Move any coins locked to this key to {_FRESH_ADDRESS}, spending the whole balance in one "
        "transaction. See the P2PK migration plan."
    )
    return Risk.CRITICAL, KeyExposure.EXPOSED, explanation, recommendation


def _p2tr() -> tuple[Risk, KeyExposure, str, str]:
    explanation = (
        "Unlike older address types, a Taproot address contains a public key (the tweaked 'output key' "
        "defined in BIP-341), not a hash of one, so the key is visible whether or not the address has "
        f"ever been spent from. {THREAT} Whoever derives the private key for that output key can spend "
        "the coins, even in script-only Taproot setups."
    )
    recommendation = (
        f"For long-term savings, consider moving to {_FRESH_ADDRESS}. Taproot is not broken today; this "
        "trades its privacy and fee benefits for hiding your key. See the P2TR migration plan."
    )
    return Risk.HIGH, KeyExposure.EXPOSED, explanation, recommendation


def _hash_type(
    parsed: ParsedAddress, activity: ChainActivity | None, lookup_requested: bool
) -> tuple[Risk, KeyExposure, str, str]:
    revealed = _REVEALED_ON_SPEND[parsed.address_type]
    hides = f"The address shows only a hash, which hides {revealed} until coins are spent from it."
    if activity is None:
        if lookup_requested and parsed.network is Network.REGTEST:
            why = "Regtest is a private local chain, so no public explorer can check its history."
        else:
            why = "Run the scan with chain lookup to check its public history."
        explanation = (
            f"Unknown: depends on whether this address has ever spent. {hides} If it never has, the key is "
            f"hidden and the risk is low; if it has, the key is public and the risk is high. {why}"
        )
        recommendation = (
            "Avoid reusing this address. If it has been spent from and still holds coins, move them to "
            f"{_FRESH_ADDRESS}."
        )
        return Risk.UNKNOWN, KeyExposure.UNKNOWN, explanation, recommendation
    if activity.spent_outputs > 0:
        explanation = (
            f"{hides} Coins have already been spent from it ({activity.spent_outputs} spent output(s) on "
            f"{activity.chain}), which published {revealed} on the blockchain. {THREAT} Coins still here, "
            "or sent here in the future, rely only on that key."
        )
        if activity.balance_sats > 0:
            recommendation = (
                f"Move the remaining {activity.balance_sats} sats to {_FRESH_ADDRESS} in one transaction, "
                "then stop receiving to this address."
            )
        else:
            recommendation = "This address holds no coins now. Do not receive to it again."
        return Risk.HIGH, KeyExposure.EXPOSED, explanation, recommendation
    explanation = (
        f"{hides} No spend from it appears on {activity.chain}, so {revealed} has not been revealed here. "
        "Spending will reveal it, briefly while the transaction waits to confirm and then permanently. "
        "This assumes the same key is not also used by another address that has been spent from."
    )
    recommendation = (
        "No need to move coins now. When you do spend, send the whole balance in one transaction to "
        f"{_FRESH_ADDRESS}, and do not reuse this address afterwards."
    )
    return Risk.LOW, KeyExposure.NOT_EXPOSED, explanation, recommendation


def assess(
    parsed: ParsedAddress, activity: ChainActivity | None = None, *, lookup_requested: bool = False
) -> AddressAssessment:
    """Assess one parsed input; ``activity`` is its spend history when it was looked up."""
    if parsed.address_type is AddressType.P2PK:
        risk, exposure, explanation, recommendation = _p2pk()
    elif parsed.address_type is AddressType.P2TR:
        risk, exposure, explanation, recommendation = _p2tr()
    else:
        risk, exposure, explanation, recommendation = _hash_type(parsed, activity, lookup_requested)
    return AddressAssessment(
        input=parsed.text,
        address_type=parsed.address_type,
        network=parsed.network,
        risk=risk,
        key_exposure=exposure,
        explanation=f"{_DESCRIPTIONS[parsed.address_type]} {explanation}",
        recommendation=recommendation,
        chain_activity=activity,
    )


def needs_lookup(parsed: ParsedAddress) -> bool:
    """Spend history only changes the result for hash-based types on a public chain."""
    return parsed.address_type in HASH_TYPES and parsed.network in (Network.MAINNET, Network.TEST)


def scan(inputs: Sequence[str], lookup: ChainLookup | None = None) -> ScanResult:
    """Validate every input first, then assess each, looking up spend history if ``lookup`` is given."""
    if not inputs:
        raise Rejected(Reason.INVALID_INPUT, "provide at least one address")
    if len(inputs) > MAX_BATCH:
        raise Rejected(Reason.INVALID_INPUT, f"at most {MAX_BATCH} addresses per scan, got {len(inputs)}")
    parsed = []
    for index, raw in enumerate(inputs, start=1):
        try:
            parsed.append(parse_address(raw))
        except Rejected as exc:
            raise Rejected(exc.reason, f"address #{index}: {exc.detail}") from None
    results = [
        assess(item, lookup(item) if lookup and needs_lookup(item) else None, lookup_requested=lookup is not None)
        for item in parsed
    ]
    by_risk = {risk: sum(r.risk is risk for r in results) for risk in Risk}
    return ScanResult(results=results, summary=ScanSummary(total=len(results), by_risk=by_risk))
