# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Test helpers for the Bitcoin tests: known addresses, mempool.space bodies, a fake Anthropic client."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import Any

from kestrix.bitcoin.address import Bech32Encoding, _bech32_polymod, _hrp_expand

# Known-valid addresses (BIP-173/BIP-350 examples and well-known mainnet addresses).
GENESIS_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
P2SH_MAIN = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
P2WPKH_MAIN = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
P2WPKH_TEST = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
P2WSH_MAIN = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
P2TR_MAIN = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
G_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def stats_body(
    *, funded: int = 1, spent: int = 0, funded_sum: int = 5000, spent_sum: int = 0, pending_spent: int = 0
) -> bytes:
    zero = {"funded_txo_count": 0, "funded_txo_sum": 0, "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": 0}
    return json.dumps(
        {
            "address": "x",
            "chain_stats": {
                "funded_txo_count": funded,
                "funded_txo_sum": funded_sum,
                "spent_txo_count": spent,
                "spent_txo_sum": spent_sum,
                "tx_count": funded + spent,
            },
            "mempool_stats": {**zero, "spent_txo_count": pending_spent},
        }
    ).encode()


class FakeMessages:
    def __init__(self, output: Any = None, *, stop_reason: str = "end_turn", error: Exception | None = None) -> None:
        self.output = output
        self.stop_reason = stop_reason
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def parse(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(parsed_output=self.output, stop_reason=self.stop_reason)


class FakeAnthropic:
    """Stands in for ``anthropic.Anthropic``; only ``beta.messages.parse`` is used."""

    def __init__(self, messages: FakeMessages) -> None:
        self.messages = messages
        self.beta = SimpleNamespace(messages=messages)


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def base58check_encode(payload: bytes) -> str:
    """Reference Base58Check encoder, used only to build edge-case inputs."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number, out = int.from_bytes(data, "big"), ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def bech32_encode(hrp: str, version: int, program: bytes) -> str:
    """Reference segwit encoder (BIP-173/350), used only to build regtest and edge-case inputs."""
    acc = bits = 0
    data = [version]
    for byte in program:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    const = Bech32Encoding.BECH32.value if version == 0 else Bech32Encoding.BECH32M.value
    polymod = _bech32_polymod([*_hrp_expand(hrp), *data, 0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32[d] for d in data + checksum)
