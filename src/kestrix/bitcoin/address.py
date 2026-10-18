# SPDX-FileCopyrightText: 2026 Ruthvik Bandari and the BitShield (Team ACE) contributors
# SPDX-License-Identifier: Apache-2.0
"""Bitcoin address and raw public key parsing, standard library only.

Base58Check addresses are verified with their double-SHA-256 checksum. Segwit
addresses follow BIP-173 (Bech32, witness version 0) and BIP-350 (Bech32m, versions
1-16), including the checksum-variant, witness-version and program-length rules. Raw
public keys (the lock used by P2PK outputs, which have no address form) are accepted as
33-byte compressed or 65-byte uncompressed SEC hex and must lie on secp256k1.
"""

from __future__ import annotations

import hashlib
import string
from dataclasses import dataclass
from enum import Enum

from ..core.errors import Reason, Rejected
from .models import AddressType, Network

MAX_INPUT_CHARS = 130  # an uncompressed public key in hex

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {ch: i for i, ch in enumerate(_B58_ALPHABET)}
_B58_VERSIONS = {
    0x00: (AddressType.P2PKH, Network.MAINNET),
    0x05: (AddressType.P2SH, Network.MAINNET),
    0x6F: (AddressType.P2PKH, Network.TEST),
    0xC4: (AddressType.P2SH, Network.TEST),
}

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_MAX_LENGTH = 90
_SEGWIT_HRPS = {"bc": Network.MAINNET, "tb": Network.TEST, "bcrt": Network.REGTEST}

_SECP256K1_P = 2**256 - 2**32 - 977


class Bech32Encoding(Enum):
    BECH32 = 1
    BECH32M = 0x2BC830A3


@dataclass(frozen=True, slots=True)
class ParsedAddress:
    """A validated input. ``text`` is the canonical form (Bech32 and hex lowercased);
    ``payload`` is the key hash, script hash, witness program or public key."""

    text: str
    address_type: AddressType
    network: Network | None
    payload: bytes


# --- Base58Check ---------------------------------------------------------------------


def base58_decode(text: str) -> bytes:
    """Decode Base58 (Bitcoin alphabet). Each leading ``1`` is one leading zero byte."""
    number = 0
    for ch in text:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            raise ValueError(f"invalid Base58 character {ch!r}")
        number = number * 58 + digit
    leading_zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeros + number.to_bytes((number.bit_length() + 7) // 8, "big")


def base58check_decode(text: str) -> bytes:
    """Decode Base58Check and return the payload with its 4-byte checksum verified."""
    raw = base58_decode(text)
    if len(raw) < 5:
        raise ValueError("too short for Base58Check")
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("Base58Check checksum mismatch")
    return payload


# --- Bech32 / Bech32m ----------------------------------------------------------------


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for i, generator in enumerate(generators):
            if (top >> i) & 1:
                checksum ^= generator
    return checksum


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(ch) >> 5 for ch in hrp] + [0] + [ord(ch) & 31 for ch in hrp]


def bech32_decode(text: str) -> tuple[str, list[int], Bech32Encoding]:
    """Decode a Bech32 or Bech32m string into ``(hrp, 5-bit data without checksum, encoding)``."""
    if any(not 33 <= ord(ch) <= 126 for ch in text):
        raise ValueError("character out of range")
    if text.lower() != text and text.upper() != text:
        raise ValueError("mixed case")
    if len(text) > _BECH32_MAX_LENGTH:
        raise ValueError(f"longer than {_BECH32_MAX_LENGTH} characters")
    text = text.lower()
    separator = text.rfind("1")
    if separator < 1:
        raise ValueError("missing separator or empty human-readable part")
    if separator + 7 > len(text):
        raise ValueError("checksum too short")
    hrp, data_part = text[:separator], text[separator + 1 :]
    if any(ch not in _BECH32_CHARSET for ch in data_part):
        raise ValueError("invalid data character")
    data = [_BECH32_CHARSET.index(ch) for ch in data_part]
    constant = _bech32_polymod(_hrp_expand(hrp) + data)
    try:
        encoding = Bech32Encoding(constant)
    except ValueError:
        raise ValueError("invalid checksum") from None
    return hrp, data[:-6], encoding


def _convert_5_to_8_bits(data: list[int]) -> bytes:
    """Regroup 5-bit values into bytes; leftover padding must be under 5 bits and zero."""
    accumulator = bits = 0
    out = bytearray()
    for value in data:
        accumulator = (accumulator << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((accumulator >> bits) & 0xFF)
    if bits >= 5 or (accumulator << (8 - bits)) & 0xFF:
        raise ValueError("invalid padding")
    return bytes(out)


def decode_segwit(text: str) -> tuple[str, int, bytes]:
    """Decode a segwit address into ``(hrp, witness version, witness program)``."""
    hrp, data, encoding = bech32_decode(text)
    if not data:
        raise ValueError("empty data section")
    version = data[0]
    if version > 16:
        raise ValueError(f"invalid witness version {version}")
    program = _convert_5_to_8_bits(data[1:])
    if not 2 <= len(program) <= 40:
        raise ValueError(f"invalid witness program length {len(program)}")
    if version == 0 and len(program) not in (20, 32):
        raise ValueError(f"invalid witness program length {len(program)} for version 0")
    expected = Bech32Encoding.BECH32 if version == 0 else Bech32Encoding.BECH32M
    if encoding is not expected:
        raise ValueError(f"witness version {version} requires {expected.name.capitalize()} checksum")
    return hrp, version, program


# --- Public keys ---------------------------------------------------------------------


def _is_on_curve(sec: bytes) -> bool:
    x = int.from_bytes(sec[1:33], "big")
    if x >= _SECP256K1_P:
        return False
    rhs = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
    if len(sec) == 33:
        return pow(rhs, (_SECP256K1_P - 1) // 2, _SECP256K1_P) == 1  # rhs has a square root
    y = int.from_bytes(sec[33:], "big")
    return y < _SECP256K1_P and pow(y, 2, _SECP256K1_P) == rhs


def _parse_public_key(text: str) -> ParsedAddress:
    sec = bytes.fromhex(text)
    valid_prefix = (len(sec) == 33 and sec[0] in (2, 3)) or (len(sec) == 65 and sec[0] == 4)
    if not valid_prefix:
        raise ValueError("a public key must be 33 bytes starting 02/03 or 65 bytes starting 04")
    if not _is_on_curve(sec):
        raise ValueError("not a point on the secp256k1 curve")
    return ParsedAddress(text.lower(), AddressType.P2PK, None, sec)


# --- Dispatch ------------------------------------------------------------------------


def _parse_segwit(text: str) -> ParsedAddress:
    hrp, version, program = decode_segwit(text)
    network = _SEGWIT_HRPS[hrp]
    if version == 0:
        address_type = AddressType.P2WPKH if len(program) == 20 else AddressType.P2WSH
    elif version == 1 and len(program) == 32:
        address_type = AddressType.P2TR
    else:
        raise ValueError(
            f"witness version {version} with a {len(program)}-byte program is valid encoding "
            "but not a defined output type; do not send coins to it"
        )
    return ParsedAddress(text.lower(), address_type, network, program)


def _parse_base58(text: str) -> ParsedAddress:
    payload = base58check_decode(text)
    if len(payload) != 21 or payload[0] not in _B58_VERSIONS:
        raise ValueError("not a Bitcoin P2PKH or P2SH address")
    address_type, network = _B58_VERSIONS[payload[0]]
    return ParsedAddress(text, address_type, network, payload[1:])


def _looks_segwit(text: str) -> bool:
    lowered = text.lower()
    return any(lowered.startswith(hrp + "1") for hrp in _SEGWIT_HRPS)


def parse_address(raw: str) -> ParsedAddress:
    """Parse an address or raw public key, raising ``Rejected(INVALID_INPUT)`` if invalid."""
    text = raw.strip()
    shown = text[:100]
    if not text:
        raise Rejected(Reason.INVALID_INPUT, "empty address")
    if len(text) > MAX_INPUT_CHARS:
        raise Rejected(Reason.INVALID_INPUT, f"{shown!r}...: too long to be an address or public key")
    try:
        if len(text) in (66, 130) and all(ch in string.hexdigits for ch in text):
            return _parse_public_key(text)
        if _looks_segwit(text):
            return _parse_segwit(text)
        return _parse_base58(text)
    except ValueError as exc:
        raise Rejected(Reason.INVALID_INPUT, f"{shown!r} is not a valid Bitcoin address or public key: {exc}") from None
