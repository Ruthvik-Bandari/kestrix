"""Address parsing against the official vectors: Bitcoin Core base58_encode_decode.json,
BIP-173 (Bech32) and BIP-350 (Bech32m and segwit addresses)."""

from __future__ import annotations

import pytest

from kestrix.bitcoin.address import (
    Bech32Encoding,
    base58_decode,
    base58check_decode,
    bech32_decode,
    decode_segwit,
    parse_address,
)
from kestrix.bitcoin.models import AddressType, Network
from kestrix.core.errors import Reason, Rejected
from tests.bitcoin.btc_helpers import (
    G_COMPRESSED,
    GENESIS_P2PKH,
    P2SH_MAIN,
    P2TR_MAIN,
    P2WPKH_MAIN,
    P2WPKH_TEST,
    P2WSH_MAIN,
    base58check_encode,
    bech32_encode,
)

# --- Base58 (Bitcoin Core src/test/data/base58_encode_decode.json) -------------------

BASE58_VECTORS = [
    ("", ""),
    ("61", "2g"),
    ("626262", "a3gV"),
    ("636363", "aPEr"),
    ("73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
    ("00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"),
    ("516b6fcd0f", "ABnLTmg"),
    ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
    ("572e4794", "3EFU7m"),
    ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
    ("10c8511e", "Rt5zm"),
    ("00000000000000000000", "1111111111"),
    ("00" * 40, "1" * 40),
    ("00" * 39 + "01", "1" * 39 + "2"),
    (
        "00" * 86 + "ec39d04c37e71e5d591881f6",
        "1" * 86 + "5TYzLYH1udmLdzCLM",
    ),
    (
        "000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5",
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    ),
    ("271F359E", "zzzzy"),
    ("271F359F", "zzzzz"),
    ("271F35A0", "211111"),
    ("271F35A1", "211112"),
]


@pytest.mark.parametrize(("hex_bytes", "encoded"), BASE58_VECTORS)
def test_base58_vectors(hex_bytes: str, encoded: str) -> None:
    assert base58_decode(encoded) == bytes.fromhex(hex_bytes)


@pytest.mark.parametrize("bad", ["0", "O", "I", "l", "abc+", "3SEo3LWLoPntC "])
def test_base58_rejects_characters_outside_alphabet(bad: str) -> None:
    with pytest.raises(ValueError, match="invalid Base58 character"):
        base58_decode(bad)


def test_base58check_verifies_checksum() -> None:
    assert base58check_decode(GENESIS_P2PKH) == bytes.fromhex("0062e907b15cbf27d5425399ebf6f0fb50ebb88f18")
    with pytest.raises(ValueError, match="checksum mismatch"):
        base58check_decode(GENESIS_P2PKH[:-1] + "b")
    with pytest.raises(ValueError, match="too short"):
        base58check_decode("2g")


# --- Bech32 / Bech32m strings (BIP-173, BIP-350) -------------------------------------

BECH32_VALID = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]
BECH32M_VALID = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]
BECH32_INVALID = [
    "\x201nwldj5",
    "\x7f1axkwrx",
    "\x801eym55h",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
    "A1G7SGD8",
    "10a06t8",
    "1qzzfhee",
]
BECH32M_INVALID = [
    "\x201xj0phk",
    "\x7f1g6xzxy",
    "\x801vctc34",
    "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    "qyrz8wqd2c9m",
    "1qyrz8wqd2c9m",
    "y1b0jsk6g",
    "lt1igcx5c0",
    "in1muywd",
    "mm1crxm3i",
    "au1s5cgom",
    "M1VUXWEZ",
    "16plkw9",
    "1p2gdwpf",
]


@pytest.mark.parametrize("text", BECH32_VALID)
def test_bech32_valid(text: str) -> None:
    assert bech32_decode(text)[2] is Bech32Encoding.BECH32


@pytest.mark.parametrize("text", BECH32M_VALID)
def test_bech32m_valid(text: str) -> None:
    assert bech32_decode(text)[2] is Bech32Encoding.BECH32M


@pytest.mark.parametrize("text", BECH32_INVALID + BECH32M_INVALID)
def test_bech32_invalid(text: str) -> None:
    with pytest.raises(ValueError):
        bech32_decode(text)


# --- Segwit addresses (BIP-350, superseding the BIP-173 list) ------------------------

SEGWIT_VALID = [
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    ("BC1SW50QGDZ25J", "6002751e"),
    ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"),
    (
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
]

SEGWIT_INVALID = [
    "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    "bc1pw5dgrnzv",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
    "bc1gmk9yu",
    # BIP-173's own invalid list
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
]


def _script_pubkey(version: int, program: bytes) -> str:
    return (bytes([version + 0x50 if version else 0, len(program)]) + program).hex()


@pytest.mark.parametrize(("address", "script_hex"), SEGWIT_VALID)
def test_segwit_valid_vectors(address: str, script_hex: str) -> None:
    _, version, program = decode_segwit(address)
    assert _script_pubkey(version, program) == script_hex


@pytest.mark.parametrize("address", SEGWIT_INVALID)
def test_segwit_invalid_vectors_are_rejected(address: str) -> None:
    with pytest.raises(Rejected) as info:
        parse_address(address)
    assert info.value.reason is Reason.INVALID_INPUT


# --- Classification ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "address_type", "network"),
    [
        (GENESIS_P2PKH, AddressType.P2PKH, Network.MAINNET),
        (P2SH_MAIN, AddressType.P2SH, Network.MAINNET),
        ("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", AddressType.P2PKH, Network.TEST),
        ("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc", AddressType.P2SH, Network.TEST),
        (P2WPKH_MAIN, AddressType.P2WPKH, Network.MAINNET),
        (P2WPKH_TEST, AddressType.P2WPKH, Network.TEST),
        (P2WSH_MAIN, AddressType.P2WSH, Network.MAINNET),
        (P2TR_MAIN, AddressType.P2TR, Network.MAINNET),
        ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", AddressType.P2TR, Network.TEST),
    ],
)
def test_classifies_address_type_and_network(address: str, address_type: AddressType, network: Network) -> None:
    parsed = parse_address(f"  {address}\n")
    assert (parsed.address_type, parsed.network) == (address_type, network)


def test_genesis_address_payload_is_its_key_hash() -> None:
    assert parse_address(GENESIS_P2PKH).payload.hex() == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"


def test_uppercase_bech32_is_normalized() -> None:
    assert parse_address(P2WPKH_MAIN.upper()).text == P2WPKH_MAIN


def test_regtest_bech32_address() -> None:
    parsed = parse_address(bech32_encode("bcrt", 0, bytes(20)))
    assert (parsed.address_type, parsed.network) == (AddressType.P2WPKH, Network.REGTEST)


@pytest.mark.parametrize(("version", "length"), [(1, 20), (2, 32), (16, 2)])
def test_undefined_witness_programs_are_rejected(version: int, length: int) -> None:
    with pytest.raises(Rejected, match="not a defined output type"):
        parse_address(bech32_encode("bc", version, bytes(length)))


def test_base58_with_unknown_version_or_length_is_rejected() -> None:
    with pytest.raises(Rejected, match="not a Bitcoin P2PKH or P2SH address"):
        parse_address(base58check_encode(b"\x30" + bytes(20)))  # Litecoin P2PKH version
    with pytest.raises(Rejected, match="not a Bitcoin P2PKH or P2SH address"):
        parse_address(base58check_encode(b"\x00" + bytes(19)))


# --- Raw public keys -----------------------------------------------------------------

G_UNCOMPRESSED = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


@pytest.mark.parametrize("key", [G_COMPRESSED, G_COMPRESSED.upper(), G_UNCOMPRESSED])
def test_raw_public_key_is_p2pk(key: str) -> None:
    parsed = parse_address(key)
    assert (parsed.address_type, parsed.network, parsed.text) == (AddressType.P2PK, None, key.lower())


@pytest.mark.parametrize(
    "key",
    [
        "05" + G_COMPRESSED[2:],  # bad prefix
        "04" + G_COMPRESSED[2:],  # uncompressed prefix on 33 bytes
        G_UNCOMPRESSED[:-1] + "9",  # y not on the curve
        "02" + "ff" * 32,  # x beyond the field prime
    ],
)
def test_invalid_public_keys_are_rejected(key: str) -> None:
    with pytest.raises(Rejected) as info:
        parse_address(key)
    assert info.value.reason is Reason.INVALID_INPUT


@pytest.mark.parametrize("text", ["", "   ", "hello", "x" * 131, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"])
def test_garbage_is_rejected(text: str) -> None:
    with pytest.raises(Rejected) as info:
        parse_address(text)
    assert info.value.reason is Reason.INVALID_INPUT
