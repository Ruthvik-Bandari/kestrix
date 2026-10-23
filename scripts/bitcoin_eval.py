# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Offline correctness evaluation of the Bitcoin quantum-risk module.

Run from the repo root: ``uv run python scripts/bitcoin_eval.py`` (add ``--check`` to compare with the
committed report instead of writing it). It needs no network and writes ``docs/benchmarks/bitcoin.json``.

What it measures: address parsing and type classification against official test vectors, and the risk and
key-exposure rating of every category the module reports, on synthetic inputs built here. What it cannot
measure: whether a real address has spent from itself. That needs chain data, so it is not evaluated.

Vector sources (all copied verbatim; none was written for this evaluation):

* Bitcoin Core ``src/test/data/base58_encode_decode.json``, ``key_io_valid.json`` and ``key_io_invalid.json``,
  MIT licence, https://github.com/bitcoin/bitcoin/tree/master/src/test/data (copies in ``scripts/bitcoin_vectors``).
* BIP-173 and BIP-350 test vectors, BSD-2-Clause (``scripts/bitcoin_bip_vectors.py``).
* BIP-341 ``wallet-test-vectors.json``, ``scriptPubKey`` section, BSD-3-Clause,
  https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json.

Generated, not official: BIP-13 defines only version bytes 5 and 196 and the leading characters 3 and 2, with
no published vectors, so those cases are built here. Raw public-key cases are built with a pure-Python
secp256k1 multiplication. The risk matrix is a synthetic specification written from ``risk.py``'s documented
rules.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import bitcoin_bip_vectors as bip  # noqa: E402

from kestrix.bitcoin import chain  # noqa: E402
from kestrix.bitcoin.address import (  # noqa: E402
    Bech32Encoding,
    ParsedAddress,
    base58_decode,
    bech32_decode,
    decode_segwit,
    parse_address,
)
from kestrix.bitcoin.chain import MempoolClient  # noqa: E402
from kestrix.bitcoin.models import AddressType, ChainActivity, KeyExposure, Network, Risk  # noqa: E402
from kestrix.bitcoin.risk import HASH_TYPES, assess, scan  # noqa: E402
from kestrix.core.errors import Rejected  # noqa: E402

VECTORS = ROOT / "scripts" / "bitcoin_vectors"
REPORT = ROOT / "docs" / "benchmarks" / "bitcoin.json"

Failure = str | None  # None means the case passed; a string says why it failed


def _load(name: str) -> Any:
    return json.loads((VECTORS / name).read_text())


def _parse(text: str) -> ParsedAddress | None:
    try:
        return parse_address(text)
    except Rejected:
        return None


def _rejected(text: str) -> Failure:
    parsed = _parse(text)
    return None if parsed is None else f"accepted as {parsed.address_type.value}"


# --- official vectors ----------------------------------------------------------------


def base58_decode_vectors() -> list[tuple[str, Failure]]:
    out: list[tuple[str, Failure]] = []
    for hex_bytes, encoded in _load("base58_encode_decode.json"):
        ok = base58_decode(encoded) == bytes.fromhex(hex_bytes)
        out.append((encoded or "(empty)", None if ok else "decoded to different bytes"))
    return out


def _script_kind(script: bytes) -> tuple[AddressType | None, bytes]:
    """The output type and payload a scriptPubKey encodes, or ``(None, program)`` for undefined witness versions."""
    if script[:3] == b"\x76\xa9\x14":
        return AddressType.P2PKH, script[3:23]
    if script[:2] == b"\xa9\x14":
        return AddressType.P2SH, script[2:22]
    version = 0 if script[0] == 0 else script[0] - 0x50
    program = script[2:]
    if version == 0:
        return (AddressType.P2WPKH if len(program) == 20 else AddressType.P2WSH), program
    if version == 1 and len(program) == 32:
        return AddressType.P2TR, program
    return None, program


_CORE_NETWORK = {"main": Network.MAINNET, "regtest": None}  # regtest depends on the encoding (see below)


def _expected_network(chain_name: str, address: str) -> Network:
    if chain_name == "main":
        return Network.MAINNET
    if chain_name == "regtest" and address.lower().startswith("bcrt1"):
        return Network.REGTEST
    return Network.TEST  # testnet, signet and Base58 regtest share their encoding


def _core_valid(kind: str) -> list[tuple[str, Failure]]:
    out: list[tuple[str, Failure]] = []
    for address, script_hex, meta in _load("key_io_valid.json"):
        if meta["isPrivkey"]:
            continue
        expected_type, payload = _script_kind(bytes.fromhex(script_hex))
        is_base58 = expected_type in (AddressType.P2PKH, AddressType.P2SH)
        is_defined_segwit = expected_type in (AddressType.P2WPKH, AddressType.P2WSH, AddressType.P2TR)
        if kind == "base58" and not is_base58:
            continue
        if kind == "segwit" and not is_defined_segwit:
            continue
        if kind == "future" and expected_type is not None:
            continue
        parsed = _parse(address)
        if kind == "future":
            out.append((address, None if parsed is None else f"accepted as {parsed.address_type.value}"))
        elif parsed is None:
            out.append((address, "rejected"))
        elif parsed.address_type is not expected_type:
            out.append(
                (address, f"classified {parsed.address_type.value}, expected {expected_type and expected_type.value}")
            )
        elif parsed.network is not _expected_network(meta["chain"], address):
            out.append((address, f"network {parsed.network}"))
        elif parsed.payload != payload:
            out.append((address, "payload differs from the scriptPubKey"))
        else:
            out.append((address, None))
    return out


def core_base58_addresses() -> list[tuple[str, Failure]]:
    return _core_valid("base58")


def core_segwit_addresses() -> list[tuple[str, Failure]]:
    return _core_valid("segwit")


def core_undefined_witness_versions() -> list[tuple[str, Failure]]:
    return _core_valid("future")


def core_wif_keys() -> list[tuple[str, Failure]]:
    return [(a, _rejected(a)) for a, _, meta in _load("key_io_valid.json") if meta["isPrivkey"]]


def core_invalid() -> list[tuple[str, Failure]]:
    return [(entry[0] or "(empty)", _rejected(entry[0])) for entry in _load("key_io_invalid.json")]


def _bech32_case(text: str, expected: Bech32Encoding | None) -> Failure:
    try:
        encoding = bech32_decode(text)[2]
    except ValueError:
        return None if expected is None else "rejected a valid string"
    return "accepted an invalid string" if expected is None else (None if encoding is expected else "wrong encoding")


def bip173_bip350_strings() -> list[tuple[str, Failure]]:
    cases: list[tuple[str, Failure]] = []
    cases += [(t, _bech32_case(t, Bech32Encoding.BECH32)) for t in bip.BECH32_VALID]
    cases += [(t, _bech32_case(t, Bech32Encoding.BECH32M)) for t in bip.BECH32M_VALID]
    cases += [(t, _bech32_case(t, None)) for t in bip.BECH32_INVALID + bip.BECH32M_INVALID]
    return cases


def bip173_bip350_segwit_valid() -> list[tuple[str, Failure]]:
    out: list[tuple[str, Failure]] = []
    for address, script_hex in bip.SEGWIT_VALID:
        try:
            _, version, program = decode_segwit(address)
        except ValueError as exc:
            out.append((address, f"rejected: {exc}"))
            continue
        script = bytes([version + 0x50 if version else 0, len(program)]) + program
        out.append((address, None if script.hex() == script_hex else "scriptPubKey differs"))
    return out


def bip173_bip350_segwit_invalid() -> list[tuple[str, Failure]]:
    return [(a, _rejected(a)) for a in bip.SEGWIT_INVALID]


def bip341_taproot() -> list[tuple[str, Failure]]:
    out: list[tuple[str, Failure]] = []
    for vector in _load("bip341_scriptpubkey.json")["scriptPubKey"]:
        address = vector["expected"]["bip350Address"]
        output_key = bytes.fromhex(vector["intermediary"]["tweakedPubkey"])
        parsed = _parse(address)
        if parsed is None:
            out.append((address, "rejected"))
        elif (parsed.address_type, parsed.network, parsed.payload) != (AddressType.P2TR, Network.MAINNET, output_key):
            out.append((address, "wrong type, network or output key"))
        elif bytes([0x51, 0x20]) + parsed.payload != bytes.fromhex(vector["expected"]["scriptPubKey"]):
            out.append((address, "scriptPubKey differs"))
        else:
            assessed = assess(parsed)
            ok = (assessed.risk, assessed.key_exposure) == (Risk.HIGH, KeyExposure.EXPOSED)
            out.append((address, None if ok else "not rated high/exposed"))
    return out


# --- generated cases -----------------------------------------------------------------


def _b58check(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(payload + checksum, "big")
    digits = ""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    while number:
        number, rem = divmod(number, 58)
        digits = alphabet[rem] + digits
    return "1" * (len(payload + checksum) - len((payload + checksum).lstrip(b"\x00"))) + digits


def bip13_p2sh() -> list[tuple[str, Failure]]:
    """BIP-13: version 5 gives a leading 3 on mainnet, version 196 a leading 2 on test networks."""
    hashes = [bytes(20), b"\xff" * 20] + [hashlib.sha256(bytes([i])).digest()[:20] for i in range(48)]
    out: list[tuple[str, Failure]] = []
    for version, lead, network in ((5, "3", Network.MAINNET), (196, "2", Network.TEST)):
        for digest in hashes:
            address = _b58check(bytes([version]) + digest)
            parsed = _parse(address)
            if parsed is None:
                out.append((address, "rejected"))
            elif not address.startswith(lead):
                out.append((address, f"does not start with {lead}"))
            elif (parsed.address_type, parsed.network, parsed.payload) != (AddressType.P2SH, network, digest):
                out.append((address, "wrong type, network or script hash"))
            else:
                out.append((address, None))
    return out


_P = 2**256 - 2**32 - 977
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _add(a: tuple[int, int] | None, b: tuple[int, int] | None) -> tuple[int, int] | None:
    if a is None or b is None:
        return a or b
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    slope = (3 * a[0] * a[0] * pow(2 * a[1], -1, _P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, _P)) % _P
    x = (slope * slope - a[0] - b[0]) % _P
    return x, (slope * (a[0] - x) - a[1]) % _P


def _multiples(count: int) -> list[tuple[int, int]]:
    point: tuple[int, int] | None = None
    out = []
    for _ in range(count):
        point = _add(point, (_GX, _GY))
        assert point is not None
        out.append(point)
    return out


def raw_public_keys() -> list[tuple[str, Failure]]:
    out: list[tuple[str, Failure]] = []
    for x, y in _multiples(25):
        for sec in (
            bytes([2 + (y & 1)]) + x.to_bytes(32, "big"),
            b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"),
        ):
            parsed = _parse(sec.hex())
            ok = parsed is not None and (parsed.address_type, parsed.network, parsed.payload) == (
                AddressType.P2PK,
                None,
                sec,
            )
            out.append((sec.hex(), None if ok else "valid key not classified P2PK"))
    x = next(x for x in range(1, 100) if pow((x**3 + 7) % _P, (_P - 1) // 2, _P) != 1)  # no square root: off the curve
    g = _GX.to_bytes(32, "big")
    invalid = [
        b"\x02" + x.to_bytes(32, "big"),  # x not on the curve
        b"\x05" + g,  # unknown prefix
        b"\x04" + g,  # uncompressed prefix on 33 bytes
        b"\x02" + _P.to_bytes(32, "big"),  # x not below the field prime
        b"\x04" + g + (_GY + 1).to_bytes(32, "big"),  # y off the curve
        b"\x04" + g + _P.to_bytes(32, "big"),  # y not below the field prime
        b"\x00" + g,  # zero prefix
        b"\x02" + g[:-1] + b"\x00" * 2,  # 34 bytes
    ]
    out += [(k.hex(), _rejected(k.hex()) if len(k) in (33, 65) else "length not tested here") for k in invalid[:-1]]
    out.append((invalid[-1].hex(), _rejected(invalid[-1].hex())))
    return out


# --- risk categories -----------------------------------------------------------------

_Sample = tuple[str, ParsedAddress]


def _samples() -> dict[str, list[_Sample]]:
    """One real, valid address per output type and public network, taken from the official vectors."""
    found: dict[str, list[_Sample]] = {}
    for address, script_hex, meta in _load("key_io_valid.json"):
        if meta["isPrivkey"] or meta["chain"] not in ("main", "testnet4", "regtest"):
            continue
        kind, _ = _script_kind(bytes.fromhex(script_hex))
        parsed = _parse(address)
        if kind is None or parsed is None:
            continue
        key = f"{kind.value}/{parsed.network.value if parsed.network else '?'}"
        found.setdefault(key, []).append((address, parsed))
    return found


def _activity(spent: int, balance: int) -> ChainActivity:
    return ChainActivity(chain="mainnet", funded_outputs=spent + 1, spent_outputs=spent, balance_sats=balance)


def risk_matrix() -> list[tuple[str, Failure]]:
    """Every (address type, spend-history state) the module can report, against the documented rating."""
    samples = _samples()
    out: list[tuple[str, Failure]] = []

    def check(label: str, got: tuple[Risk, KeyExposure], want: tuple[Risk, KeyExposure]) -> None:
        out.append((label, None if got == want else f"got {got[0].value}/{got[1].value}"))

    pk = ParsedAddress("02" + "11" * 32, AddressType.P2PK, None, b"")
    for label, activity in (
        ("no lookup", None),
        ("lookup never spent", _activity(0, 5000)),
        ("lookup spent", _activity(3, 0)),
    ):
        a = assess(pk, activity)
        check(f"P2PK, {label}", (a.risk, a.key_exposure), (Risk.CRITICAL, KeyExposure.EXPOSED))
    for key, items in samples.items():
        kind = AddressType(key.split("/")[0])
        _, parsed = items[0]
        if kind is AddressType.P2TR:
            for label, activity in (("no lookup", None), ("lookup never spent", _activity(0, 5000))):
                a = assess(parsed, activity)
                check(
                    f"P2TR {parsed.network.value if parsed.network else ''}, {label}",
                    (a.risk, a.key_exposure),
                    (Risk.HIGH, KeyExposure.EXPOSED),
                )
        elif kind in HASH_TYPES:
            net = parsed.network.value if parsed.network else ""
            unknown = (Risk.UNKNOWN, KeyExposure.UNKNOWN)
            a = assess(parsed, None)
            check(f"{kind.value} {net}, no lookup", (a.risk, a.key_exposure), unknown)
            a = assess(parsed, None, lookup_requested=True)
            want = unknown
            check(f"{kind.value} {net}, lookup requested but unavailable", (a.risk, a.key_exposure), want)
            if parsed.network is Network.REGTEST:
                out.append(
                    (
                        f"{kind.value} regtest, explanation names regtest",
                        None if "Regtest" in a.explanation else "missing",
                    )
                )
                continue
            a = assess(parsed, _activity(0, 5000))
            check(f"{kind.value} {net}, never spent", (a.risk, a.key_exposure), (Risk.LOW, KeyExposure.NOT_EXPOSED))
            a = assess(parsed, _activity(2, 700))
            check(
                f"{kind.value} {net}, spent from with balance",
                (a.risk, a.key_exposure),
                (Risk.HIGH, KeyExposure.EXPOSED),
            )
            out.append(
                (
                    f"{kind.value} {net}, spent with balance recommends moving it",
                    None if "700 sats" in a.recommendation else "no balance in advice",
                )
            )
            a = assess(parsed, _activity(2, 0))
            check(
                f"{kind.value} {net}, spent from and empty", (a.risk, a.key_exposure), (Risk.HIGH, KeyExposure.EXPOSED)
            )
    return out


def scan_lookup_policy() -> list[tuple[str, Failure]]:
    """``scan`` asks for spend history only for hash-based types on public chains, and summarises correctly."""
    pool = [item for items in _samples().values() for item in items]
    out: list[tuple[str, Failure]] = []
    for lookup_on in (False, True):
        looked: list[str] = []

        def lookup(parsed: ParsedAddress, looked: list[str] = looked) -> ChainActivity:
            looked.append(parsed.text)
            return _activity(0, 1)

        result = scan([a for a, _ in pool], lookup if lookup_on else None)
        expected = [
            a
            for a, p in pool
            if lookup_on and p.address_type in HASH_TYPES and p.network in (Network.MAINNET, Network.TEST)
        ]
        out.append(
            (
                f"lookup {'on' if lookup_on else 'off'}: queried exactly the eligible addresses",
                None if looked == expected else f"queried {len(looked)}, expected {len(expected)}",
            )
        )
        counts = {risk: sum(r.risk is risk for r in result.results) for risk in Risk}
        out.append(
            (
                f"lookup {'on' if lookup_on else 'off'}: summary counts match results",
                None if counts == result.summary.by_risk and result.summary.total == len(pool) else "summary differs",
            )
        )
    return out


def _stats_body(*, funded: int, spent: int, pending_spent: int) -> bytes:
    zero = {"funded_txo_count": 0, "funded_txo_sum": 0, "spent_txo_count": 0, "spent_txo_sum": 0}
    confirmed = {
        "funded_txo_count": funded,
        "funded_txo_sum": 5000,
        "spent_txo_count": spent,
        "spent_txo_sum": 1000 * spent,
    }
    return json.dumps({"chain_stats": confirmed, "mempool_stats": {**zero, "spent_txo_count": pending_spent}}).encode()


def chain_interpretation_fixtures() -> list[tuple[str, Failure]]:
    """How the module turns mempool.space-shaped bodies into a rating. The bodies are hand-written, not chain data."""
    address = _samples()["P2WPKH/mainnet"][0][1]
    cases = [
        ("never spent", _stats_body(funded=1, spent=0, pending_spent=0), (Risk.LOW, KeyExposure.NOT_EXPOSED)),
        (
            "spent in a confirmed block",
            _stats_body(funded=1, spent=1, pending_spent=0),
            (Risk.HIGH, KeyExposure.EXPOSED),
        ),
        (
            "spent only in the mempool",
            _stats_body(funded=1, spent=0, pending_spent=1),
            (Risk.HIGH, KeyExposure.EXPOSED),
        ),
    ]
    out: list[tuple[str, Failure]] = []
    original = chain.check_url
    chain.check_url = lambda url, *, allow_private=False: ("mempool.space", 443, ["192.0.2.1"])  # type: ignore[assignment]  # no DNS
    try:
        for label, body, want in cases:
            transport = httpx.MockTransport(lambda request, body=body: httpx.Response(200, content=body))
            with MempoolClient(transport=transport) as client:
                result = assess(address, client.activity(address))
            out.append(
                (
                    label,
                    None
                    if (result.risk, result.key_exposure) == want
                    else f"got {result.risk.value}/{result.key_exposure.value}",
                )
            )
    finally:
        chain.check_url = original
    return out


CATEGORIES: list[tuple[str, str, str, Callable[[], list[tuple[str, Failure]]]]] = [
    ("base58_decode", "Base58 decoding", "official: Bitcoin Core base58_encode_decode.json", base58_decode_vectors),
    (
        "core_base58_addresses",
        "Base58Check P2PKH and P2SH addresses (main, test)",
        "official: Bitcoin Core key_io_valid.json",
        core_base58_addresses,
    ),
    (
        "core_segwit_addresses",
        "Segwit v0 and v1 addresses (P2WPKH, P2WSH, P2TR; main, test, regtest)",
        "official: Bitcoin Core key_io_valid.json",
        core_segwit_addresses,
    ),
    (
        "core_undefined_witness",
        "Valid segwit encodings with no defined output type (v1 with a non-32-byte program, v2 to v16): must be refused",
        "official: Bitcoin Core key_io_valid.json",
        core_undefined_witness_versions,
    ),
    (
        "core_wif_keys",
        "WIF private keys: must be refused as addresses",
        "official: Bitcoin Core key_io_valid.json",
        core_wif_keys,
    ),
    ("core_invalid", "Invalid addresses", "official: Bitcoin Core key_io_invalid.json", core_invalid),
    (
        "bip173_bip350_strings",
        "Bech32 and Bech32m strings (valid and invalid)",
        "official: BIP-173, BIP-350",
        bip173_bip350_strings,
    ),
    (
        "bip173_bip350_segwit_valid",
        "Valid segwit addresses decode to the published scriptPubKey",
        "official: BIP-350 (supersedes BIP-173)",
        bip173_bip350_segwit_valid,
    ),
    (
        "bip173_bip350_segwit_invalid",
        "Invalid segwit addresses",
        "official: BIP-173, BIP-350",
        bip173_bip350_segwit_invalid,
    ),
    (
        "bip341_taproot",
        "Taproot addresses for the BIP-341 output keys, rated high and exposed",
        "official: BIP-341 wallet-test-vectors.json",
        bip341_taproot,
    ),
    (
        "bip13_p2sh",
        "P2SH version bytes 5 and 196 give leading 3 and 2 and classify as P2SH",
        "generated from BIP-13 (no official vectors exist)",
        bip13_p2sh,
    ),
    (
        "raw_public_keys",
        "Raw public keys: 50 valid secp256k1 keys (25 points, both encodings) and 8 invalid keys",
        "generated (pure-Python secp256k1)",
        raw_public_keys,
    ),
    (
        "risk_matrix",
        "Risk and key exposure for every address type and spend-history state, unknown cases included",
        "synthetic specification from risk.py's documented rules",
        risk_matrix,
    ),
    (
        "scan_lookup_policy",
        "scan() queries spend history only where it can change the answer, and its summary is consistent",
        "synthetic",
        scan_lookup_policy,
    ),
    (
        "chain_interpretation_fixtures",
        "Spend-history bodies (never spent, confirmed spend, mempool-only spend) give the documented rating",
        "synthetic bodies, not chain data",
        chain_interpretation_fixtures,
    ),
]


def evaluate() -> dict[str, Any]:
    categories = []
    for ident, title, source, run in CATEGORIES:
        cases = run()
        failures = [{"case": name, "detail": detail} for name, detail in cases if detail is not None]
        categories.append(
            {
                "id": ident,
                "title": title,
                "source": source,
                "cases": len(cases),
                "passed": len(cases) - len(failures),
                "failures": failures,
            }
        )
    total = sum(c["cases"] for c in categories)
    passed = sum(c["passed"] for c in categories)
    return {
        "schema_version": 1,
        "generated_by": "scripts/bitcoin_eval.py",
        "network_used": False,
        "cases": total,
        "passed": passed,
        "categories": categories,
        "not_measured": [
            "Whether a real address has spent from itself (needs chain data).",
            "Whether the same key is reused across address types (needs chain data).",
            "Any prediction of when a quantum computer could break a key.",
        ],
    }


def main(argv: list[str]) -> int:
    report = evaluate()
    text = json.dumps(report, indent=2) + "\n"
    if "--check" in argv:
        return 0 if REPORT.read_text() == text else 1
    REPORT.write_text(text)
    for c in report["categories"]:
        print(f"{c['passed']:>4}/{c['cases']:<4} {c['id']}")
    print(f"{report['passed']}/{report['cases']} total")
    return 0 if report["passed"] == report["cases"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
