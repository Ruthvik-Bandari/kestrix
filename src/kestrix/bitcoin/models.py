# SPDX-FileCopyrightText: 2026 Ruthvik Bandari and the BitShield (Team ACE) contributors
# SPDX-License-Identifier: Apache-2.0
"""Result types shared by the Bitcoin scanner, migration planner, API and CLI."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .. import ATTRIBUTION
from ..core.enums import TextEnum


class AddressType(TextEnum):
    P2PK = "P2PK"
    P2PKH = "P2PKH"
    P2SH = "P2SH"
    P2WPKH = "P2WPKH"
    P2WSH = "P2WSH"
    P2TR = "P2TR"


class Network(TextEnum):
    """Network an address belongs to, as far as its encoding reveals.

    Testnet3, testnet4 and signet share the ``tb`` Bech32 prefix and the Base58 version
    bytes, so they are indistinguishable; regtest Base58 addresses share them too and
    are reported as ``test``. Only Bech32 regtest addresses (``bcrt1``) are ``regtest``.
    """

    MAINNET = "mainnet"
    TEST = "test"
    REGTEST = "regtest"


class PublicTestnet(TextEnum):
    """Public test chain to query on mempool.space for ``test`` network addresses."""

    TESTNET4 = "testnet4"
    SIGNET = "signet"


class Risk(TextEnum):
    CRITICAL = "critical"
    HIGH = "high"
    LOW = "low"
    UNKNOWN = "unknown"


class KeyExposure(TextEnum):
    EXPOSED = "exposed"
    NOT_EXPOSED = "not_exposed"
    UNKNOWN = "unknown"


class ChainActivity(BaseModel):
    """Spend history of one address, confirmed plus unconfirmed (mempool)."""

    source: Literal["mempool.space"] = "mempool.space"
    chain: Literal["mainnet", "testnet4", "signet"]
    funded_outputs: int
    spent_outputs: int
    balance_sats: int


class AddressAssessment(BaseModel):
    input: str
    address_type: AddressType
    network: Network | None
    risk: Risk
    key_exposure: KeyExposure
    explanation: str
    recommendation: str
    chain_activity: ChainActivity | None


class ScanSummary(BaseModel):
    total: int
    by_risk: dict[Risk, int]


class ScanResult(BaseModel):
    generated_by: str = Field(default=ATTRIBUTION, description="Tool and author that produced this report.")
    results: list[AddressAssessment]
    summary: ScanSummary


class MigrationPlan(BaseModel):
    generated_by: str = Field(default=ATTRIBUTION, description="Tool and author that produced this report.")
    address_type: AddressType
    urgency: Literal["now", "if_spent"]
    summary: str
    steps: list[str]
    cautions: list[str]


class GuardianIntent(TextEnum):
    SCAN_ADDRESSES = "scan_addresses"
    EXPLAIN_RISK = "explain_risk"
    MIGRATION_HELP = "migration_help"
    SET_POLICY_REQUEST = "set_policy_request"
    UNKNOWN = "unknown"


class GuardianResult(BaseModel):
    """Intent classification. ``model_summary`` is model-written text and is untrusted;
    every other field is either validated or produced by Kestrix itself."""

    generated_by: str = Field(default=ATTRIBUTION, description="Tool and author that produced this report.")

    intent: GuardianIntent
    addresses: list[str]
    ignored_addresses: list[str]
    address_type: AddressType | None
    model_summary: str
    next_step: str
    model: str
