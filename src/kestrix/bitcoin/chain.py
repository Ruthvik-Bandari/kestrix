# SPDX-FileCopyrightText: 2026 Ruthvik Bandari and the BitShield (Team ACE) contributors
# SPDX-License-Identifier: Apache-2.0
"""Optional spend-history lookup on the public mempool.space API.

Only used when the user asks for it: the queried addresses are sent to mempool.space.
Every request URL passes ``netguard.check_url``; redirects are not followed, responses
are size-capped and schema-validated, and any failure is ``Rejected(UPSTREAM_ERROR)``.
"""

from __future__ import annotations

from types import TracebackType
from typing import Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from ..core.errors import Reason, Rejected
from ..core.netguard import check_url
from .address import ParsedAddress
from .models import ChainActivity, Network, PublicTestnet

MEMPOOL_BASE_URL = "https://mempool.space"
TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 64 * 1024

ChainName = Literal["mainnet", "testnet4", "signet"]
_API_PREFIX: dict[ChainName, str] = {"mainnet": "/api", "testnet4": "/testnet4/api", "signet": "/signet/api"}


class _TxoStats(BaseModel):
    funded_txo_count: int = Field(ge=0)
    funded_txo_sum: int = Field(ge=0)
    spent_txo_count: int = Field(ge=0)
    spent_txo_sum: int = Field(ge=0)


class _AddressStats(BaseModel):
    chain_stats: _TxoStats
    mempool_stats: _TxoStats


class MempoolClient:
    """Looks up address spend history. Use as a context manager to close the connection pool."""

    def __init__(
        self,
        *,
        base_url: str = MEMPOOL_BASE_URL,
        testnet: PublicTestnet = PublicTestnet.TESTNET4,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._testnet = testnet
        self._http = httpx.Client(
            timeout=TIMEOUT_SECONDS,
            follow_redirects=False,
            transport=transport,
            headers={"Accept": "application/json"},
        )

    def __enter__(self) -> MempoolClient:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self._http.close()

    def _chain_for(self, network: Network | None) -> ChainName:
        if network is Network.MAINNET:
            return "mainnet"
        if network is Network.TEST:
            return "testnet4" if self._testnet is PublicTestnet.TESTNET4 else "signet"
        raise Rejected(Reason.INVALID_INPUT, "only mainnet and public test-network addresses can be looked up")

    def _get(self, url: str) -> bytes:
        check_url(url)
        try:
            with self._http.stream("GET", url) as response:
                if response.status_code == 429:
                    raise Rejected(
                        Reason.UPSTREAM_ERROR,
                        "mempool.space rate limit reached; try again later or scan fewer addresses",
                    )
                if response.status_code >= 500:
                    raise Rejected(Reason.UPSTREAM_ERROR, f"mempool.space server error (HTTP {response.status_code})")
                if response.status_code != 200:
                    raise Rejected(Reason.UPSTREAM_ERROR, f"mempool.space returned HTTP {response.status_code}")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise Rejected(Reason.UPSTREAM_ERROR, "mempool.space response exceeded the size limit")
                return bytes(body)
        except httpx.TimeoutException:
            raise Rejected(
                Reason.UPSTREAM_ERROR, f"mempool.space did not respond within {TIMEOUT_SECONDS:.0f} s"
            ) from None
        except httpx.HTTPError as exc:
            raise Rejected(Reason.UPSTREAM_ERROR, f"could not reach mempool.space: {type(exc).__name__}") from None

    def activity(self, parsed: ParsedAddress) -> ChainActivity:
        chain = self._chain_for(parsed.network)
        body = self._get(f"{self._base_url}{_API_PREFIX[chain]}/address/{parsed.text}")
        try:
            stats = _AddressStats.model_validate_json(body)
        except ValidationError:
            raise Rejected(Reason.UPSTREAM_ERROR, "mempool.space returned an unexpected response") from None
        confirmed, pending = stats.chain_stats, stats.mempool_stats
        return ChainActivity(
            chain=chain,
            funded_outputs=confirmed.funded_txo_count + pending.funded_txo_count,
            spent_outputs=confirmed.spent_txo_count + pending.spent_txo_count,
            balance_sats=confirmed.funded_txo_sum
            + pending.funded_txo_sum
            - confirmed.spent_txo_sum
            - pending.spent_txo_sum,
        )
