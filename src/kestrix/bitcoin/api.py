"""HTTP routes for the Bitcoin module."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from . import guardian
from .chain import MempoolClient
from .migration import parse_address_type, plan_for
from .models import GuardianResult, MigrationPlan, PublicTestnet, ScanResult
from .risk import MAX_BATCH, scan

router = APIRouter(prefix="/api/bitcoin", tags=["bitcoin"])

ChainClientFactory = Callable[[PublicTestnet], MempoolClient]
Classifier = Callable[[str], GuardianResult]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    addresses: list[Annotated[str, StringConstraints(max_length=200)]] = Field(min_length=1, max_length=MAX_BATCH)
    lookup_chain: bool = False
    testnet: PublicTestnet = PublicTestnet.TESTNET4


class GuardianRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=guardian.MAX_MESSAGE_CHARS)


def chain_client_factory() -> ChainClientFactory:
    """Dependency so tests can swap in a client backed by a mock transport."""

    def make(testnet: PublicTestnet) -> MempoolClient:
        return MempoolClient(testnet=testnet)

    return make


@router.post("/scan")
def scan_addresses(
    body: ScanRequest, make_client: Annotated[ChainClientFactory, Depends(chain_client_factory)]
) -> ScanResult:
    if not body.lookup_chain:
        return scan(body.addresses)
    with make_client(body.testnet) as client:
        return scan(body.addresses, lookup=client.activity)


@router.get("/migration/{address_type}")
def migration_plan(address_type: str) -> MigrationPlan:
    return plan_for(parse_address_type(address_type))


def guardian_classifier() -> Classifier:
    """Dependency so tests can swap in a fake model. The key is checked per request, after body validation."""
    return lambda message: guardian.classify_intent(message, guardian.build_client())


@router.post("/guardian")
def classify(body: GuardianRequest, classifier: Annotated[Classifier, Depends(guardian_classifier)]) -> GuardianResult:
    return classifier(body.message)
