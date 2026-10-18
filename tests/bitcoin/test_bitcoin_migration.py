# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from kestrix.bitcoin.migration import parse_address_type, plan_for
from kestrix.bitcoin.models import AddressType
from kestrix.core.errors import Reason, Rejected


def test_p2pk_plan_is_urgent_and_explains_sweeping() -> None:
    plan = plan_for(AddressType.P2PK)
    assert plan.urgency == "now"
    assert any("pk()" in step for step in plan.steps)


def test_p2tr_plan_warns_that_script_only_taproot_does_not_help() -> None:
    plan = plan_for(AddressType.P2TR)
    assert plan.urgency == "now"
    assert "does not help" in plan.cautions[0]


@pytest.mark.parametrize("address_type", [AddressType.P2PKH, AddressType.P2SH, AddressType.P2WPKH, AddressType.P2WSH])
def test_hash_type_plans_depend_on_spend_history(address_type: AddressType) -> None:
    plan = plan_for(address_type)
    assert plan.urgency == "if_spent"
    assert "never been spent from" in plan.summary


@pytest.mark.parametrize("address_type", list(AddressType))
def test_every_plan_has_core_steps_and_safety_cautions(address_type: AddressType) -> None:
    plan = plan_for(address_type)
    text = " ".join(plan.steps)
    assert "entire balance" in text
    assert "mempool" in text
    assert any("seed phrase" in c for c in plan.cautions)
    assert any("BIP-360" in c and "draft" in c for c in plan.cautions)


def test_plans_do_not_share_mutable_lists() -> None:
    plan_for(AddressType.P2WPKH).steps.append("tampered")
    assert "tampered" not in plan_for(AddressType.P2WPKH).steps


@pytest.mark.parametrize(("text", "expected"), [("p2tr", AddressType.P2TR), (" P2wpkh ", AddressType.P2WPKH)])
def test_parse_address_type_is_case_insensitive(text: str, expected: AddressType) -> None:
    assert parse_address_type(text) is expected


def test_unknown_address_type_is_rejected() -> None:
    with pytest.raises(Rejected) as info:
        parse_address_type("P2QRH")
    assert info.value.reason is Reason.INVALID_INPUT
    assert "P2TR" in info.value.detail
