# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""TextEnum behaves like enum.StrEnum on every supported Python: str(), format() and JSON give the value."""

import json

import pytest
from pydantic import BaseModel

from kestrix.bitcoin.models import AddressType, GuardianIntent, KeyExposure, Network, PublicTestnet, Risk
from kestrix.core.enums import TextEnum
from kestrix.core.errors import Reason, Rejected
from kestrix.detect.diagnose import Family
from kestrix.detect.workflow import Outcome
from kestrix.webcheck.cli import SiteType

ENUMS = [AddressType, GuardianIntent, KeyExposure, Network, PublicTestnet, Risk, Reason, Family, Outcome, SiteType]


@pytest.mark.parametrize("enum", ENUMS, ids=lambda e: e.__name__)
def test_members_render_as_their_value(enum: type[TextEnum]) -> None:
    assert issubclass(enum, TextEnum)
    for member in enum:
        assert isinstance(member, str) and member == member.value
        assert str(member) == f"{member}" == format(member) == "{}".format(member) == member.value  # noqa: UP032
        assert f"{member:>3}" == f"{member.value:>3}"
        assert json.dumps(member) == json.dumps(member.value)
        assert enum(member.value) is member


def test_rejected_message_uses_the_reason_value() -> None:
    assert str(Rejected(Reason.INVALID_INPUT, "bad")) == "invalid_input: bad"


def test_pydantic_dumps_the_value() -> None:
    class Model(BaseModel):
        outcome: Outcome

    assert Model(outcome=Outcome.REPAIRED).model_dump_json() == '{"outcome":"repaired"}'
    assert Model.model_validate({"outcome": "repaired"}).outcome is Outcome.REPAIRED
