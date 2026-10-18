# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Autouse safety nets: no test resolves DNS, reaches a host, or sees the user's real Anthropic key."""

from __future__ import annotations

import pytest

from kestrix.bitcoin import chain
from kestrix.core import config


@pytest.fixture(autouse=True)
def no_dns(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the netguard check (which resolves DNS) with a recorder."""
    checked: list[str] = []

    def fake_check(url: str, *, allow_private: bool = False) -> tuple[str, int, list[str]]:
        checked.append(url)
        return "mempool.space", 443, ["192.0.2.1"]

    monkeypatch.setattr(chain, "check_url", fake_check)
    return checked


@pytest.fixture(autouse=True)
def no_real_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "anthropic_key", lambda: None)
