# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Hosted-mode fixtures. The providers are an ``httpx.MockTransport``; no test touches the network."""

import httpx
import pytest
from fastapi.testclient import TestClient

from kestrix.server.app import create_app

from .hosted_support import (
    GITHUB_ID,
    GITHUB_SECRET,
    GOOGLE_ID,
    GOOGLE_SECRET,
    ORIGIN,
    PEPPER,
    Clock,
    FakeProviders,
)


@pytest.fixture
def hosted_env(monkeypatch, tmp_path):
    env = {
        "KESTRIX_MODE": "hosted",
        "KESTRIX_PUBLIC_ORIGIN": ORIGIN,
        "KESTRIX_SESSION_PEPPER": PEPPER,
        "KESTRIX_DB": str(tmp_path / "state" / "hosted.sqlite3"),
        "KESTRIX_GOOGLE_CLIENT_ID": GOOGLE_ID,
        "KESTRIX_GOOGLE_CLIENT_SECRET": GOOGLE_SECRET,
        "KESTRIX_GITHUB_CLIENT_ID": GITHUB_ID,
        "KESTRIX_GITHUB_CLIENT_SECRET": GITHUB_SECRET,
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return env


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def providers(clock):
    return FakeProviders(clock)


@pytest.fixture
def hosted(hosted_env, providers, clock):
    app = create_app(provider_transport=httpx.MockTransport(providers.handler))
    app.state.auth.clock = clock
    return TestClient(app, base_url=ORIGIN)
