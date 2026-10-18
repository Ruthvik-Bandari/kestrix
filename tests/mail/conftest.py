# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import pytest
from fastapi.testclient import TestClient

from kestrix.server.app import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(extra_hosts=frozenset({"testserver"})))
