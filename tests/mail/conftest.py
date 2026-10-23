# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import pytest
from fastapi.testclient import TestClient

from kestrix.server.app import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(extra_hosts=frozenset({"testserver"})))


@pytest.fixture
def fake_mail():
    from mailbox_support import FakeMail

    return FakeMail()


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every host resolves to a public address, so the real ``netguard.check_url`` runs without DNS."""
    import socket

    monkeypatch.setattr(
        "kestrix.core.netguard._resolve",
        lambda host, port, timeout: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.80.46", port))],
    )


@pytest.fixture
def service(fake_mail, public_dns):
    from kestrix.mail.mailbox import MailboxService

    return MailboxService(fake_mail.transport())


@pytest.fixture
def mailbox_client(fake_mail, public_dns) -> TestClient:
    return TestClient(create_app(mailbox_transport=fake_mail.transport()), base_url="http://127.0.0.1:8765")
