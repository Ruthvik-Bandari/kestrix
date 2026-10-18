# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import socket

import pytest

DNS = {"site.test": ["93.184.216.34"], "evil.test": ["10.0.0.5"], "rebind.test": ["127.0.0.1"]}


@pytest.fixture
def fake_dns(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host.strip("[]"))
            return real(host.strip("[]"), port, *args, **kwargs)
        except OSError:
            pass
        if host not in DNS:
            raise socket.gaierror(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in DNS[host]]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
