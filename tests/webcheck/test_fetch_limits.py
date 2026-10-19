# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The web check's overall deadlines, DNS timeout, port restriction and generic errors.

Servers here listen on 127.0.0.1 only, with ``allow_private`` (as a lab target would be).
"""

import socket
import threading
import time
from collections.abc import Callable

import httpx
import pytest

from kestrix.core.errors import Reason, Rejected
from kestrix.core.netguard import check_url
from kestrix.webcheck.fetch import GENERIC_UNREACHABLE, fetch, tls_probe

HOSTED_PORTS = frozenset({80, 443})


def serve(handler: Callable[[socket.socket], None]) -> int:
    """Run ``handler`` for each connection on a local port; return the port."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)

    def loop() -> None:
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return listener.getsockname()[1]


def drip(prefix: bytes) -> Callable[[socket.socket], None]:
    def handler(conn: socket.socket) -> None:
        conn.recv(65536)
        try:
            conn.sendall(prefix)
            for _ in range(100):
                conn.sendall(b"a")
                time.sleep(0.2)
        except OSError:
            pass
        conn.close()

    return handler


@pytest.mark.parametrize(
    "prefix",
    [b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n", b"HTTP/1.1 200 OK\r\nX-Slow: "],
    ids=["body", "headers"],
)
def test_fetch_has_one_overall_deadline(prefix):
    port = serve(drip(prefix))
    started = time.monotonic()
    with pytest.raises(Rejected) as exc:
        fetch(f"http://127.0.0.1:{port}/", allow_private=True, timeout=1.0)
    assert exc.value.reason is Reason.TARGET_UNREACHABLE
    assert time.monotonic() - started < 2.0


def test_tls_probe_has_one_overall_deadline():
    port = serve(drip(b"\x16\x03\x01"))  # starts like a TLS record, then drips
    started = time.monotonic()
    info = tls_probe("site.test", "127.0.0.1", port, timeout=1.0)
    assert info.status == "handshake_failed"
    assert time.monotonic() - started < 2.0


def test_dns_lookup_has_a_timeout(monkeypatch):
    real = socket.getaddrinfo

    def slow(*args, **kwargs):
        time.sleep(1.5)
        return real(*args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", slow)
    started = time.monotonic()
    with pytest.raises(Rejected) as exc:
        check_url("http://site.test/", resolve_timeout=0.2)
    assert exc.value.reason is Reason.TARGET_UNREACHABLE and "timed out" in exc.value.detail
    assert time.monotonic() - started < 1.0


def test_invalid_dns_name_is_invalid_url():
    with pytest.raises(Rejected) as exc:
        check_url("http://" + "a" * 64 + ".example/")
    assert exc.value.reason is Reason.INVALID_URL


def test_a_broken_body_is_an_upstream_error(fake_dns):
    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            yield b"partial"
            raise httpx.ReadError("connection reset")

    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=Broken()))
    with pytest.raises(Rejected) as exc:
        fetch("http://site.test/", transport=transport)
    assert exc.value.reason is Reason.UPSTREAM_ERROR
    with pytest.raises(Rejected) as exc:
        fetch("http://site.test/", transport=transport, generic_errors=True)
    assert (exc.value.reason, exc.value.detail) == (Reason.TARGET_UNREACHABLE, GENERIC_UNREACHABLE)


def test_only_allowed_ports_on_every_hop(fake_dns):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "http://site.test:22/"}, stream=httpx.ByteStream(b""))

    transport = httpx.MockTransport(handler)
    with pytest.raises(Rejected) as exc:
        fetch("http://site.test:22/", transport=transport, allowed_ports=HOSTED_PORTS)
    assert exc.value.reason is Reason.TARGET_NOT_ALLOWED and seen == []
    with pytest.raises(Rejected) as exc:
        fetch("https://site.test/", transport=transport, allowed_ports=HOSTED_PORTS)
    assert exc.value.reason is Reason.TARGET_NOT_ALLOWED and len(seen) == 1  # the redirect to :22 is refused
    with pytest.raises(Rejected) as exc:
        fetch("http://site.test:22/", transport=transport)  # local mode: any port
    assert exc.value.reason is Reason.UPSTREAM_ERROR  # the redirect loop, not the port


def ssh_banner(conn: socket.socket) -> None:
    conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
    conn.recv(1024)
    conn.close()


def closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_generic_errors_hide_what_is_on_a_port():
    banner, closed = serve(ssh_banner), closed_port()
    local = []
    for port in (closed, banner):
        with pytest.raises(Rejected) as exc:
            fetch(f"http://127.0.0.1:{port}/", allow_private=True)
        local.append(exc.value.reason)
        with pytest.raises(Rejected) as exc:
            fetch(f"http://127.0.0.1:{port}/", allow_private=True, generic_errors=True)
        assert (exc.value.reason, exc.value.detail) == (Reason.TARGET_UNREACHABLE, GENERIC_UNREACHABLE)
    assert local == [Reason.TARGET_UNREACHABLE, Reason.UPSTREAM_ERROR]  # local mode keeps the detail
