"""Network side of the web check: one GET (plus up to five redirects) and one TLS handshake.

Every hop is validated with :func:`kestrix.core.netguard.check_url` and the request is
sent to the validated IP address (Host header and TLS SNI keep the real hostname), so a
DNS answer that changes between the check and the connection cannot redirect the request
to a private address.
"""

from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from .. import __version__
from ..core.errors import Reason, Rejected
from ..core.netguard import check_url
from .checks import Headers
from .models import Hop, TlsInfo

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1024 * 1024
TIMEOUT_S = 10.0
USER_AGENT = f"kestrix-webcheck/{__version__}"
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_OUTDATED = ("UNSUPPORTED_PROTOCOL", "TLSV1_ALERT_PROTOCOL_VERSION", "NO_PROTOCOLS_AVAILABLE", "WRONG_VERSION_NUMBER")
_VERIFY_CODES = {
    10: "expired",
    9: "not_yet_valid",
    62: "hostname_mismatch",
    18: "untrusted",
    19: "untrusted",
    20: "untrusted",
    21: "untrusted",
}

TlsProbe = Callable[[str, str, int, float], TlsInfo]


@dataclass
class FetchResult:
    final_url: str
    status_code: int | None
    headers: Headers
    chain: list[Hop] = field(default_factory=list)
    final_host: str = ""
    final_ip: str = ""
    final_port: int = 443
    body: bytes = b""  # final response only, at most MAX_BODY_BYTES; parsed for the site profile


def _is_tls_error(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, ssl.SSLError):
            return True
        current = current.__cause__ or current.__context__
    return False


def _headers(resp: httpx.Response) -> Headers:
    out: Headers = {}
    for name, value in resp.headers.multi_items():
        out.setdefault(name.lower(), []).append(value)
    return out


def fetch(
    url: str,
    *,
    allow_private: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> FetchResult:
    deadline = time.monotonic() + TIMEOUT_S
    chain: list[Hop] = []
    with httpx.Client(
        transport=transport, follow_redirects=False, trust_env=False, verify=httpx.create_ssl_context()
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            host, port, ips = check_url(url, allow_private=allow_private)
            target = httpx.URL(url)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Rejected(Reason.TARGET_UNREACHABLE, "timed out")
            request = httpx.Request(
                "GET",
                target.copy_with(host=ips[0]),
                headers={
                    "Host": target.netloc.decode(),
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,*/*",
                    # Uncompressed, so the bounded body read is the real page size.
                    "Accept-Encoding": "identity",
                },
                extensions={"sni_hostname": host, "timeout": httpx.Timeout(remaining).as_dict()},
            )
            started = time.monotonic()
            try:
                resp = client.send(request, stream=True)
            except httpx.ConnectError as exc:
                if _is_tls_error(exc):
                    return FetchResult(url, None, {}, chain, host, ips[0], port)
                raise Rejected(Reason.TARGET_UNREACHABLE, f"cannot connect to {host}") from None
            except httpx.TimeoutException:
                raise Rejected(Reason.TARGET_UNREACHABLE, f"{host} timed out") from None
            except httpx.HTTPError as exc:
                raise Rejected(Reason.UPSTREAM_ERROR, type(exc).__name__) from None
            body = bytearray()
            try:
                for chunk in resp.iter_raw():  # raw, never decompressed: no decompression bombs
                    body += chunk[: MAX_BODY_BYTES - len(body)]
                    if len(body) >= MAX_BODY_BYTES:
                        break
            finally:
                resp.close()
            chain.append(
                Hop(
                    url=url,
                    address=ips[0],
                    status_code=resp.status_code,
                    elapsed_ms=round((time.monotonic() - started) * 1000),
                )
            )
            location = resp.headers.get("location")
            if resp.status_code in _REDIRECTS and location:
                url = str(target.join(location))
                continue
            return FetchResult(url, resp.status_code, _headers(resp), chain, host, ips[0], port, bytes(body))
    raise Rejected(Reason.UPSTREAM_ERROR, f"more than {MAX_REDIRECTS} redirects")


def _issuer(cert: dict[str, Any]) -> str | None:
    parts = dict(item for rdn in cert.get("issuer", ()) for item in rdn)
    return parts.get("organizationName") or parts.get("commonName")


def tls_probe(host: str, ip: str, port: int, timeout: float = TIMEOUT_S) -> TlsInfo:
    """One verified handshake against the validated IP with the real hostname as SNI."""
    ctx = httpx.create_ssl_context()
    try:
        with (
            socket.create_connection((ip, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert() or {}
            protocol = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return TlsInfo(host=host, status=_VERIFY_CODES.get(exc.verify_code, "untrusted"), detail=exc.verify_message)  # type: ignore[arg-type]
    except ssl.SSLError as exc:
        status = "outdated_protocol" if any(code in str(exc.reason) for code in _OUTDATED) else "handshake_failed"
        return TlsInfo(host=host, status=status, detail=str(exc.reason))  # type: ignore[arg-type]
    except OSError as exc:
        return TlsInfo(host=host, status="handshake_failed", detail=type(exc).__name__)
    not_after = cert.get("notAfter")
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC) if isinstance(not_after, str) else None
    return TlsInfo(
        host=host,
        status="ok",
        protocol=protocol,
        issuer=_issuer(cert),
        not_after=expires.isoformat() if expires else None,
        days_remaining=(expires - datetime.now(UTC)).days if expires else None,
    )
