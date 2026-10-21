# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Network side of the web check: GET requests with redirects, and one TLS handshake.

``fetch`` sends one GET (plus up to five redirects). The whole-site scan (``crawl.py``) calls it once
per page, with ``stay_on`` (a redirect that leaves the site is reported, not followed) and a shared
:class:`RequestBudget`. No cookie is ever sent back, not even between the hops of one redirect chain.

Every hop is validated with :func:`kestrix.core.netguard.check_url` and the request is
sent to the validated IP address (Host header and TLS SNI keep the real hostname), so a
DNS answer that changes between the check and the connection cannot redirect the request
to a private address.

The whole fetch, DNS lookups included, has one deadline (``timeout``, 10 s by default): every
socket operation's timeout is capped at the time left, so a server that drips its response
cannot hold the check open. The TLS probe has its own deadline of the same length.
"""

from __future__ import annotations

import http.cookiejar
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

import httpcore
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

# What the hosted service says for any connection-level failure, so a check cannot be used to
# tell closed, filtered and non-HTTP ports apart.
GENERIC_UNREACHABLE = "the site could not be reached"

TlsProbe = Callable[[str, str, int, float], TlsInfo]
Origin = tuple[str, str, int]  # scheme, lower-case host, port: what "the same site" means


def origin_of(url: str) -> Origin:
    parts = urlsplit(url)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        port = 0
    return parts.scheme, (parts.hostname or "").lower(), port


@dataclass
class RequestBudget:
    """GET requests a whole-site scan may still send. ``pages`` is for the first request to each page
    (the start page, linked and sitemap pages, login probes); ``extra`` is for the sitemap and for every
    redirect hop. ``sent`` counts every request actually sent."""

    pages: int
    extra: int
    sent: int = 0

    def take_page(self) -> bool:
        if self.pages <= 0:
            return False
        self.pages -= 1
        return True

    def take_extra(self) -> bool:
        if self.extra <= 0:
            return False
        self.extra -= 1
        return True


class _NoCookies(http.cookiejar.CookiePolicy):
    """Accept and return no cookie, so a response can never make a later request carry one."""

    netscape = True
    rfc2965 = False
    hide_cookie2 = False

    def set_ok(self, cookie: http.cookiejar.Cookie, request: Any) -> bool:
        return False

    def return_ok(self, cookie: http.cookiejar.Cookie, request: Any) -> bool:
        return False

    def domain_return_ok(self, domain: str, request: Any) -> bool:
        return False

    def path_return_ok(self, path: str, request: Any) -> bool:
        return False


def user_agent(abuse_contact: str | None = None) -> str:
    """The honest User-Agent: names Kestrix and, on a hosted service, where to report abuse."""
    return f"{USER_AGENT} (abuse contact: {abuse_contact})" if abuse_contact else USER_AGENT


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
    # Set when a redirect was not followed: it leaves the site (``stay_on``) or the budget is spent.
    not_followed: Literal["off_site", "budget"] | None = None
    redirect_to: str = ""


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


class _DeadlineStream(httpcore.NetworkStream):
    """A socket stream whose every operation times out no later than ``deadline``."""

    def __init__(self, inner: httpcore.NetworkStream, deadline: float) -> None:
        self._inner = inner
        self._deadline = deadline

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, _capped(timeout, self._deadline, httpcore.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, _capped(timeout, self._deadline, httpcore.WriteTimeout))

    def close(self) -> None:
        self._inner.close()

    def start_tls(
        self, ssl_context: ssl.SSLContext, server_hostname: str | None = None, timeout: float | None = None
    ) -> httpcore.NetworkStream:
        timeout = _capped(timeout, self._deadline, httpcore.ConnectTimeout)
        return _DeadlineStream(self._inner.start_tls(ssl_context, server_hostname, timeout), self._deadline)

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _DeadlineBackend(httpcore.NetworkBackend):
    def __init__(self, deadline: float) -> None:
        self._inner = httpcore.SyncBackend()
        self._deadline = deadline

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        timeout = _capped(timeout, self._deadline, httpcore.ConnectTimeout)
        return _DeadlineStream(
            self._inner.connect_tcp(host, port, timeout, local_address, socket_options), self._deadline
        )

    def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Any = None
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("unix sockets are not used")

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _capped(timeout: float | None, deadline: float, error: type[Exception]) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise error("the check's time limit was reached")
    return left if timeout is None else min(timeout, left)


def _deadline_transport(deadline: float) -> httpx.HTTPTransport:
    transport = httpx.HTTPTransport(verify=httpx.create_ssl_context(), trust_env=False)
    # httpx has no public hook for the network backend, so its connection pool is replaced by an
    # identical one that uses the deadline backend. tests/webcheck exercise this against local servers.
    transport._pool = httpcore.ConnectionPool(
        ssl_context=httpx.create_ssl_context(), network_backend=_DeadlineBackend(deadline)
    )
    return transport


def _request(target: httpx.URL, ip: str, host: str, agent: str, timeout: float) -> httpx.Request:
    """A GET with no body, no cookie and no credentials, sent to the validated ``ip``."""
    return httpx.Request(
        "GET",
        target.copy_with(host=ip),
        headers={
            "Host": target.netloc.decode(),
            "User-Agent": agent,
            "Accept": "text/html,*/*",
            # Uncompressed, so the bounded body read is the real page size.
            "Accept-Encoding": "identity",
        },
        extensions={"sni_hostname": host, "timeout": httpx.Timeout(timeout).as_dict()},
    )


def _send(
    client: httpx.Client, request: httpx.Request, host: str, left: Callable[[], float], generic_errors: bool
) -> tuple[httpx.Response, bytes] | None:
    """Send ``request`` and read at most MAX_BODY_BYTES of the body; ``None`` when TLS setup failed."""

    def unreachable(detail: str) -> Rejected:
        return Rejected(Reason.TARGET_UNREACHABLE, GENERIC_UNREACHABLE if generic_errors else detail)

    def upstream(exc: httpx.HTTPError) -> Rejected:
        return unreachable("") if generic_errors else Rejected(Reason.UPSTREAM_ERROR, type(exc).__name__)

    try:
        resp = client.send(request, stream=True)
    except httpx.ConnectError as exc:
        if _is_tls_error(exc):
            return None
        raise unreachable(f"cannot connect to {host}") from None
    except httpx.TimeoutException:
        raise unreachable(f"{host} timed out") from None
    except httpx.HTTPError as exc:
        raise upstream(exc) from None
    body = bytearray()
    try:
        for chunk in resp.iter_raw():  # raw, never decompressed: no decompression bombs
            body += chunk[: MAX_BODY_BYTES - len(body)]
            if len(body) >= MAX_BODY_BYTES:
                break
            left()
    except httpx.TimeoutException:
        raise unreachable(f"{host} timed out") from None
    except httpx.HTTPError as exc:
        raise upstream(exc) from None
    finally:
        resp.close()
    return resp, bytes(body)


def _stop_reason(
    next_url: str, stay_on: Origin | None, budget: RequestBudget | None, *, last: bool
) -> Literal["off_site", "budget"] | None:
    """Why a redirect to ``next_url`` must not be followed, if it must not."""
    if stay_on is not None and origin_of(next_url) != stay_on:
        return "off_site"
    if budget is not None and not last and not budget.take_extra():
        return "budget"
    return None


def _port_allowed(url: str, allowed_ports: frozenset[int]) -> None:
    parts = urlsplit(url)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return  # check_url rejects it
    if port not in allowed_ports:
        ports = " and ".join(str(p) for p in sorted(allowed_ports))
        raise Rejected(Reason.TARGET_NOT_ALLOWED, f"only ports {ports} can be checked here")


def fetch(
    url: str,
    *,
    allow_private: bool = False,
    transport: httpx.BaseTransport | None = None,
    agent: str = USER_AGENT,
    timeout: float = TIMEOUT_S,
    allowed_ports: frozenset[int] | None = None,
    generic_errors: bool = False,
    stay_on: Origin | None = None,
    budget: RequestBudget | None = None,
) -> FetchResult:
    """GET ``url`` and follow up to five redirects within ``timeout`` seconds in total.

    ``allowed_ports`` restricts every hop's port; ``generic_errors`` reports every
    connection-level failure with one message. The hosted service sets both. With ``stay_on`` a
    redirect to another origin is not followed; with ``budget`` each redirect hop must take one of its
    ``extra`` requests, and every request sent is counted in ``budget.sent``.
    """
    deadline = time.monotonic() + timeout

    def unreachable(detail: str) -> Rejected:
        return Rejected(Reason.TARGET_UNREACHABLE, GENERIC_UNREACHABLE if generic_errors else detail)

    def left() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise unreachable("timed out")
        return remaining

    chain: list[Hop] = []
    with httpx.Client(
        transport=transport or _deadline_transport(deadline), follow_redirects=False, trust_env=False
    ) as client:
        client.cookies.jar.set_policy(_NoCookies())
        for hop in range(MAX_REDIRECTS + 1):
            if allowed_ports is not None:
                _port_allowed(url, allowed_ports)
            host, port, ips = check_url(url, allow_private=allow_private, resolve_timeout=left())
            target = httpx.URL(url)
            request = _request(target, ips[0], host, agent, left())
            started = time.monotonic()
            if budget is not None:
                budget.sent += 1
            sent = _send(client, request, host, left, generic_errors)
            if sent is None:  # the TLS handshake with the site failed
                return FetchResult(url, None, {}, chain, host, ips[0], port)
            resp, body = sent
            chain.append(
                Hop(
                    url=url,
                    address=ips[0],
                    status_code=resp.status_code,
                    elapsed_ms=round((time.monotonic() - started) * 1000),
                )
            )
            result = FetchResult(url, resp.status_code, _headers(resp), chain, host, ips[0], port, bytes(body))
            location = resp.headers.get("location")
            if resp.status_code in _REDIRECTS and location:
                next_url = str(target.join(location))
                stop = _stop_reason(next_url, stay_on, budget, last=hop == MAX_REDIRECTS)
                if stop:
                    result.not_followed, result.redirect_to = stop, next_url
                    return result
                url = next_url
                continue
            return result
    raise Rejected(Reason.UPSTREAM_ERROR, f"more than {MAX_REDIRECTS} redirects")


def _issuer(cert: dict[str, Any]) -> str | None:
    parts = dict(item for rdn in cert.get("issuer", ()) for item in rdn)
    return parts.get("organizationName") or parts.get("commonName")


def tls_probe(host: str, ip: str, port: int, timeout: float = TIMEOUT_S) -> TlsInfo:
    """One verified handshake against the validated IP with the real hostname as SNI, connect
    and handshake together within ``timeout`` seconds."""
    deadline = time.monotonic() + timeout
    ctx = httpx.create_ssl_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # The handshake treats the socket timeout as one deadline for the whole exchange.
            sock.settimeout(_capped(None, deadline, TimeoutError))
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
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
    expires = (
        datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
        if isinstance(not_after, str)
        else None
    )
    return TlsInfo(
        host=host,
        status="ok",
        protocol=protocol,
        issuer=_issuer(cert),
        not_after=expires.isoformat() if expires else None,
        days_remaining=(expires - datetime.now(timezone.utc)).days if expires else None,
    )
