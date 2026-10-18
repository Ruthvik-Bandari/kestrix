# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Outbound URL validation shared by modules that make network requests.

Only http(s) URLs are allowed. Resolved addresses in private, loopback, link-local
(including cloud metadata), multicast and reserved ranges are refused unless the
caller explicitly allows private targets. Redirects must be re-checked by the caller.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from .errors import Reason, Rejected

ALLOWED_SCHEMES = frozenset({"http", "https"})


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4 address carried inside an IPv6 one (mapped, 6to4 or NAT64), if any."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in _IPV4_COMPATIBLE:  # deprecated ::a.b.c.d form; never a legitimate public target
            return False
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            ip = embedded
    return ip.is_global and not ip.is_multicast


# A name like ``intranet.fentorfen.example`` that resolves to 10.0.0.0/8 is refused here.
def check_url(url: str, *, allow_private: bool = False) -> tuple[str, int, list[str]]:
    """Return ``(host, port, resolved_ips)`` or raise ``Rejected``."""
    if len(url) > 2048:
        raise Rejected(Reason.INVALID_URL, "URL is too long")
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES or not parts.hostname:
        raise Rejected(Reason.INVALID_URL, "only http and https URLs with a host are allowed")
    if parts.username or parts.password:
        raise Rejected(Reason.INVALID_URL, "credentials in URLs are not allowed")
    host = parts.hostname
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise Rejected(Reason.INVALID_URL, "invalid port") from None
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise Rejected(Reason.TARGET_UNREACHABLE, f"cannot resolve {host}") from None
    ips = sorted({str(info[4][0]) for info in infos})
    if not allow_private:
        blocked = [ip for ip in ips if not _is_public(ipaddress.ip_address(ip))]
        if blocked:
            raise Rejected(Reason.TARGET_NOT_ALLOWED, f"{host} resolves to non-public address {blocked[0]}")
    return host, port, ips
