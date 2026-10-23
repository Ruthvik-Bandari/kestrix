# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The one HTTP client the mailbox connector uses.

Every request must be HTTPS to port 443 of an allow-listed provider host and pass `netguard.check_url`
(public addresses only). Redirects are never followed, bodies are read as a stream with a byte cap, and
timeouts are short. Headers (which carry bearer tokens) and URLs (which can carry codes) are never logged.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from ...core.errors import Reason, Rejected
from ...core.netguard import check_url

ALLOWED_HOSTS = frozenset(
    {
        "accounts.google.com",
        "oauth2.googleapis.com",
        "gmail.googleapis.com",
        "login.microsoftonline.com",
        "graph.microsoft.com",
    }
)
JSON_LIMIT = 1024 * 1024
TIMEOUT = httpx.Timeout(20.0, connect=5.0)
UrlCheck = Callable[[str], object]


class _DropProviderRequests(logging.Filter):
    """httpx logs every request URL at INFO. Provider URLs carry search text and message ids, which the
    connector promises never to log, so those records are dropped."""

    def filter(self, record: logging.LogRecord) -> bool:
        text = record.getMessage()
        return not any(host in text for host in ALLOWED_HOSTS)


for _name in ("httpx", "httpcore", "httpcore.connection", "httpcore.http11"):
    logging.getLogger(_name).addFilter(_DropProviderRequests())


@dataclass(frozen=True)
class Reply:
    status: int
    headers: Mapping[str, str]
    body: bytes


def check_provider_url(url: str) -> None:
    """Refuse anything but https://<allow-listed host>/... on port 443 without credentials."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise Rejected(Reason.INVALID_URL, "invalid provider URL") from None
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS or port not in (None, 443):
        raise Rejected(Reason.TARGET_NOT_ALLOWED, "only the mail providers' own HTTPS hosts may be contacted")
    if parts.username or parts.password:
        raise Rejected(Reason.INVALID_URL, "credentials in URLs are not allowed")


class MailboxHttp:
    def __init__(self, transport: httpx.BaseTransport | None = None, check: UrlCheck = check_url) -> None:
        self._transport = transport
        self._check = check

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: Mapping[str, str] | None = None,
        max_bytes: int = JSON_LIMIT,
        too_large: Reason = Reason.UPSTREAM_ERROR,
    ) -> Reply:
        check_provider_url(url)
        self._check(url)
        try:
            with (
                httpx.Client(transport=self._transport, timeout=TIMEOUT, follow_redirects=False) as client,
                client.stream(method, url, headers=dict(headers or {}), data=dict(data) if data else None) as response,
            ):
                if 300 <= response.status_code < 400:
                    raise Rejected(Reason.UPSTREAM_ERROR, "the provider answered with an unexpected redirect")
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise Rejected(too_large, f"the provider's answer is larger than {max_bytes:,} bytes")
                    chunks.append(chunk)
                return Reply(response.status_code, dict(response.headers), b"".join(chunks))
        except httpx.TimeoutException:
            raise Rejected(Reason.TARGET_UNREACHABLE, f"{urlsplit(url).hostname} did not answer in time") from None
        except httpx.HTTPError:
            raise Rejected(
                Reason.TARGET_UNREACHABLE, f"could not reach {urlsplit(url).hostname}; check your connection"
            ) from None
