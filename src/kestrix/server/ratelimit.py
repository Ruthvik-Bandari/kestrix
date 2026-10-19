# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""In-memory sliding-window rate limiter for hosted mode.

The counters live in this process only. That is correct for one server instance; with
several instances (or workers) each keeps its own counters, so the effective limit is
multiplied by the instance count. A shared store (Redis, Postgres) would be needed then.
"""

from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import deque
from collections.abc import Callable

from starlette.requests import Request

MAX_KEYS = 100_000


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = MAX_KEYS) -> None:
        self.clock = clock
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self._hits: dict[str, tuple[float, deque[float]]] = {}

    def hit(self, key: str, limit: int, window_s: float) -> int | None:
        """Record one request; return ``None`` if allowed, else the seconds until a slot frees up."""
        now = self.clock()
        with self._lock:
            _, hits = self._hits.get(key, (window_s, deque()))
            while hits and hits[0] <= now - window_s:
                hits.popleft()
            if len(hits) >= limit:
                return max(1, math.ceil(hits[0] + window_s - now))
            hits.append(now)
            self._hits[key] = (window_s, hits)
            if len(self._hits) > self.max_keys:
                self._evict(now)
            return None

    def _evict(self, now: float) -> None:
        """Drop keys with no hit inside their window; if still over the cap, drop the oldest keys.

        Dropping a live key resets its counter, which only happens when more than ``max_keys``
        clients are active at once; the cap keeps memory bounded under a spread-out flood.
        """
        stale = [key for key, (window, hits) in self._hits.items() if not hits or hits[-1] <= now - window]
        for key in stale:
            del self._hits[key]
        for key in list(self._hits)[: max(0, len(self._hits) - self.max_keys)]:
            del self._hits[key]


def client_ip(request: Request, *, trust_proxy_headers: bool, client_ip_header: str | None = None) -> str:
    """The socket peer; or the value of ``client_ip_header``; or, with ``trust_proxy_headers``,
    the right-most ``X-Forwarded-For`` entry.

    ``client_ip_header`` is for platforms whose proxy always overwrites one header with the
    address it accepted the connection from (Fly: ``Fly-Client-IP``); trust it only after checking
    that a header sent by the client is replaced. Only the right-most ``X-Forwarded-For`` entry is
    used because it is the one appended by the proxy directly in front of the server; entries
    further left are whatever the client chose to send.
    """
    if client_ip_header:
        values = request.headers.getlist(client_ip_header)
        if len(values) == 1:
            try:
                return str(ipaddress.ip_address(values[0].strip()))
            except ValueError:
                pass
    elif trust_proxy_headers:
        forwarded = ",".join(request.headers.getlist("x-forwarded-for")).split(",")[-1].strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    return request.client.host if request.client else "unknown"
