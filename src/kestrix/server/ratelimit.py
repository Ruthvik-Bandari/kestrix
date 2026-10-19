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
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from starlette.requests import Request

MAX_KEYS = 100_000


@dataclass
class _Entry:
    limit: int
    seen: float  # the last request for this key, allowed or not
    hits: deque[float] = field(default_factory=deque)

    def blocked(self, now: float, window_s: float) -> bool:
        return len(self.hits) >= self.limit and self.hits[0] > now - window_s


class RateLimiter:
    """Sliding-window counters, at most ``max_keys`` keys.

    Keys are kept per window length in least-recently-requested order. Above the cap, keys with
    no hit inside their window go first, then the least recently requested ones, until 10 % of
    the cap is free again; a key that is blocked right now is evicted only if nothing else is
    left. Each eviction touches only the keys it drops (or skips), so its cost is spread over the
    many requests that filled the room.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = MAX_KEYS) -> None:
        self.clock = clock
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self._windows: dict[float, OrderedDict[str, _Entry]] = {}
        self._count = 0

    def __len__(self) -> int:
        return self._count

    def hit(self, key: str, limit: int, window_s: float) -> int | None:
        """Record one request; return ``None`` if allowed, else the seconds until a slot frees up."""
        now = self.clock()
        with self._lock:
            keys = self._windows.setdefault(window_s, OrderedDict())
            entry = keys.get(key)
            if entry is None:
                entry = keys[key] = _Entry(limit, now)
                self._count += 1
            else:
                keys.move_to_end(key)
                entry.limit, entry.seen = limit, now
            hits = entry.hits
            while hits and hits[0] <= now - window_s:
                hits.popleft()
            if len(hits) >= limit:
                return max(1, math.ceil(hits[0] + window_s - now))
            hits.append(now)
            if self._count > self.max_keys:
                self._evict(now)
            return None

    def forget(self, keys: Iterable[str]) -> None:
        """Drop these keys' counters (for example when an account is deleted)."""
        with self._lock:
            for key in keys:
                for entries in self._windows.values():
                    if entries.pop(key, None) is not None:
                        self._count -= 1

    def _evict(self, now: float) -> None:
        target = self.max_keys - max(1, self.max_keys // 10)
        for window, entries in self._windows.items():
            while entries:
                key, entry = next(iter(entries.items()))
                if entry.hits and entry.hits[-1] > now - window:
                    break
                del entries[key]
                self._count -= 1
        # Least recently requested first, across window lengths; blocked keys are set aside.
        kept: list[tuple[float, str, _Entry]] = []
        while self._count > target:
            fronts = [
                (next(iter(entries.values())).seen, window) for window, entries in self._windows.items() if entries
            ]
            if not fronts:
                break
            window = min(fronts)[1]
            key, entry = self._windows[window].popitem(last=False)
            if entry.blocked(now, window):
                kept.append((window, key, entry))
            else:
                self._count -= 1
        drop = max(0, self._count - target)  # only blocked keys were left: drop the oldest of them
        self._count -= drop
        for window, key, entry in reversed(kept[drop:]):
            entries = self._windows[window]
            entries[key] = entry
            entries.move_to_end(key, last=False)


def ip_key(ip: str) -> str:
    """The rate-limit key for a client address: IPv4 as is, IPv6 by its /64 (one subscriber's
    network, which can rotate through 2**64 addresses), IPv4-mapped IPv6 as the IPv4 address."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((address, 64), strict=False))
    return str(address)


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
