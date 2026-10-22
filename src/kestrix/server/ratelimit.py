# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Sliding-window rate limiters for hosted mode.

``RateLimiter`` (the default) keeps its counters in this process only. That is correct for one
server process; with several processes each keeps its own counters, so the effective limit is
multiplied by the process count. ``SqliteRateLimiter`` (``KESTRIX_RATE_LIMIT_STORE=sqlite``) keeps
them in a small SQLite file instead, so every process that opens the same file counts together. It
shares one machine's disk: two machines have two files. Both answer the same ``Limiter`` protocol.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import math
import sqlite3
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from starlette.requests import Request

from .store import private_file

MAX_KEYS = 100_000
MAX_ROWS = 200_000
CLEANUP_EVERY = 256
SQLITE_BUSY_MS = 500

log = logging.getLogger("kestrix.ratelimit")


class Limiter(Protocol):
    """What the hosted middleware needs from a rate limiter."""

    shared: bool  # True: ``hit`` touches a file, so callers on the event loop should run it in a thread

    def hit(self, key: str, limit: int, window_s: float) -> int | None: ...

    def forget(self, keys: Iterable[str]) -> None: ...


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

    shared = False

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


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS hits (
    key_hash TEXT NOT NULL,
    ts REAL NOT NULL,
    expires REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS hits_key_ts ON hits (key_hash, ts);
CREATE INDEX IF NOT EXISTS hits_expires ON hits (expires);
"""


class SqliteRateLimiter:
    """Sliding-window counters in a SQLite file shared by every process that opens it.

    One row per allowed request, keyed by ``HMAC(salt, key)`` so the file holds no address or user id,
    with the time it happened and when it stops counting. ``hit`` is one short ``BEGIN IMMEDIATE``
    transaction (WAL, ``busy_timeout`` of 500 ms), so concurrent processes serialize on the write lock and
    never count the same slot twice. Blocked requests add no row, so a key holds at most ``limit`` rows.
    Expired rows are deleted for the key at every hit and, for all keys, every ``CLEANUP_EVERY`` hits; if
    the table still holds more than ``max_rows`` the oldest rows go first (that resets those counters, as
    dropping a key does in memory). Wall-clock time is used because processes cannot share a monotonic clock.

    If the file is locked for longer than the busy timeout or otherwise fails, the request is counted by
    an in-process limiter for the moment instead (and a warning is logged at most once a minute): a
    limiter that fails closed would turn a disk problem into an outage, and one that fails open would
    switch the limits off.
    """

    shared = True

    def __init__(
        self,
        path: Path,
        salt: bytes,
        clock: Callable[[], float] = time.time,
        max_rows: int = MAX_ROWS,
    ) -> None:
        private_file(path)
        self.clock = clock
        self.max_rows = max_rows
        self._salt = salt
        self._lock = threading.Lock()
        self._hits_since_cleanup = 0
        self._last_warning = float("-inf")
        self._fallback = RateLimiter(clock=clock)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=SQLITE_BUSY_MS / 1000)
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.execute("PRAGMA secure_delete=ON")
            self._db.executescript(_SQLITE_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _hash(self, key: str) -> str:
        return hmac.new(self._salt, b"kx-ratelimit\x00" + key.encode(), hashlib.sha256).hexdigest()[:32]

    def hit(self, key: str, limit: int, window_s: float) -> int | None:
        """Record one request; return ``None`` if allowed, else the seconds until a slot frees up."""
        now = self.clock()
        key_hash = self._hash(key)
        try:
            with self._lock:
                return self._hit(key_hash, limit, window_s, now)
        except sqlite3.Error:
            self._warn(now)
            return self._fallback.hit(key, limit, window_s)

    def _hit(self, key_hash: str, limit: int, window_s: float, now: float) -> int | None:
        db = self._db
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("DELETE FROM hits WHERE key_hash = ? AND ts <= ?", (key_hash, now - window_s))
            count, oldest = db.execute("SELECT COUNT(*), MIN(ts) FROM hits WHERE key_hash = ?", (key_hash,)).fetchone()
            retry: int | None = None
            if count >= limit:
                retry = max(1, math.ceil(oldest + window_s - now))
            else:
                db.execute("INSERT INTO hits (key_hash, ts, expires) VALUES (?, ?, ?)", (key_hash, now, now + window_s))
                self._hits_since_cleanup += 1
                if self._hits_since_cleanup >= CLEANUP_EVERY:
                    self._hits_since_cleanup = 0
                    self._cleanup(now)
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        return retry

    def _cleanup(self, now: float) -> None:
        db = self._db
        db.execute("DELETE FROM hits WHERE expires <= ?", (now,))
        rows = db.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        if rows > self.max_rows:
            target = self.max_rows - max(1, self.max_rows // 10)
            db.execute("DELETE FROM hits WHERE rowid IN (SELECT rowid FROM hits ORDER BY ts LIMIT ?)", (rows - target,))

    def forget(self, keys: Iterable[str]) -> None:
        """Drop these keys' counters (for example when an account is deleted)."""
        hashes = [(self._hash(key),) for key in keys]
        try:
            with self._lock:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._db.executemany("DELETE FROM hits WHERE key_hash = ?", hashes)
                    self._db.execute("COMMIT")
                except BaseException:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    raise
        except sqlite3.Error:
            self._warn(self.clock())
        self._fallback.forget(keys)

    def _warn(self, now: float) -> None:
        if now - self._last_warning >= 60:
            self._last_warning = now
            log.warning("shared rate-limit store unavailable; counting in this process for now")


def rate_limit_path(db_path: Path) -> Path:
    """The shared rate-limit database, beside the accounts database: ``kestrix.db`` -> ``kestrix-ratelimit.db``."""
    return db_path.with_name(f"{db_path.stem}-ratelimit{db_path.suffix}")


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
