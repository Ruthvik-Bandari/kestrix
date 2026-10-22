# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The shared SQLite rate limiter (KESTRIX_RATE_LIMIT_STORE=sqlite) and its wiring."""

import logging
import sqlite3
import stat
import sys
import threading
from pathlib import Path

import pytest

from kestrix.server import ratelimit
from kestrix.server.ratelimit import SqliteRateLimiter, rate_limit_path
from kestrix.server.settings import SettingsError, load_settings

from .hosted_support import start_login
from .test_hosted_settings import BASE

SALT = b"s" * 32


@pytest.fixture
def path(tmp_path):
    return tmp_path / "state" / "kestrix-ratelimit.db"


def rows(path):
    with sqlite3.connect(path) as db:
        return db.execute("SELECT COUNT(*) FROM hits").fetchone()[0]


def test_the_window_slides_like_the_in_memory_limiter(path):
    now = [1000.0]
    limiter = SqliteRateLimiter(path, SALT, clock=lambda: now[0])
    assert [limiter.hit("k", 2, 60) for _ in range(2)] == [None, None]
    assert limiter.hit("k", 2, 60) == 60
    now[0] += 30
    assert limiter.hit("k", 2, 60) == 30
    now[0] += 31
    assert limiter.hit("k", 2, 60) is None
    assert limiter.hit("other", 2, 60) is None
    assert rows(path) == 2  # the first two "k" hits expired and the blocked one added no row: "k" and "other"


def test_two_limiters_on_one_file_count_together(path):
    one, two = SqliteRateLimiter(path, SALT), SqliteRateLimiter(path, SALT)
    assert one.hit("login:203.0.113.7", 3, 600) is None
    assert two.hit("login:203.0.113.7", 3, 600) is None
    assert one.hit("login:203.0.113.7", 3, 600) is None
    for limiter in (one, two):  # the third hit used the last slot, whichever process counted it
        retry = limiter.hit("login:203.0.113.7", 3, 600)
        assert retry is not None and 1 <= retry <= 600
    assert two.hit("login:198.51.100.1", 3, 600) is None  # another key is unaffected


def test_forget_clears_the_key_for_every_process(path):
    one, two = SqliteRateLimiter(path, SALT), SqliteRateLimiter(path, SALT)
    for _ in range(2):
        one.hit("webcheck:7", 2, 3600)
    assert two.hit("webcheck:7", 2, 3600) is not None
    two.forget(["webcheck:7"])
    assert one.hit("webcheck:7", 2, 3600) is None


def test_the_file_holds_no_address_or_user_id_and_is_private(path):
    limiter = SqliteRateLimiter(path, SALT)
    limiter.hit("login:203.0.113.7", 5, 600)
    limiter.hit("webcheck:424242", 5, 600)
    limiter.close()
    data = b"".join(p.read_bytes() for p in path.parent.iterdir())
    assert b"203.0.113.7" not in data and b"424242" not in data and b"login" not in data
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_a_different_salt_does_not_see_the_counters(path):
    SqliteRateLimiter(path, SALT).hit("k", 1, 60)
    assert SqliteRateLimiter(path, b"t" * 32).hit("k", 1, 60) is None


def test_expired_rows_are_cleaned_up_for_every_key(path, monkeypatch):
    monkeypatch.setattr(ratelimit, "CLEANUP_EVERY", 1)
    now = [0.0]
    limiter = SqliteRateLimiter(path, SALT, clock=lambda: now[0])
    for index in range(10):
        limiter.hit(f"key{index}", 5, 60)
    assert rows(path) == 10
    now[0] = 120.0
    limiter.hit("fresh", 5, 60)  # a different key: the cleanup, not this key's own check, drops the old rows
    assert rows(path) == 1


def test_the_table_is_bounded_and_the_oldest_rows_go_first(path, monkeypatch):
    monkeypatch.setattr(ratelimit, "CLEANUP_EVERY", 1)
    now = [0.0]
    limiter = SqliteRateLimiter(path, SALT, clock=lambda: now[0], max_rows=20)
    for index in range(100):
        now[0] += 1
        limiter.hit(f"key{index}", 5, 10_000)
    assert rows(path) <= 20
    assert limiter.hit("key99", 1, 10_000) is not None  # the newest key is still counted
    assert limiter.hit("key0", 1, 10_000) is None  # the oldest was dropped: its counter reset


def test_concurrent_processes_never_exceed_the_limit(path):
    limiters = [SqliteRateLimiter(path, SALT) for _ in range(4)]
    allowed, lock = [], threading.Lock()

    def worker(limiter):
        for _ in range(40):
            if limiter.hit("burst", 50, 600) is None:
                with lock:
                    allowed.append(1)

    threads = [threading.Thread(target=worker, args=(limiters[i % 4],)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(allowed) == 50  # 320 attempts across four connections, exactly 50 slots


def test_an_unavailable_file_falls_back_to_counting_in_process(path, caplog):
    limiter = SqliteRateLimiter(path, SALT)
    limiter.close()  # every query now fails
    with caplog.at_level(logging.WARNING, logger="kestrix.ratelimit"):
        assert [limiter.hit("k", 2, 60) for _ in range(3)] == [None, None, 60]  # still limited
    assert caplog.text.count("shared rate-limit store unavailable") == 1  # logged once, not per request


def test_the_setting_defaults_to_memory_and_rejects_other_values():
    assert load_settings(BASE).hosted.rate_limit_store == "memory"
    assert load_settings({**BASE, "KESTRIX_RATE_LIMIT_STORE": " SQLite "}).hosted.rate_limit_store == "sqlite"
    with pytest.raises(SettingsError, match="KESTRIX_RATE_LIMIT_STORE must be memory or sqlite"):
        load_settings({**BASE, "KESTRIX_RATE_LIMIT_STORE": "redis"})


def test_the_default_store_creates_no_file(hosted, hosted_env):
    start_login(hosted)
    assert not rate_limit_path(Path(hosted_env["KESTRIX_DB"])).exists()


def test_two_hosted_apps_on_one_database_share_the_sign_in_limit(make_hosted, hosted_env):
    first, second = make_hosted(rate_limit_store="sqlite"), make_hosted(rate_limit_store="sqlite")
    assert rate_limit_path(Path(hosted_env["KESTRIX_DB"])).is_file()
    codes = [first.get("/api/auth/login/google", follow_redirects=False).status_code for _ in range(12)]
    codes += [second.get("/api/auth/login/google", follow_redirects=False).status_code for _ in range(10)]
    assert codes[:20] == [302] * 20  # twenty sign-in starts per ten minutes, counted across both apps
    assert codes[20:] == [429, 429]
