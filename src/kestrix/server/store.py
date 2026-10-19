# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""SQLite store for hosted-mode users, sessions and pending sign-ins (ADR 0004).

The repository layer is deliberately small so Postgres can replace it. Every query is
parameterized; the schema is static. One connection is shared across threads and guarded by
a lock. The database file is created ``0600`` inside a ``0700`` directory. Session ids and
OAuth ``state`` values never reach this module in raw form, only as keyed hashes.

Deleted rows are overwritten (``secure_delete``), user ids are never reused (``AUTOINCREMENT``),
and deleting an account checkpoints and truncates the write-ahead log, so a deleted account's
email does not linger in the database files. A database created by an earlier preview without
these properties is refused at start-up (:class:`SchemaError`).
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .settings import SettingsError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL,
    disabled_at INTEGER,
    UNIQUE (provider, subject)
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions (user_id);
CREATE TABLE IF NOT EXISTS login_attempts (
    state_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    verifier TEXT NOT NULL,
    nonce TEXT,
    next TEXT,
    created_at INTEGER NOT NULL
);
"""


class SchemaError(SettingsError):
    """The database file was created with an older schema; the server must not start."""


@dataclass(frozen=True)
class UserRow:
    id: int
    disabled_at: int | None


@dataclass(frozen=True)
class LoginAttempt:
    provider: str
    verifier: str = field(repr=False)
    nonce: str | None = field(repr=False)
    next: str | None
    created_at: int


@dataclass(frozen=True)
class SessionRow:
    user_id: int
    csrf_token_hash: str = field(repr=False)
    created_at: int
    last_seen_at: int
    expires_at: int
    provider: str
    email: str
    display_name: str


def _private_file(path: Path) -> None:
    """Create the parent directory ``0700`` and the database file ``0600`` before SQLite opens it."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if sys.platform != "win32" and parent.stat().st_uid == os.getuid():
        os.chmod(parent, 0o700)  # mkdir does not tighten a directory that already exists
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    os.close(os.open(path, flags, 0o600))
    os.chmod(path, 0o600)


class Store:
    def __init__(self, path: Path) -> None:
        _private_file(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        with self._lock:
            # SQLite creates the -wal and -shm files with the database file's permissions.
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA busy_timeout=5000")
            self._db.execute("PRAGMA secure_delete=ON")
            self._check_schema(path)
            self._db.executescript(_SCHEMA)

    def _check_schema(self, path: Path) -> None:
        row = self._db.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").fetchone()
        if row is None:
            return
        columns = {info[1] for info in self._db.execute("PRAGMA table_info(users)")}
        if "AUTOINCREMENT" not in str(row[0]).upper() or "disabled_at" not in columns:
            self._db.close()
            raise SchemaError(
                f"{path} was created by an earlier Kestrix preview with an older schema. It holds only "
                "accounts and sessions: stop the service, move the file (and its -wal and -shm files) "
                "aside, and start again; users sign in again to recreate their accounts"
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock, self._db:
            yield self._db

    # Pending sign-ins

    def add_login_attempt(self, state_hash: str, attempt: LoginAttempt) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO login_attempts (state_hash, provider, verifier, nonce, next, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (state_hash, attempt.provider, attempt.verifier, attempt.nonce, attempt.next, attempt.created_at),
            )

    def take_login_attempt(self, state_hash: str) -> LoginAttempt | None:
        """Delete and return the attempt, so each ``state`` can be used once."""
        with self._tx() as db:
            row = db.execute(
                "DELETE FROM login_attempts WHERE state_hash = ? RETURNING provider, verifier, nonce, next, created_at",
                (state_hash,),
            ).fetchone()
        return None if row is None else LoginAttempt(*row)

    # Users and sessions

    def upsert_user(self, provider: str, subject: str, email: str, display_name: str, now: int) -> UserRow:
        with self._tx() as db:
            row = db.execute(
                "INSERT INTO users (provider, subject, email, display_name, created_at, last_login_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (provider, subject) DO UPDATE SET email = excluded.email, "
                "display_name = excluded.display_name, last_login_at = excluded.last_login_at "
                "RETURNING id, disabled_at",
                (provider, subject, email, display_name, now, now),
            ).fetchone()
        return UserRow(int(row[0]), row[1])

    def delete_user(self, user_id: int) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        with self._lock:
            # Move the deletion out of the write-ahead log into the (securely overwritten) main file.
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def set_disabled(self, email: str, disabled_at: int | None) -> int:
        """Disable (``disabled_at`` set) or re-enable every account with this email, ending the
        sessions of disabled ones. Returns the number of accounts changed."""
        with self._tx() as db:
            ids = [row[0] for row in db.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (email.strip(),))]
            for user_id in ids:
                db.execute("UPDATE users SET disabled_at = ? WHERE id = ?", (disabled_at, user_id))
                if disabled_at is not None:
                    db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        return len(ids)

    def create_session(self, id_hash: str, user_id: int, csrf_token_hash: str, now: int, expires_at: int) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO sessions (id_hash, user_id, csrf_token_hash, created_at, last_seen_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (id_hash, user_id, csrf_token_hash, now, now, expires_at),
            )

    def get_session(self, id_hash: str) -> SessionRow | None:
        with self._tx() as db:
            row = db.execute(
                "SELECT s.user_id, s.csrf_token_hash, s.created_at, s.last_seen_at, s.expires_at, "
                "u.provider, u.email, u.display_name "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ? AND u.disabled_at IS NULL",
                (id_hash,),
            ).fetchone()
        return None if row is None else SessionRow(*row)

    def touch_session(self, id_hash: str, now: int) -> None:
        with self._tx() as db:
            db.execute("UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?", (now, id_hash))

    def delete_session(self, id_hash: str) -> None:
        with self._tx() as db:
            db.execute("DELETE FROM sessions WHERE id_hash = ?", (id_hash,))

    def purge(self, *, now: int, idle_s: int, attempt_ttl_s: int) -> None:
        """Delete expired sessions and stale sign-in attempts."""
        with self._tx() as db:
            db.execute("DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?", (now, now - idle_s))
            db.execute("DELETE FROM login_attempts WHERE created_at <= ?", (now - attempt_ttl_s,))
