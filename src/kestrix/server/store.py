# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""SQLite store for hosted-mode users, refresh-token families and pending sign-ins (ADR 0004, ADR 0007).

The repository layer is deliberately small so Postgres can replace it. Every query is
parameterized; the schema is static. One connection is shared across threads and guarded by
a lock. The database file is created ``0600`` inside a ``0700`` directory. Refresh tokens and
OAuth ``state`` values never reach this module in raw form, only as keyed hashes.

A refresh family (the ``sessions`` table) is one sign-in on one browser: its id (``sid``, also in
the access token), the hash of its current refresh token, and its times. The hashes of rotated
refresh tokens are kept in ``rotated_refresh_tokens`` until the family is purged, so presenting
one again can be recognized as reuse.

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
    terms_accepted_at INTEGER,
    UNIQUE (provider, subject)
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    refresh_hash TEXT NOT NULL UNIQUE,
    family_created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions (user_id);
CREATE TABLE IF NOT EXISTS rotated_refresh_tokens (
    refresh_hash TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS rotated_refresh_tokens_session_id ON rotated_refresh_tokens (session_id);
CREATE TABLE IF NOT EXISTS login_attempts (
    state_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    verifier TEXT NOT NULL,
    nonce TEXT,
    next TEXT,
    intent TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""
# Columns a database must already have when its tables exist; an older schema is refused.
_REQUIRED_COLUMNS = {
    "users": {"disabled_at", "terms_accepted_at"},
    "sessions": {"refresh_hash", "family_created_at", "last_used_at", "revoked_at"},
    "login_attempts": {"intent"},
}


class SchemaError(SettingsError):
    """The database file was created with an older schema; the server must not start."""


@dataclass(frozen=True)
class UserRow:
    id: int
    disabled_at: int | None
    created: bool  # this sign-in created the account


@dataclass(frozen=True)
class LoginAttempt:
    provider: str
    verifier: str = field(repr=False)
    nonce: str | None = field(repr=False)
    next: str | None
    intent: str  # "login" or "signup"
    created_at: int


@dataclass(frozen=True)
class FamilyRow:
    """A refresh family joined with its (enabled) user."""

    sid: str
    user_id: int
    family_created_at: int
    last_used_at: int
    expires_at: int
    revoked_at: int | None
    provider: str
    email: str
    display_name: str


@dataclass(frozen=True)
class RefreshLookup:
    family: FamilyRow
    current: bool  # False: the token was already rotated (reuse)


_FAMILY_COLUMNS = (
    "s.id, s.user_id, s.family_created_at, s.last_used_at, s.expires_at, s.revoked_at, "
    "u.provider, u.email, u.display_name"
)
_FAMILY_JOIN = "FROM sessions s JOIN users u ON u.id = s.user_id"


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
        tables = {
            str(name): str(sql)
            for name, sql in self._db.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table'")
        }
        outdated = "users" in tables and "AUTOINCREMENT" not in tables["users"].upper()
        for table, needed in _REQUIRED_COLUMNS.items():
            if table in tables:
                columns = {info[1] for info in self._db.execute(f"PRAGMA table_info({table})")}
                outdated = outdated or not needed <= columns
        if outdated:
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
                "INSERT INTO login_attempts (state_hash, provider, verifier, nonce, next, intent, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    state_hash,
                    attempt.provider,
                    attempt.verifier,
                    attempt.nonce,
                    attempt.next,
                    attempt.intent,
                    attempt.created_at,
                ),
            )

    def take_login_attempt(self, state_hash: str) -> LoginAttempt | None:
        """Delete and return the attempt, so each ``state`` can be used once."""
        with self._tx() as db:
            row = db.execute(
                "DELETE FROM login_attempts WHERE state_hash = ? "
                "RETURNING provider, verifier, nonce, next, intent, created_at",
                (state_hash,),
            ).fetchone()
        return None if row is None else LoginAttempt(*row)

    # Users

    def upsert_user(
        self, provider: str, subject: str, email: str, display_name: str, now: int, *, terms_accepted: bool
    ) -> UserRow:
        """Create the account or refresh its email and name. ``terms_accepted`` records
        ``terms_accepted_at`` only when this call creates the account."""
        with self._tx() as db:
            existing = db.execute(
                "SELECT id FROM users WHERE provider = ? AND subject = ?", (provider, subject)
            ).fetchone()
            if existing is None:
                row = db.execute(
                    "INSERT INTO users (provider, subject, email, display_name, created_at, last_login_at, "
                    "terms_accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id, disabled_at",
                    (provider, subject, email, display_name, now, now, now if terms_accepted else None),
                ).fetchone()
            else:
                row = db.execute(
                    "UPDATE users SET email = ?, display_name = ?, last_login_at = ? WHERE id = ? "
                    "RETURNING id, disabled_at",
                    (email, display_name, now, existing[0]),
                ).fetchone()
        return UserRow(int(row[0]), row[1], created=existing is None)

    def delete_user(self, user_id: int) -> list[str]:
        """Delete the user and, by cascade, every refresh family. Returns the deleted families' ids."""
        with self._tx() as db:
            sids = [str(row[0]) for row in db.execute("SELECT id FROM sessions WHERE user_id = ?", (user_id,))]
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        with self._lock:
            # Move the deletion out of the write-ahead log into the (securely overwritten) main file.
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return sids

    def set_disabled(self, email: str, disabled_at: int | None) -> int:
        """Disable (``disabled_at`` set) or re-enable every account with this email, revoking the
        refresh families of disabled ones. Returns the number of accounts changed."""
        with self._tx() as db:
            ids = [row[0] for row in db.execute("SELECT id FROM users WHERE lower(email) = lower(?)", (email.strip(),))]
            for user_id in ids:
                db.execute("UPDATE users SET disabled_at = ? WHERE id = ?", (disabled_at, user_id))
                if disabled_at is not None:
                    db.execute(
                        "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                        (disabled_at, user_id),
                    )
        return len(ids)

    # Refresh families

    def create_family(self, sid: str, user_id: int, refresh_hash: str, now: int, expires_at: int) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO sessions (id, user_id, refresh_hash, family_created_at, last_used_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (sid, user_id, refresh_hash, now, now, expires_at),
            )

    def family(self, sid: str) -> FamilyRow | None:
        """The family with this id, if its user exists and is not disabled."""
        with self._tx() as db:
            row = db.execute(
                f"SELECT {_FAMILY_COLUMNS} {_FAMILY_JOIN} WHERE s.id = ? AND u.disabled_at IS NULL",
                (sid,),
            ).fetchone()
        return None if row is None else FamilyRow(*row)

    def find_refresh(self, refresh_hash: str) -> RefreshLookup | None:
        """The family whose current or a rotated refresh token has this hash (user not disabled)."""
        with self._tx() as db:
            row = db.execute(
                f"SELECT {_FAMILY_COLUMNS} {_FAMILY_JOIN} WHERE s.refresh_hash = ? AND u.disabled_at IS NULL",
                (refresh_hash,),
            ).fetchone()
            current = row is not None
            if row is None:
                row = db.execute(
                    f"SELECT {_FAMILY_COLUMNS} {_FAMILY_JOIN} "
                    "JOIN rotated_refresh_tokens r ON r.session_id = s.id "
                    "WHERE r.refresh_hash = ? AND u.disabled_at IS NULL",
                    (refresh_hash,),
                ).fetchone()
        return None if row is None else RefreshLookup(FamilyRow(*row), current)

    def rotate_refresh(self, sid: str, old_hash: str, new_hash: str, now: int) -> bool:
        """Replace the family's refresh hash if it is still ``old_hash`` (compare and swap) and keep
        the old one for reuse detection. False when another request rotated it first."""
        with self._tx() as db:
            changed = db.execute(
                "UPDATE sessions SET refresh_hash = ?, last_used_at = ? "
                "WHERE id = ? AND refresh_hash = ? AND revoked_at IS NULL",
                (new_hash, now, sid, old_hash),
            ).rowcount
            if changed:
                db.execute(
                    "INSERT INTO rotated_refresh_tokens (refresh_hash, session_id) VALUES (?, ?)", (old_hash, sid)
                )
        return bool(changed)

    def revoke_family(self, sid: str, now: int) -> None:
        with self._tx() as db:
            db.execute("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (now, sid))

    def purge(self, *, now: int, idle_s: int, attempt_ttl_s: int) -> None:
        """Delete ended families (expired, idle or revoked) with their rotated hashes, and stale sign-in attempts."""
        with self._tx() as db:
            db.execute(
                "DELETE FROM sessions WHERE expires_at <= ? OR last_used_at <= ? OR revoked_at IS NOT NULL",
                (now, now - idle_s),
            )
            db.execute("DELETE FROM login_attempts WHERE created_at <= ?", (now - attempt_ttl_s,))
