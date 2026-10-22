# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Per-user result history (ADR 0008): the reports of recent analyses, kept for 30 days.

After a successful email check, website check, file analysis or URL analysis, :class:`HistoryRecorder`
copies the JSON *response* (the report) into :class:`HistoryStore`. It never reads the request, so
uploaded files and email messages are never stored; the mail report itself carries no message body.

Each row holds the user id, the tool, the time, a short unencrypted summary for the list (the
verdict, grade or highest severity, and the number of findings) and the full report. On the hosted
service the report is encrypted with AES-256-GCM under ``KESTRIX_HISTORY_KEY``: a random 96-bit
nonce per row, and the row id, user id and tool as associated data, so a ciphertext copied to another
row or user does not decrypt. Rows name their key by a key id derived from the key, so a rotated-out
key (``KESTRIX_HISTORY_KEY_PREVIOUS``) still decrypts older rows until they expire. Locally the
history lives in the user's own config folder as plaintext JSON in a ``0600`` file (the machine is the
user's own; an encryption key stored beside it would add nothing).

Rows older than 30 days are deleted on every write and when the store opens, and never listed. A user
can turn history off, which deletes their rows and stops recording.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .store import private_file

RETENTION_DAYS = 30
RETENTION_S = RETENTION_DAYS * 24 * 3600
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_VERDICT = 32
LOCAL_USER = 0
KEY_BYTES = 32
NONCE_BYTES = 12
# The analysis routes whose successful responses are recorded, and their tool ids.
TOOLS = {
    "/api/mail/analyze": "mail",
    "/api/webcheck": "webcheck",
    "/api/forensics/file": "forensics_file",
    "/api/forensics/url": "forensics_url",
}
_SEVERITY_ORDER = ("high", "medium", "low", "info")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    tool TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    findings INTEGER NOT NULL,
    key_id TEXT,
    report BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS history_user_created ON history (user_id, created_at);
CREATE TABLE IF NOT EXISTS history_settings (
    user_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL
);
"""

log = logging.getLogger("kestrix.history")


class HistoryDecryptError(Exception):
    """The report cannot be decrypted: unknown key id, wrong key or altered data."""


def key_id(key: bytes) -> str:
    """A short public name for a key: a keyed hash that reveals nothing usable about it."""
    return hmac.new(key, b"kestrix-history-key-id", hashlib.sha256).hexdigest()[:16]


def _aad(row_id: str, user_id: int, tool: str) -> bytes:
    return f"kestrix-history/v1\x00{row_id}\x00{user_id}\x00{tool}".encode()


class HistoryCipher:
    """AES-256-GCM with the current key; the previous key, if any, only decrypts."""

    def __init__(self, key: bytes, previous: bytes | None = None) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(key) != KEY_BYTES or (previous is not None and len(previous) != KEY_BYTES):
            raise ValueError(f"history keys must be {KEY_BYTES} bytes")
        self.current_kid = key_id(key)
        self._keys = {self.current_kid: AESGCM(key)}
        if previous is not None:
            self._keys[key_id(previous)] = AESGCM(previous)

    def __repr__(self) -> str:
        return f"HistoryCipher(kid={self.current_kid})"

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[str, bytes]:
        nonce = os.urandom(NONCE_BYTES)
        return self.current_kid, nonce + self._keys[self.current_kid].encrypt(nonce, plaintext, aad)

    def decrypt(self, kid: str, blob: bytes, aad: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag

        aead = self._keys.get(kid)
        if aead is None or len(blob) <= NONCE_BYTES:
            raise HistoryDecryptError("unknown key id")
        try:
            return aead.decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)
        except InvalidTag:
            raise HistoryDecryptError("authentication failed") from None


def summarize(tool: str, report: dict[str, Any]) -> tuple[str, int]:
    """The list summary: ``(verdict, number of findings)``. Short, fixed vocabulary, no content."""
    findings = report.get("findings")
    found = [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []
    if tool == "mail":
        verdict = report.get("verdict")
    elif tool == "webcheck":
        verdict = report.get("grade")
    elif tool == "forensics_url":
        verdict = report.get("level")
    else:
        severities = {item.get("severity") for item in found}
        verdict = next((s for s in _SEVERITY_ORDER if s in severities), "none")
    if not isinstance(verdict, str) or not verdict or len(verdict) > MAX_VERDICT:
        verdict = "unknown"
    return verdict, len(found)


@dataclass(frozen=True)
class HistoryItem:
    id: str
    tool: str
    created_at: int
    verdict: str
    findings: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "created_at": self.created_at,
            "verdict": self.verdict,
            "findings": self.findings,
        }


@dataclass
class HistoryStore:
    """SQLite store of result reports. ``cipher`` set: hosted (encrypted rows only); unset: local plaintext."""

    path: Path
    cipher: HistoryCipher | None = None
    clock: Callable[[], float] = field(default=time.time)

    def __post_init__(self) -> None:
        private_file(self.path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA busy_timeout=5000")
            self._db.execute("PRAGMA secure_delete=ON")
            self._db.executescript(_SCHEMA)
        self.purge()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock, self._db:
            yield self._db

    def _now(self) -> int:
        return int(self.clock())

    def _cutoff(self) -> int:
        return self._now() - RETENTION_S

    def purge(self) -> int:
        """Delete every row older than the retention period. Returns how many."""
        with self._tx() as db:
            return db.execute("DELETE FROM history WHERE created_at <= ?", (self._cutoff(),)).rowcount

    # Settings

    def enabled(self, user_id: int) -> bool:
        with self._tx() as db:
            row = db.execute("SELECT enabled FROM history_settings WHERE user_id = ?", (user_id,)).fetchone()
        return row is None or bool(row[0])

    def set_enabled(self, user_id: int, enabled: bool) -> None:
        """Turn recording on or off; turning it off deletes the user's history."""
        with self._tx() as db:
            db.execute(
                "INSERT INTO history_settings (user_id, enabled) VALUES (?, ?) "
                "ON CONFLICT (user_id) DO UPDATE SET enabled = excluded.enabled",
                (user_id, int(enabled)),
            )
            if not enabled:
                db.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
        if not enabled:
            self._checkpoint()

    # Rows

    def record(self, user_id: int, tool: str, body: bytes) -> str | None:
        """Store one report (the JSON response body). Returns the row id, or None when not stored."""
        if tool not in TOOLS.values() or len(body) > MAX_REPORT_BYTES or not self.enabled(user_id):
            return None
        try:
            report = json.loads(body)
        except ValueError:
            return None
        if not isinstance(report, dict):
            return None
        verdict, findings = summarize(tool, report)
        row_id = secrets.token_urlsafe(16)
        plaintext = json.dumps(report, separators=(",", ":")).encode()
        kid: str | None = None
        stored = plaintext
        if self.cipher is not None:
            kid, stored = self.cipher.encrypt(plaintext, _aad(row_id, user_id, tool))
        with self._tx() as db:
            db.execute("DELETE FROM history WHERE created_at <= ?", (self._cutoff(),))
            db.execute(
                "INSERT INTO history (id, user_id, tool, created_at, verdict, findings, key_id, report) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (row_id, user_id, tool, self._now(), verdict, findings, kid, stored),
            )
        log.info("history stored tool=%s bytes=%d", tool, len(plaintext))
        return row_id

    def list(self, user_id: int, page: int, per_page: int) -> tuple[int, list[HistoryItem]]:
        """Newest first, within the retention period. Returns ``(total, items on this page)``."""
        cutoff = self._cutoff()
        with self._tx() as db:
            total = db.execute(
                "SELECT count(*) FROM history WHERE user_id = ? AND created_at > ?", (user_id, cutoff)
            ).fetchone()[0]
            rows = db.execute(
                "SELECT id, tool, created_at, verdict, findings FROM history "
                "WHERE user_id = ? AND created_at > ? ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                (user_id, cutoff, per_page, (page - 1) * per_page),
            ).fetchall()
        return int(total), [HistoryItem(str(r[0]), str(r[1]), int(r[2]), str(r[3]), int(r[4])) for r in rows]

    def get(self, user_id: int, row_id: str) -> dict[str, Any] | None:
        """The item with its decrypted report, or None (unknown, another user's, expired or undecryptable)."""
        with self._tx() as db:
            row = db.execute(
                "SELECT id, tool, created_at, verdict, findings, key_id, report FROM history "
                "WHERE id = ? AND user_id = ? AND created_at > ?",
                (row_id, user_id, self._cutoff()),
            ).fetchone()
        if row is None:
            return None
        item = HistoryItem(str(row[0]), str(row[1]), int(row[2]), str(row[3]), int(row[4]))
        kid, blob = row[5], bytes(row[6])
        if (kid is None) != (self.cipher is None):
            return None  # an encrypted row without a key, or a plaintext row in an encrypted store
        try:
            plaintext = (
                blob if self.cipher is None else self.cipher.decrypt(str(kid), blob, _aad(item.id, user_id, item.tool))
            )
            report = json.loads(plaintext)
        except (HistoryDecryptError, ValueError) as exc:
            log.warning("history row %s unreadable: %s", item.id, type(exc).__name__)
            return None
        return {**item.as_dict(), "report": report}

    def delete(self, user_id: int, row_id: str) -> bool:
        with self._tx() as db:
            deleted = db.execute("DELETE FROM history WHERE id = ? AND user_id = ?", (row_id, user_id)).rowcount
        return bool(deleted)

    def delete_all(self, user_id: int) -> int:
        with self._tx() as db:
            deleted = db.execute("DELETE FROM history WHERE user_id = ?", (user_id,)).rowcount
        self._checkpoint()
        return int(deleted)

    def forget_user(self, user_id: int) -> None:
        """Account deletion: the user's rows and their setting."""
        with self._tx() as db:
            db.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
            db.execute("DELETE FROM history_settings WHERE user_id = ?", (user_id,))
        self._checkpoint()

    def _checkpoint(self) -> None:
        # Move deletions out of the write-ahead log into the (securely overwritten) main file.
        with self._lock:
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")


UserOf = Callable[[Scope], int | None]


class HistoryRecorder:
    """ASGI middleware: records the JSON response of a successful analysis for its user.

    ``user_of(scope)`` names the user (None: do not record). Only the response is read; the request
    body passes through untouched. A response larger than ``MAX_REPORT_BYTES`` is not recorded, and a
    failure to record never changes the response, which has already been sent.
    """

    def __init__(self, app: ASGIApp, history: HistoryStore, user_of: UserOf) -> None:
        self.app = app
        self.history = history
        self.user_of = user_of

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        tool = TOOLS.get(scope["path"]) if scope["type"] == "http" and scope["method"] == "POST" else None
        if tool is None:
            await self.app(scope, receive, send)
            return
        status = 0
        chunks: list[bytes] = []
        size = 0

        async def capture(message: Message) -> None:
            nonlocal status, size
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body" and status == 200:
                body = message.get("body", b"")
                size += len(body)
                if size <= MAX_REPORT_BYTES:
                    chunks.append(body)
            await send(message)

        await self.app(scope, receive, capture)
        if status != 200 or size > MAX_REPORT_BYTES:
            return
        user_id = self.user_of(scope)
        if user_id is None:
            return
        try:
            await run_in_threadpool(self.history.record, user_id, tool, b"".join(chunks))
        except Exception as exc:  # the response is already sent; never let history break it
            log.error("history record failed tool=%s error=%s", tool, type(exc).__name__)
