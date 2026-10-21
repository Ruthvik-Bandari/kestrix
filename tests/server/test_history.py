# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Per-user result history (ADR 0008): encryption, retention, ownership, the toggle, and both modes."""

import base64
import json
import logging
import os
import sqlite3
import stat
import sys

import pytest
from fastapi.testclient import TestClient

from kestrix.core import config
from kestrix.server.app import create_app, history_path
from kestrix.server.history import (
    RETENTION_S,
    HistoryCipher,
    HistoryDecryptError,
    HistoryStore,
    key_id,
    summarize,
)
from kestrix.server.settings import SettingsError, load_settings

from .hosted_support import HISTORY_KEY, HISTORY_KEY_2, ORIGIN, Clock, csrf, sign_in

KEY = base64.b64decode(HISTORY_KEY)
KEY_2 = base64.b64decode(HISTORY_KEY_2)
URL_BODY = {"url": "http://paypa1-login.example.top/verify"}
BODY_SENTINEL = "BODY-SENTINEL-7f3a appears only in the message body"
EML = (
    "From: Alice <alice@mail.example>\r\nTo: bob@mail.example\r\nSubject: Quarterly notes\r\n"
    f"Date: Sat, 17 Oct 2026 10:00:00 +0000\r\n\r\nHello Bob,\r\n{BODY_SENTINEL}\r\n"
).encode()
REPORT = {"verdict": "suspicious", "findings": [{"id": "a"}, {"id": "b"}], "subject": "s"}


def rows(path):
    with sqlite3.connect(path) as db:
        return db.execute("SELECT id, user_id, tool, key_id, report FROM history").fetchall()


# The cipher and the store


def test_encryption_round_trip_and_wrong_key_fails():
    cipher = HistoryCipher(KEY)
    kid, blob = cipher.encrypt(b'{"a":1}', b"aad")
    assert kid == key_id(KEY) and b'{"a":1}' not in blob
    assert cipher.decrypt(kid, blob, b"aad") == b'{"a":1}'
    with pytest.raises(HistoryDecryptError):
        cipher.decrypt(kid, blob, b"other aad")  # bound to its row, user and tool
    with pytest.raises(HistoryDecryptError):
        HistoryCipher(KEY_2).decrypt(kid, blob, b"aad")  # unknown key id
    with pytest.raises(HistoryDecryptError):
        HistoryCipher(KEY_2, previous=b"x" * 32).decrypt(key_id(b"x" * 32), blob, b"aad")  # wrong key bytes
    assert KEY.hex() not in repr(cipher)


def test_store_round_trip_encrypts_at_rest(tmp_path):
    path = tmp_path / "h.sqlite3"
    store = HistoryStore(path, HistoryCipher(KEY))
    row_id = store.record(7, "mail", json.dumps(REPORT).encode())
    assert row_id is not None
    [(stored_id, user_id, tool, kid, blob)] = rows(path)
    assert (stored_id, user_id, tool, kid) == (row_id, 7, "mail", key_id(KEY))
    assert b"suspicious" not in blob and json.dumps(REPORT).encode() not in blob
    found = store.get(7, row_id)
    assert found == {
        "id": row_id,
        "tool": "mail",
        "created_at": found["created_at"],
        "verdict": "suspicious",
        "findings": 2,
        "report": REPORT,
    }
    assert HistoryStore(path, HistoryCipher(KEY_2)).get(7, row_id) is None  # wrong key: unreadable, not an error


def test_key_rotation(tmp_path):
    path = tmp_path / "h.sqlite3"
    old_id = HistoryStore(path, HistoryCipher(KEY)).record(1, "webcheck", b'{"grade":"B","findings":[]}')
    rotated = HistoryStore(path, HistoryCipher(KEY_2, previous=KEY))
    new_id = rotated.record(1, "webcheck", b'{"grade":"A","findings":[]}')
    kids = {row[0]: row[3] for row in rows(path)}
    assert kids == {old_id: key_id(KEY), new_id: key_id(KEY_2)}
    assert rotated.get(1, old_id)["verdict"] == "B" and rotated.get(1, new_id)["verdict"] == "A"
    assert HistoryStore(path, HistoryCipher(KEY_2)).get(1, old_id) is None  # previous key dropped


def test_settings_require_a_32_byte_history_key():
    from .test_hosted_settings import BASE

    hosted = load_settings(BASE).hosted
    assert hosted is not None and hosted.history_key == KEY and hosted.history_key_previous is None
    assert HISTORY_KEY not in repr(hosted)
    for change, message in [
        ({"KESTRIX_HISTORY_KEY": ""}, "needs KESTRIX_HISTORY_KEY"),
        ({"KESTRIX_HISTORY_KEY": base64.b64encode(b"short").decode()}, "exactly 32 bytes"),
        ({"KESTRIX_HISTORY_KEY": "not base64!"}, "exactly 32 bytes"),
        ({"KESTRIX_HISTORY_KEY_PREVIOUS": HISTORY_KEY}, "must differ"),
    ]:
        with pytest.raises(SettingsError, match=message):
            load_settings({**BASE, **change})
    rotated = load_settings({**BASE, "KESTRIX_HISTORY_KEY_PREVIOUS": HISTORY_KEY_2}).hosted
    assert rotated is not None and rotated.history_key_previous == KEY_2


def test_retention_purge_on_write_and_at_startup(tmp_path):
    clock = Clock()
    path = tmp_path / "h.sqlite3"
    store = HistoryStore(path, clock=clock)
    old = store.record(0, "forensics_url", b'{"level":"high","findings":[]}')
    clock.advance(RETENTION_S - 10)
    recent = store.record(0, "forensics_url", b'{"level":"low","findings":[]}')
    clock.advance(20)
    assert store.get(0, old) is None and [i.id for i in store.list(0, 1, 20)[1]] == [recent]  # hidden, not listed
    assert len(rows(path)) == 2  # GET-style reads delete nothing
    store.record(0, "forensics_url", b'{"level":"none","findings":[]}')  # a write purges
    assert old not in {row[0] for row in rows(path)}
    clock.advance(RETENTION_S)
    HistoryStore(path, clock=clock)  # opening purges
    assert rows(path) == []


def test_summaries():
    assert summarize("mail", {"verdict": "malicious", "findings": [{}]}) == ("malicious", 1)
    assert summarize("webcheck", {"grade": "C", "findings": [{}, {}]}) == ("C", 2)
    assert summarize("forensics_url", {"level": "medium", "findings": []}) == ("medium", 0)
    file_report = {"findings": [{"severity": "low"}, {"severity": "medium"}]}
    assert summarize("forensics_file", file_report) == ("medium", 2)
    assert summarize("forensics_file", {"findings": []}) == ("none", 0)
    assert summarize("mail", {"verdict": "x" * 100}) == ("unknown", 0)


# Local mode


@pytest.fixture
def local():
    return TestClient(create_app(extra_hosts=frozenset({"testserver"})))


def test_local_history_records_lists_reads_and_deletes(local):
    assert local.get("/api/history").json() == {
        "enabled": True,
        "retention_days": 30,
        "page": 1,
        "per_page": 20,
        "total": 0,
        "items": [],
    }
    assert local.post("/api/forensics/url", json=URL_BODY).status_code == 200
    assert local.post("/api/forensics/file", files={"file": ("a.txt", b"hello", "text/plain")}).status_code == 200
    assert local.post("/api/forensics/url", json={"url": ""}).status_code == 400  # failures are not kept
    listing = local.get("/api/history", params={"per_page": 1}).json()
    assert (listing["total"], listing["per_page"]) == (2, 1)
    [newest] = listing["items"]
    assert set(newest) == {"id", "tool", "created_at", "verdict", "findings"} and newest["tool"] == "forensics_file"
    assert newest["verdict"] in {"high", "medium", "low", "info", "none"}
    second = local.get("/api/history", params={"page": 2, "per_page": 1}).json()["items"][0]
    assert second["tool"] == "forensics_url" and second["verdict"] in {"none", "low", "medium", "high"}
    detail = local.get(f"/api/history/{second['id']}").json()
    assert detail["report"]["url"] == URL_BODY["url"] and detail["verdict"] == detail["report"]["level"]
    assert local.get("/api/history", params={"per_page": 51}).status_code == 422
    assert local.get("/api/history/not-an-id").status_code == 404
    assert local.delete(f"/api/history/{second['id']}").status_code == 204
    assert local.get(f"/api/history/{second['id']}").status_code == 404
    assert local.delete(f"/api/history/{second['id']}").status_code == 404
    assert local.delete("/api/history").status_code == 204
    assert local.get("/api/history").json()["total"] == 0


def test_local_history_file_is_private_and_plaintext(local):
    local.post("/api/forensics/url", json=URL_BODY)
    path = config.config_dir() / "history.sqlite3"
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    [(_, user_id, _, kid, blob)] = rows(path)
    assert (user_id, kid) == (0, None) and json.loads(blob)["url"] == URL_BODY["url"]


def test_local_toggle_off_deletes_and_stops_recording(local):
    local.post("/api/forensics/url", json=URL_BODY)
    assert local.put("/api/settings/history", json={"enabled": False}).json() == {"enabled": False}
    local.post("/api/forensics/url", json=URL_BODY)
    listing = local.get("/api/history").json()
    assert (listing["enabled"], listing["total"]) == (False, 0)
    assert local.put("/api/settings/history", json={"enabled": True, "x": 1}).status_code == 422
    local.put("/api/settings/history", json={"enabled": True})
    local.post("/api/forensics/url", json=URL_BODY)
    assert local.get("/api/history").json()["total"] == 1


def test_local_history_writes_from_other_sites_are_refused(local):
    resp = local.delete("/api/history", headers={"origin": "https://evil.example"})
    assert resp.status_code == 403


# Hosted mode


def hosted_store(client) -> HistoryStore:
    return client.app.state.history


def test_hosted_history_is_encrypted_and_never_holds_the_upload(hosted, providers, hosted_env):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    files = {"file": ("m.eml", EML, "message/rfc822")}
    assert hosted.post("/api/mail/analyze", files=files, headers=headers).status_code == 200
    [item] = hosted.get("/api/history").json()["items"]
    assert item["tool"] == "mail" and item["verdict"] in {"clean", "suspicious", "malicious", "insufficient_evidence"}
    path = history_path(load_settings().hosted.db_path)
    assert path.name == "hosted-history.sqlite3"
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    [(row_id, user_id, tool, kid, blob)] = rows(path)
    assert kid == key_id(KEY)
    plaintext = HistoryCipher(KEY).decrypt(kid, blob, f"kestrix-history/v1\x00{row_id}\x00{user_id}\x00{tool}".encode())
    report = json.loads(plaintext)
    assert report["subject"] == "Quarterly notes"  # the report itself is stored...
    assert b"BODY-SENTINEL" not in plaintext and b"Hello Bob" not in plaintext  # ...never the message body
    assert plaintext not in blob and b"Quarterly" not in blob and b"BODY-SENTINEL" not in blob
    assert hosted.get(f"/api/history/{row_id}").json()["report"] == report


def test_hosted_history_is_owner_only(hosted, providers, hosted_env):
    sign_in(hosted, providers)  # Google user
    hosted.post("/api/forensics/url", json=URL_BODY, headers=csrf(hosted))
    [item] = hosted.get("/api/history").json()["items"]
    other = TestClient(hosted.app, base_url=ORIGIN)
    sign_in(other, providers, provider="github")
    assert other.get("/api/history").json()["total"] == 0
    assert other.get(f"/api/history/{item['id']}").status_code == 404
    assert other.delete(f"/api/history/{item['id']}", headers=csrf(other)).status_code == 404
    other.delete("/api/history", headers=csrf(other))
    assert hosted.get(f"/api/history/{item['id']}").status_code == 200  # untouched


def test_hosted_history_needs_sign_in_and_csrf(hosted, providers):
    assert hosted.get("/api/history").status_code == 401
    sign_in(hosted, providers)
    hosted.post("/api/forensics/url", json=URL_BODY, headers=csrf(hosted))
    [item] = hosted.get("/api/history").json()["items"]
    for method, path, body in [
        ("DELETE", f"/api/history/{item['id']}", None),
        ("DELETE", "/api/history", None),
        ("PUT", "/api/settings/history", {"enabled": False}),
    ]:
        resp = hosted.request(method, path, json=body)
        assert resp.status_code == 403 and resp.json()["reason"] == "csrf_failed"
    assert hosted.get("/api/history").json()["total"] == 1
    assert hosted.get("/api/settings").status_code == 404  # the rest of /api/settings stays local-only


def test_hosted_history_writes_are_rate_limited(hosted, providers):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    codes = [hosted.delete("/api/history", headers=headers).status_code for _ in range(121)]
    assert codes[:120] == [204] * 120 and codes[120] == 429


def test_hosted_toggle_off_deletes_and_stops_recording(hosted, providers):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    hosted.post("/api/forensics/url", json=URL_BODY, headers=headers)
    assert hosted.put("/api/settings/history", json={"enabled": False}, headers=headers).json() == {"enabled": False}
    hosted.post("/api/forensics/url", json=URL_BODY, headers=headers)
    assert rows(hosted_store(hosted).path) == []
    assert hosted.get("/api/history").json()["enabled"] is False


def test_account_deletion_deletes_the_history(hosted, providers):
    sign_in(hosted, providers)
    headers = csrf(hosted)
    hosted.post("/api/forensics/url", json=URL_BODY, headers=headers)
    hosted.put("/api/settings/history", json={"enabled": True}, headers=headers)
    store = hosted_store(hosted)
    assert len(rows(store.path)) == 1
    assert hosted.delete("/api/auth/account", headers=headers).status_code == 204
    assert rows(store.path) == []
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM history_settings").fetchone()[0] == 0


def test_logs_hold_no_report_content(hosted, providers, caplog):
    caplog.set_level(logging.DEBUG, logger="kestrix")
    sign_in(hosted, providers)
    headers = csrf(hosted)
    hosted.post("/api/forensics/url", json=URL_BODY, headers=headers)
    hosted.post("/api/mail/analyze", files={"file": ("m.eml", EML, "message/rfc822")}, headers=headers)
    [item, _] = hosted.get("/api/history").json()["items"]
    hosted.get(f"/api/history/{item['id']}")
    assert "history stored tool=forensics_url" in caplog.text
    for content in ["paypa1", "Quarterly", "alice@mail.example", "BODY-SENTINEL", '"findings"']:
        assert content not in caplog.text, content
