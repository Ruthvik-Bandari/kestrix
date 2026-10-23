# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The OSV index: severity, the index build, ``db update`` with a fake HTTPS server, and ``db status``."""

import hashlib
import io
import json
import sqlite3
import urllib.error
import zipfile
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any

import osv_support as osv
import pytest
from cli_support import run

from kestrix_scan import osvdb
from kestrix_scan.errors import Rejected


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
        ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_base_score(vector: str, score: float) -> None:
    assert osvdb.cvss3_score(vector) == score


@pytest.mark.parametrize(
    "vector",
    ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:N"],
)
def test_cvss3_score_ignores_other_vectors(vector: str) -> None:
    assert osvdb.cvss3_score(vector) is None


def test_advisory_severity_prefers_cvss_then_the_ghsa_label() -> None:
    assert osvdb.advisory_severity({"severity": [{"type": "CVSS_V3", "score": osv.CVSS_CRITICAL}]}) == "critical"
    assert osvdb.advisory_severity({"severity": [{"type": "CVSS_V3", "score": osv.CVSS_MEDIUM}]}) == "medium"
    assert osvdb.advisory_severity({"database_specific": {"severity": "HIGH"}}) == "high"
    assert osvdb.advisory_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert osvdb.advisory_severity({"database_specific": {"severity": "LOW"}}) == "low"
    assert osvdb.advisory_severity({}) == "medium"
    assert [osvdb.score_severity(s) for s in (0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)] == [
        "low", "low", "medium", "medium", "high", "high", "critical",
    ]  # fmt: skip


def test_index_build_and_lookups(tmp_path: Path) -> None:
    path = osv.build(tmp_path)
    db = osvdb.connect(path)
    assert db is not None
    found = {adv.id: adv for adv in osvdb.advisories_for(db, "PyPI", "DEMO.pkg")}  # looked up by normalized name
    assert set(found) == {"GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1", "GHSA-dddd-eeee-ffff"}
    ghsa = found["GHSA-aaaa-bbbb-cccc"]
    assert ghsa.severity == "critical" and ghsa.cwes == ("CWE-94",) and "CVE-2026-0001" in ghsa.aliases
    assert found["GHSA-dddd-eeee-ffff"].severity == "medium" and not ghsa.malicious
    assert [adv.malicious for adv in osvdb.advisories_for(db, "npm", "@evil/stealer")] == [True]
    assert osvdb.advisories_for(db, "PyPI", "gone") == []  # withdrawn
    assert osvdb.advisories_for(db, "npm", "demo-pkg") == []  # other ecosystem
    with pytest.raises(sqlite3.OperationalError):  # opened read-only
        db.execute("DELETE FROM advisories")
    db.close()
    state = osvdb.status(path)
    assert state.counts == {"PyPI": (5, 2), "npm": (2, 1)}
    assert [s.ecosystem for s in state.sources] == ["PyPI", "npm"] and state.built_at


def test_index_skips_oversized_and_broken_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = tmp_path / "PyPI.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("broken.json", "{not json")
        bundle.writestr("list.json", "[]")
        bundle.writestr(
            "big.json", json.dumps(osv.advisory("GHSA-big", "PyPI", "big", versions=["1"], summary="x" * 500))
        )
        bundle.writestr("ok.json", json.dumps(osv.advisory("GHSA-ok", "PyPI", "ok", versions=["1"])))
    monkeypatch.setattr(osvdb, "MAX_ENTRY_BYTES", 400)
    source = osvdb.Source("PyPI", "https://example.invalid", "0" * 64, 1, osvdb._now())
    osvdb.build_index({"PyPI": (archive, source)}, tmp_path / "osv.sqlite3")
    assert osvdb.status(tmp_path / "osv.sqlite3").counts == {"PyPI": (1, 0)}
    monkeypatch.setattr(osvdb, "MAX_UNPACKED_BYTES", 10)
    with pytest.raises(Rejected, match="unpacks to more than"):
        osvdb.build_index({"PyPI": (archive, source)}, tmp_path / "other.sqlite3")
    assert not (tmp_path / "other.sqlite3").exists()
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".osv-")] == []  # no temp file left behind


def test_connect_refuses_missing_or_foreign_files(tmp_path: Path) -> None:
    assert osvdb.connect(tmp_path / "missing.sqlite3") is None
    other = tmp_path / "other.sqlite3"
    sqlite3.connect(other).executescript("CREATE TABLE meta (key TEXT, value TEXT);").close()
    assert osvdb.connect(other) is None
    (tmp_path / "junk.sqlite3").write_bytes(b"junk")
    assert osvdb.connect(tmp_path / "junk.sqlite3") is None
    assert osvdb.status(tmp_path / "missing.sqlite3").age_s() is None


def test_status_age(tmp_path: Path) -> None:
    path = osv.build(tmp_path, downloaded_at="2026-10-01T00:00:00+00:00")
    now = datetime(2026, 10, 4, tzinfo=timezone.utc).timestamp()
    assert osvdb.status(path).age_s(now=now) == 3 * 86400


def test_cache_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KESTRIX_SCAN_DB", str(tmp_path / "custom"))
    assert osvdb.db_path() == tmp_path / "custom" / "osv.sqlite3"
    monkeypatch.delenv("KESTRIX_SCAN_DB")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("sys.platform", "darwin")
    assert osvdb.cache_dir() == tmp_path / "Library" / "Caches" / "kestrix-scan"
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert osvdb.cache_dir() == tmp_path / "xdg" / "kestrix-scan"
    monkeypatch.setenv("XDG_CACHE_HOME", "relative")  # ignored, as the XDG specification says
    assert osvdb.cache_dir() == tmp_path / ".cache" / "kestrix-scan"
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert osvdb.cache_dir() == tmp_path / "local" / "kestrix-scan"


# ----- db update against a fake HTTPS server


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, url: str, headers: dict[str, str]) -> None:
        super().__init__(body)
        self.url = url
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value

    def geturl(self) -> str:
        return self.url


class FakeOpener:
    """Serves synthetic exports; records each request. ``etag`` answers a matching If-None-Match with 304."""

    def __init__(
        self,
        bodies: dict[str, bytes],
        *,
        etag: str = '"v1"',
        url_override: str | None = None,
        length: int | None = None,
    ) -> None:
        self.bodies = bodies
        self.etag = etag
        self.url_override = url_override
        self.length = length
        self.etags: dict[str, str] = {}  # per-ecosystem override of ``etag``
        self.modified = "Thu, 22 Oct 2026 04:00:00 GMT"
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: float) -> FakeResponse:
        self.requests.append(request)
        url = request.full_url
        assert url.startswith("https://") and timeout > 0
        ecosystem = url.split("/")[-2]
        etag = self.etags.get(ecosystem, self.etag)
        if request.get_header("If-none-match") == etag:
            raise urllib.error.HTTPError(url, 304, "Not Modified", Message(), None)
        body = self.bodies[ecosystem]
        length = str(self.length if self.length is not None else len(body))
        headers = {"Content-Length": length, "ETag": etag, "Last-Modified": self.modified}
        return FakeResponse(body, self.url_override or url, headers)


def _zip_bytes(tmp_path: Path, name: str, records: list[dict[str, Any]]) -> bytes:
    return osv.write_zip(tmp_path / "server" / name, records).read_bytes()


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeOpener:
    opener = FakeOpener(
        {"PyPI": _zip_bytes(tmp_path, "PyPI.zip", osv.PYPI), "npm": _zip_bytes(tmp_path, "npm.zip", osv.NPM)}
    )
    monkeypatch.setattr(osvdb, "_opener", lambda: opener)
    return opener


def test_update_downloads_verifies_and_indexes(server: FakeOpener, isolated_osv_index: Path) -> None:
    lines: list[str] = []
    path = osvdb.update(["PyPI", "npm"], progress=lines.append)
    assert path == isolated_osv_index / "osv.sqlite3"
    state = osvdb.status()
    assert state.counts == {"PyPI": (5, 2), "npm": (2, 1)}
    by_eco = {s.ecosystem: s for s in state.sources}
    assert by_eco["PyPI"].sha256 == hashlib.sha256(server.bodies["PyPI"]).hexdigest()
    assert by_eco["PyPI"].size == len(server.bodies["PyPI"]) and by_eco["PyPI"].etag == '"v1"'
    assert by_eco["npm"].url == "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip"
    assert (isolated_osv_index / "downloads" / "PyPI.zip").read_bytes() == server.bodies["PyPI"]
    assert any("indexing" in line for line in lines)

    # A second update sends the ETag, gets 304 and keeps the cached zip; npm, not asked for, stays indexed.
    server.requests.clear()
    osvdb.update(["PyPI"])
    assert [r.get_header("If-none-match") for r in server.requests] == ['"v1"']
    assert [r.get_header("If-modified-since") for r in server.requests] == [server.modified]
    assert osvdb.status().counts == {"PyPI": (5, 2), "npm": (2, 1)}


def test_update_refuses_bad_responses(
    server: FakeOpener, isolated_osv_index: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(Rejected, match="unsupported ecosystem"):
        osvdb.update(["Bogus"])
    server.url_override = "http://insecure.example.invalid/all.zip"
    with pytest.raises(Rejected, match="non-HTTPS"):
        osvdb.update(["PyPI"])
    server.url_override = None
    server.length = osvdb.MAX_DOWNLOAD_BYTES + 1
    with pytest.raises(Rejected, match="byte cap"):
        osvdb.update(["PyPI"])
    server.length = 10  # a Content-Length that understates the body: the streamed byte count still stops it
    monkeypatch.setattr(osvdb, "MAX_DOWNLOAD_BYTES", 100)
    with pytest.raises(Rejected, match="larger than"):
        osvdb.update(["PyPI"])
    server.length = None
    monkeypatch.setattr(osvdb, "MAX_DOWNLOAD_BYTES", 2 * 1024**3)
    server.bodies["PyPI"] = b"not a zip"
    with pytest.raises(Rejected, match="did not return a zip"):
        osvdb.update(["PyPI"])
    assert not (isolated_osv_index / "downloads" / "PyPI.zip").exists()
    assert not list((isolated_osv_index / "downloads").glob(".*"))  # temp files are removed
    assert osvdb.connect() is None


def test_redirect_to_http_is_refused() -> None:
    import urllib.request

    handler = next(h for h in osvdb._opener().handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
    request = urllib.request.Request("https://storage.googleapis.com/x")
    with pytest.raises(Rejected, match="away from HTTPS"):
        handler.redirect_request(request, None, 302, "Found", Message(), "http://example.invalid/x")
    assert handler.redirect_request(request, None, 302, "Found", Message(), "https://example.invalid/x") is not None


def test_db_cli_update_and_status(server: FakeOpener) -> None:
    missing = run("db", "status")
    assert missing.exit_code == 1 and "No vulnerability index" in missing.stdout
    result = run("db", "update", "--ecosystem", "npm")
    assert result.exit_code == 0, result.output
    assert "Updated" in result.stdout and "npm: 2 advisories (1 malicious-package reports)" in result.stdout
    assert "PyPI" not in result.stdout
    status = run("db", "status")
    assert status.exit_code == 0 and "Age: 0.0 days" in status.stdout and "stale" not in status.stdout
    bad = run("db", "update", "--ecosystem", "Bogus")
    assert bad.exit_code == 2


def test_db_cli_reports_a_failed_download(server: FakeOpener) -> None:
    server.bodies["PyPI"] = b"not a zip"
    result = run("db", "update", "--ecosystem", "PyPI")
    assert result.exit_code == 2 and "did not return a zip" in result.stderr


def test_db_cli_marks_a_stale_index(isolated_osv_index: Path) -> None:
    osv.build(isolated_osv_index, downloaded_at="2020-01-01T00:00:00+00:00")
    assert "(stale, over 7 days: run `kestrix-scan db update`)" in run("db", "status").stdout


def _ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def test_unchanged_exports_keep_the_index_and_only_record_the_check(
    server: FakeOpener, isolated_osv_index: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    osvdb.update(["PyPI", "npm"])
    index = isolated_osv_index / "osv.sqlite3"
    built = index.stat().st_mtime_ns
    first = {s.ecosystem: s for s in osvdb.status().sources}
    assert first["npm"].last_modified == server.modified
    monkeypatch.setattr(osvdb, "_now", lambda: "2099-01-01T00:00:00+00:00")
    lines: list[str] = []
    osvdb.update(["PyPI", "npm"], progress=lines.append)
    assert index.stat().st_mtime_ns == built  # not rebuilt
    assert any("unchanged" in line and "index kept" in line for line in lines)
    state = osvdb.status()
    assert set(state.checked) == {"PyPI", "npm"} and state.checked["npm"] == "2099-01-01T00:00:00+00:00"
    # The age counts from the last confirmation, not from the download.
    assert state.age_s(now=_ts("2099-01-02T00:00:00+00:00")) == 86400
    assert "confirmed current 2099-01-01" in run("db", "status").stdout


def test_a_changed_export_rebuilds_and_a_corrupt_cached_zip_is_downloaded_again(
    server: FakeOpener, isolated_osv_index: Path, tmp_path: Path
) -> None:
    osvdb.update(["PyPI", "npm"])
    index = isolated_osv_index / "osv.sqlite3"
    built = index.stat().st_mtime_ns
    server.etags["npm"] = '"v2"'  # npm changed on the server (a new advisory), PyPI did not
    server.bodies["npm"] = _zip_bytes(
        tmp_path, "npm2.zip", [*osv.NPM, osv.advisory("MAL-2026-300", "npm", "x", events=[{"introduced": "0"}])]
    )
    (isolated_osv_index / "downloads" / "PyPI.zip").write_bytes(b"tampered")
    lines: list[str] = []
    osvdb.update(["PyPI", "npm"], progress=lines.append)
    assert index.stat().st_mtime_ns != built
    assert any("PyPI: cached export does not match its SHA-256" in line for line in lines)
    assert (isolated_osv_index / "downloads" / "PyPI.zip").read_bytes() == server.bodies["PyPI"]
    by_eco = {s.ecosystem: s for s in osvdb.status().sources}
    assert osvdb.status().counts["npm"] == (3, 2)
    assert by_eco["npm"].etag == '"v2"' and by_eco["PyPI"].sha256 == hashlib.sha256(server.bodies["PyPI"]).hexdigest()


def test_db_update_downloads_only_the_ecosystems_the_project_needs(
    server: FakeOpener, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.bodies["Packagist"] = _zip_bytes(tmp_path, "Packagist.zip", osv.PACKAGIST)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "composer.lock").write_text('{"packages": []}')
    (project / "vendor" / "x").mkdir(parents=True)
    (project / "vendor" / "x" / "Cargo.lock").write_text("")  # vendored: not walked
    monkeypatch.chdir(project)
    result = run("db", "update")
    assert result.exit_code == 0, result.output
    assert [r.full_url.split("/")[-2] for r in server.requests] == ["Packagist"]
    assert "ecosystems: Packagist" in result.stderr
    assert "Packagist: 1 advisories" in result.stdout
    # Nothing to detect and nothing configured: the default pair.
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(empty)
    monkeypatch.setenv("KESTRIX_SCAN_DB", str(tmp_path / "other-index"))
    server.requests.clear()
    assert run("db", "update").exit_code == 0
    assert sorted(r.full_url.split("/")[-2] for r in server.requests) == ["PyPI", "npm"]
    # [tool.kestrix] db-ecosystems adds to what is found.
    (empty / ".kestrix.toml").write_text('db-ecosystems = ["Packagist"]\n')
    monkeypatch.setenv("KESTRIX_SCAN_DB", str(tmp_path / "third-index"))
    server.requests.clear()
    assert run("db", "update").exit_code == 0
    assert [r.full_url.split("/")[-2] for r in server.requests] == ["Packagist"]


def test_db_status_json_and_max_age(isolated_osv_index: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = json.loads(run("db", "status", "--json").stdout)
    assert missing["present"] is False and missing["stale"] is True
    osv.build(isolated_osv_index, downloaded_at="2020-01-01T00:00:00+00:00")
    data = json.loads(run("db", "status", "--json").stdout)
    assert data["present"] and data["stale"] and data["max_age_days"] == 7 and data["age_days"] > 1000
    assert set(data["ecosystems"]) == {"PyPI", "npm"} and data["ecosystems"]["PyPI"]["advisories"] == 5
    monkeypatch.setenv("KESTRIX_SCAN_MAX_AGE_DAYS", "100000")
    assert json.loads(run("db", "status", "--json").stdout)["stale"] is False
    assert "stale" not in run("db", "status").stdout


def test_max_age_days_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KESTRIX_SCAN_MAX_AGE_DAYS", raising=False)
    assert osvdb.max_age_days() == 7 and osvdb.max_age_days(30) == 30
    monkeypatch.setenv("KESTRIX_SCAN_MAX_AGE_DAYS", "2")
    assert osvdb.max_age_days(30) == 2
    for bad in ("0", "-1", "soon", ""):
        monkeypatch.setenv("KESTRIX_SCAN_MAX_AGE_DAYS", bad)
        assert osvdb.max_age_days(30) == 30
