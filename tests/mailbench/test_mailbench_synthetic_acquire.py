# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The synthetic source behaves as labelled and is reproducible; acquire verifies and records files."""

import hashlib
import io
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from kestrix.mail.analyze import analyze
from kestrixmailbench.acquire import acquire, download, sha256sums
from kestrixmailbench.common import Layout, MailBenchError
from kestrixmailbench.sources import Document, Source, SourceFile
from kestrixmailbench.synthetic import FAMILIES, generate


def test_synthetic_messages_are_reproducible_and_unique() -> None:
    first, second = generate("seed", 5), generate("seed", 5)
    assert first == second
    assert generate("other", 5) != first
    assert len({data for _, _, data in first}) == len(first)
    assert {family for family, _, _ in first} == {f for f, _ in FAMILIES}


def test_synthetic_families_do_what_their_label_says() -> None:
    for family, label, data in generate("seed", 4):
        verdict = analyze(data).verdict
        if label == "ham":
            assert verdict == "clean", family
        else:
            assert verdict in ("suspicious", "malicious"), family


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, headers: dict[str, str] | None = None) -> None:
        super().__init__(data)
        self.status = 200
        self.headers = headers or {"Content-Length": str(len(data))}


def opener_for(files: dict[str, bytes]) -> Any:
    def opener(request: urllib.request.Request) -> FakeResponse:
        return FakeResponse(files[request.full_url])

    return opener


SOURCE = Source(
    "nazario",
    "t",
    "CC-BY-4.0",
    "note",
    "attr",
    "https://x/",
    (SourceFile("a.mbox", "https://x/a.mbox", "mbox", "phishing"),),
    (Document("README.txt", "https://x/README.txt"),),
)


def test_download_records_size_and_sha256(tmp_path: Path) -> None:
    info = download("https://x/a", tmp_path / "d" / "a", opener_for({"https://x/a": b"hello"}))
    assert info["size"] == 5 and info["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert (tmp_path / "d" / "a").read_bytes() == b"hello"


def test_download_refuses_http_and_short_reads(tmp_path: Path) -> None:
    with pytest.raises(MailBenchError, match="non-https"):
        download("http://x/a", tmp_path / "a")

    def short(request: urllib.request.Request) -> FakeResponse:
        return FakeResponse(b"abc", {"Content-Length": "10"})

    with pytest.raises(MailBenchError, match="download failed"):
        download("https://x/a", tmp_path / "a", short, retries=0)
    assert not (tmp_path / "a").exists()


def test_acquire_writes_manifest_and_verifies_on_rerun(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import kestrixmailbench.acquire as module

    monkeypatch.setattr(module, "SOURCES", (SOURCE,))
    layout = Layout(tmp_path)
    web = {"https://x/a.mbox": b"mbox bytes", "https://x/README.txt": b"readme"}
    manifest = acquire(layout, opener=opener_for(web))
    files = {f["filename"]: f for f in manifest["sources"][0]["files"]}
    assert files["a.mbox"]["sha256"] == hashlib.sha256(b"mbox bytes").hexdigest()
    assert files["a.mbox"]["kind"] == "mbox" and files["README.txt"]["kind"] == "document"
    assert manifest["sources"][0]["license"]["spdx"] == "CC-BY-4.0"
    assert (layout.manifests / "SHA256SUMS").read_text() == sha256sums(manifest["sources"])
    assert oct((layout.raw / "nazario" / "a.mbox").stat().st_mode & 0o777) == "0o600"
    again = acquire(layout, opener=opener_for({}))  # nothing is downloaded the second time
    assert again["sources"][0]["files"][0]["sha256"] == files["a.mbox"]["sha256"]


def test_acquire_rejects_a_file_that_no_longer_matches_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import kestrixmailbench.acquire as module

    monkeypatch.setattr(module, "SOURCES", (SOURCE,))
    layout = Layout(tmp_path)
    acquire(layout, opener=opener_for({"https://x/a.mbox": b"one", "https://x/README.txt": b"r"}))
    (layout.raw / "nazario" / "a.mbox").write_bytes(b"tampered")
    with pytest.raises(MailBenchError, match="does not match the manifest"):
        acquire(layout, opener=opener_for({}))
    assert (layout.raw / "nazario" / "a.mbox.rejected").exists()
