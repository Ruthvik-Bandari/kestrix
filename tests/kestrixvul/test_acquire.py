# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import hashlib
import io
import urllib.request
from pathlib import Path

import pytest

from kestrixvul.acquire import VerificationError, download, fetch, sha256sums, verify
from kestrixvul.sources import ARCHIVES, GIT_SOURCES, ArchiveSource, Artifact

PAYLOAD = b"synthetic archive bytes\n" * 100


def _artifact(sha256: str | None = None, md5: str | None = None, size: int | None = None) -> Artifact:
    return Artifact(
        filename="data.zip",
        url="https://example.org/data.zip",
        size=len(PAYLOAD) if size is None else size,
        md5=md5
        or hashlib.md5(
            PAYLOAD, usedforsecurity=False
        ).hexdigest(),  # kestrix: ignore[py.crypto.weak_hash] mirrors the Zenodo MD5 checksum
        sha256=sha256,
    )


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, status: int) -> None:
        super().__init__(data)
        self.status = status


def ranged_opener(calls: list[str | None]):
    def opener(request: urllib.request.Request) -> FakeResponse:
        header = request.get_header("Range")
        calls.append(header)
        start = int(header.split("=")[1].rstrip("-")) if header else 0
        return FakeResponse(PAYLOAD[start:], 206 if header else 200)

    return opener


def test_verify_accepts_matching_size_md5_and_pinned_sha256(tmp_path: Path):
    path = tmp_path / "data.zip"
    path.write_bytes(PAYLOAD)
    sha = hashlib.sha256(PAYLOAD).hexdigest()
    assert verify(path, _artifact()) == sha
    assert verify(path, _artifact(sha256=sha)) == sha


@pytest.mark.parametrize(
    "artifact",
    [_artifact(size=len(PAYLOAD) + 1), _artifact(md5="0" * 32), _artifact(sha256="0" * 64)],
    ids=["size", "md5", "sha256"],
)
def test_verify_refuses_any_mismatch(tmp_path: Path, artifact: Artifact):
    path = tmp_path / "data.zip"
    path.write_bytes(PAYLOAD)
    with pytest.raises(VerificationError):
        verify(path, artifact)


def test_download_resumes_a_partial_file(tmp_path: Path):
    dest = tmp_path / "data.zip"
    (tmp_path / "data.zip.part").write_bytes(PAYLOAD[:100])
    calls: list[str | None] = []
    download(_artifact(), dest, ranged_opener(calls))
    assert dest.read_bytes() == PAYLOAD
    assert calls == ["bytes=100-"]
    assert not (tmp_path / "data.zip.part").exists()


def test_download_restarts_when_the_server_ignores_the_range(tmp_path: Path):
    dest = tmp_path / "data.zip"
    (tmp_path / "data.zip.part").write_bytes(b"stale")

    def opener(request: urllib.request.Request) -> FakeResponse:
        return FakeResponse(PAYLOAD, 200)

    download(_artifact(), dest, opener)
    assert dest.read_bytes() == PAYLOAD


def test_download_refuses_plain_http(tmp_path: Path):
    plain = Artifact("x", "http://example.org/x", 1, "0" * 32, None)
    with pytest.raises(VerificationError, match="non-https"):
        download(plain, tmp_path / "x", ranged_opener([]))


def test_fetch_moves_a_mismatching_file_aside_and_fails(tmp_path: Path):
    source = ArchiveSource("fake", "t", "v1", "doi", "https://example.org", "CC-BY-4.0", "use", "who", (_artifact(),))
    (tmp_path / "fake").mkdir()
    (tmp_path / "fake" / "data.zip").write_bytes(b"x" * len(PAYLOAD))
    with pytest.raises(VerificationError, match="md5"):
        fetch(source, tmp_path, ranged_opener([]))
    assert (tmp_path / "fake" / "data.zip.rejected").exists()
    assert not (tmp_path / "fake" / "data.zip").exists()


def test_fetch_writes_a_private_file_and_manifest(tmp_path: Path):
    source = ArchiveSource("fake", "t", "v1", "doi", "https://example.org", "CC-BY-4.0", "use", "who", (_artifact(),))
    record = fetch(source, tmp_path, ranged_opener([]))
    assert (tmp_path / "fake" / "data.zip").stat().st_mode & 0o777 == 0o600
    assert record["files"][0]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert record["files"][0]["sha256_pinned"] is False
    sums = sha256sums([record, {"source": "git", "files": {"a/b.json": "f" * 64}}])
    assert sums.splitlines() == [f"{hashlib.sha256(PAYLOAD).hexdigest()}  fake/data.zip", f"{'f' * 64}  git/a/b.json"]


def test_every_pin_is_https_and_well_formed():
    for source in ARCHIVES:
        for artifact in source.artifacts:
            assert artifact.url.startswith("https://zenodo.org/api/records/")
            assert len(artifact.md5) == 32 and artifact.size > 0
            assert artifact.sha256 is None or len(artifact.sha256) == 64
    for git in GIT_SOURCES:
        assert git.url.startswith("https://github.com/") and len(git.commit) == 40
