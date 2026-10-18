import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from kestrixbench import __main__ as cli
from kestrixbench.acquire import AcquisitionError, checkout, manifest, sparse_patterns
from kestrixbench.qc import QC
from kestrixbench.sources import SOURCES, Source


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Source, Path]:
    repo = tmp_path / "upstream"
    (repo / "keep/sub").mkdir(parents=True)
    (repo / "keep/other").mkdir()
    (repo / "keep/top.txt").write_text("parent file\n")
    (repo / "keep/other/no.txt").write_text("sibling\n")
    (repo / "skip").mkdir()
    (repo / "LICENSE").write_text("MIT\n")
    (repo / "keep/sub/a.yml").write_text("a: 1\n")
    (repo / "skip/big.bin").write_bytes(b"x" * 64)
    _git(repo, "init", "--quiet")
    _git(repo, "config", "uploadpack.allowFilter", "true")
    _git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    _git(repo, "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.org", "commit", "--quiet", "-m", "init")
    source = Source(
        name="fake",
        url=repo.as_uri(),
        commit=_git(repo, "rev-parse", "HEAD"),
        revision_label="test",
        license_spdx="MIT",
        license_file="LICENSE",
        allowed_use="test",
        attribution="test",
        paths=("keep/sub",),
    )
    return source, tmp_path / "data" / "fake"


def test_checkout_is_sparse_and_pinned(upstream):
    source, dest = upstream
    checkout(source, dest)
    record = manifest(source, dest)
    assert record["commit"] == source.commit
    assert list(record["files"]) == ["keep/sub/a.yml"]
    assert not (dest / "skip").exists()
    assert not (dest / "keep/other").exists()
    assert record["license"]["spdx"] == "MIT"
    checkout(source, dest)  # matching checkout is reused
    assert manifest(source, dest)["content_sha256"] == record["content_sha256"]


def test_sparse_patterns_match_cone_mode():
    assert sparse_patterns(("a/b/c", "a/d", "a/b/c/e")) == [
        "/*",
        "!/*/",
        "/a/",
        "!/a/*/",
        "/a/b/",
        "!/a/b/*/",
        "/a/b/c/",
        "/a/d/",
    ]


def test_unknown_commit_fails(upstream):
    source, dest = upstream
    with pytest.raises(AcquisitionError):
        checkout(replace(source, commit="0" * 40), dest)


def test_missing_license_or_path_fails(upstream):
    source, dest = upstream
    checkout(source, dest)
    with pytest.raises(AcquisitionError, match="license"):
        manifest(replace(source, license_file="NOPE"), dest)
    with pytest.raises(AcquisitionError, match="pinned path"):
        manifest(replace(source, paths=("missing",)), dest)


def test_every_pinned_source_is_a_full_sha():
    for source in SOURCES:
        assert len(source.commit) == 40
        assert int(source.commit, 16) >= 0
        assert source.url.startswith("https://github.com/")


def test_cli_refuses_root_inside_repository():
    with pytest.raises(SystemExit):
        cli.main(["qc", "--root", str(Path(cli.__file__).resolve().parents[2] / "data")])


def test_qc_detects_files_changed_after_acquisition(upstream, monkeypatch, capsys):
    source, dest = upstream
    monkeypatch.setattr(cli, "SOURCES", (source,))
    monkeypatch.setattr(cli, "by_name", lambda _: source)
    monkeypatch.setitem(QC, "fake", lambda _: {"ok": True})
    root = dest.parent
    assert cli.main(["acquire", "--root", str(root)]) == 0
    assert json.loads((root / "manifests/fake.json").read_text())["file_count"] == 1
    assert cli.main(["qc", "--root", str(root)]) == 0
    assert json.loads((root / "reports/qc-fake.json").read_text())["checks"] == {"ok": True}
    (dest / "keep/sub/a.yml").write_text("a: 2\n")
    assert cli.main(["qc", "--root", str(root)]) == 1
    assert "changed since acquisition" in capsys.readouterr().err


def test_acquire_imports_only_the_standard_library():
    code = (
        "import sys, kestrixbench.__main__; print(sorted(m for m in ('yaml', 'pydantic', 'httpx') if m in sys.modules))"
    )
    out = subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, text=True).stdout
    assert out.strip() == "[]"
