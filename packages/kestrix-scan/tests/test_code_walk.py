# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
from collections.abc import Callable
from pathlib import Path

import pytest

from kestrix_scan import walk
from kestrix_scan.walk import Candidate, Unreadable, _GitIgnore, collect, read_text


@pytest.fixture
def no_git(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(walk, "git_executable", lambda: None)


def names(root: Path) -> list[str]:
    return sorted(c.rel for c in collect([root], root).candidates)


def write(root: Path, rel: str, data: str | bytes = "x = 1\n") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data)
    return path


@pytest.mark.usefixtures("no_git")
def test_skips_dependency_and_build_dirs(tmp_path: Path) -> None:
    for rel in ("a.py", "node_modules/m/i.js", ".venv/lib/x.py", ".git/config", "build/o.py", "pkg/__pycache__/c.py"):
        write(tmp_path, rel)
    assert names(tmp_path) == ["a.py"]


@pytest.mark.usefixtures("no_git")
def test_skips_framework_build_dirs_and_keeps_web_files(tmp_path: Path) -> None:
    skipped = (".next/server/p.html", ".nuxt/dist/a.vue", ".svelte-kit/output/a.svelte", ".output/public/i.html")
    kept = ("src/App.vue", "src/Page.svelte", "public/index.html", "styles/site.scss", "next.config.mjs")
    for rel in (*skipped, *kept, ".angular/cache/x.css"):
        write(tmp_path, rel)
    assert names(tmp_path) == sorted(kept)


@pytest.mark.usefixtures("no_git")
def test_keeps_php_and_sql_files_and_skips_composer_vendor(tmp_path: Path) -> None:
    kept = ("src/a.php", "views/page.phtml", "resources/views/x.blade.php", "db/schema.sql")
    for rel in (*kept, "vendor/laravel/framework/src/b.php"):
        write(tmp_path, rel)
    assert names(tmp_path) == sorted(kept)


@pytest.mark.usefixtures("no_git")
def test_keeps_go_jvm_dotnet_and_ruby_files_and_skips_their_build_dirs(tmp_path: Path) -> None:
    kept = (
        "cmd/main.go",
        "src/main/java/A.java",
        "app/B.kt",
        "build.gradle.kts",
        "Api/C.cs",
        "app/x.rb",
        "app/v.html.erb",
    )
    for rel in (*kept, "vendor/github.com/x/y.go", "target/classes/A.java", "Api/obj/Debug/g.cs", ".gradle/x.kts"):
        write(tmp_path, rel)
    assert names(tmp_path) == sorted(kept)


@pytest.mark.usefixtures("no_git")
def test_big_file_is_reported_as_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(walk, "MAX_FILE_BYTES", 10)
    write(tmp_path, "big.py", "x = '" + "a" * 20 + "'\n")
    result = collect([tmp_path], tmp_path)
    assert result.candidates == []
    assert [(s.path, s.reason) for s in result.skipped] == [("big.py", "too_large")]


def test_binary_file_is_unreadable_as_text(tmp_path: Path) -> None:
    path = write(tmp_path, "blob.bin", b"\x7fELF\x00\x01")
    with pytest.raises(Unreadable) as caught:
        read_text(Candidate(path=path, rel="blob.bin"))
    assert caught.value.reason == "binary"


def test_invalid_utf8_is_replaced(tmp_path: Path) -> None:
    path = write(tmp_path, "latin.txt", b"caf\xe9\n")
    assert read_text(Candidate(path=path, rel="latin.txt")) == "caf�\n"


@pytest.mark.usefixtures("no_git")
def test_file_limit_truncates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(walk, "MAX_FILES", 2)
    for i in range(4):
        write(tmp_path, f"f{i}.py")
    result = collect([tmp_path], tmp_path)
    assert len(result.candidates) == 2 and result.truncated


@pytest.mark.usefixtures("no_git")
def test_symlinks_escaping_the_root_are_skipped(tmp_path: Path) -> None:
    root, outside = tmp_path / "root", tmp_path / "outside"
    write(outside, "secret.py")
    write(root, "real.py")
    (root / "link.py").symlink_to(outside / "secret.py")
    (root / "linkdir").symlink_to(outside, target_is_directory=True)
    (root / "inside.py").symlink_to(root / "real.py")
    result = collect([root], root)
    assert [c.rel for c in result.candidates] == ["real.py"]
    assert sorted((s.path, s.reason) for s in result.skipped) == [
        ("link.py", "symlink_outside_root"),
        ("linkdir", "symlink_outside_root"),
    ]


@pytest.mark.usefixtures("no_git")
def test_gitignore_fallback_parser(tmp_path: Path) -> None:
    write(tmp_path, ".gitignore", "# comment\n*.log\nsecret/\n/top.py\n!keep.log\ndocs/**/gen\n")
    for rel in ("a.log", "keep.log", "secret/x.py", "top.py", "sub/top.py", "docs/a/b/gen", "docs/a/ok.py"):
        write(tmp_path, rel)
    assert names(tmp_path) == [".gitignore", "docs/a/ok.py", "keep.log", "sub/top.py"]


def test_gitignore_parser_rules() -> None:
    ignore = _GitIgnore.parse("build-*/\n**/cache\n*.py[co]\n\\#hash\nlib/**\n!lib/keep.py\n")
    assert ignore.ignored("build-x", is_dir=True) and not ignore.ignored("build-x", is_dir=False)
    assert ignore.ignored("a/b/cache", is_dir=False) and ignore.ignored("cache", is_dir=True)
    assert ignore.ignored("m.pyc", is_dir=False) and not ignore.ignored("m.py", is_dir=False)
    assert ignore.ignored("#hash", is_dir=False)
    assert ignore.ignored("lib/a/b.py", is_dir=False) and not ignore.ignored("lib/keep.py", is_dir=False)


def test_git_ls_files_is_preferred(repo: Path, git: Callable[..., str]) -> None:
    write(repo, ".gitignore", "ignored/\n*.tmp\n")
    write(repo, "tracked.py")
    write(repo, "untracked.py")
    write(repo, "ignored/x.py")
    write(repo, "scratch.tmp")
    write(repo, "sub/.gitignore", "local.py\n")  # nested ignore files are honored through git
    write(repo, "sub/local.py")
    git(repo, "add", "tracked.py")
    assert names(repo) == [".gitignore", "sub/.gitignore", "tracked.py", "untracked.py"]


@pytest.mark.usefixtures("no_git")
def test_explicit_file_is_scanned_even_if_ignored(tmp_path: Path) -> None:
    write(tmp_path, ".gitignore", "*.env\n")
    path = write(tmp_path, "prod.env", "A=1\n")
    assert [c.rel for c in collect([path], tmp_path).candidates] == ["prod.env"]
