# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from code_samples import fake

from kestrix.code import exit_code, scan
from kestrix.code.analyze import MISSING_REASON, load_baseline, parse_diff, write_baseline
from kestrix.code.models import ScanReport
from kestrix.core.errors import Rejected

SHELL = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"


def scan_dir(root: Path, **kwargs) -> ScanReport:
    return scan([root], root=root, **kwargs)


def test_report_shape_and_order(tmp_path: Path) -> None:
    (tmp_path / "b.py").write_text("import hashlib\nh = hashlib.md5(b'')\n")
    (tmp_path / "a.py").write_text(SHELL)
    (tmp_path / "keys.txt").write_text(f"token={fake('github_token')}\n")
    report = scan_dir(tmp_path)
    assert [(f.severity, f.path) for f in report.findings] == [
        ("critical", "keys.txt"),
        ("high", "a.py"),
        ("medium", "b.py"),
    ]
    assert report.counts.model_dump() == {"critical": 1, "high": 1, "medium": 1, "low": 0}
    assert report.files_scanned == 3 and report.root == tmp_path.resolve().as_posix()
    assert report.generated_by == "Kestrix by Ruthvik Bandari" and report.schema_version == 1
    finding = report.findings[1]
    assert (finding.rule_id, finding.cwe, finding.line, finding.column) == ("py.subprocess.shell_true", "CWE-78", 4, 5)
    assert finding.why and finding.fix and finding.snippet == "subprocess.run(cmd, shell=True)"


def test_python_snippets_have_secrets_redacted(tmp_path: Path) -> None:
    token = fake("stripe_live_key")
    (tmp_path / "a.py").write_text(f"import os\ndef f(x):\n    os.system(x + ' --key {token}')\n")
    report = scan_dir(tmp_path)
    assert {f.rule_id for f in report.findings} == {"py.os.system", "secret.stripe_live_key"}
    assert all(token not in f.snippet for f in report.findings)


def test_syntax_error_skips_python_rules_but_not_secrets(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text(f"def f(:\n    token = '{fake('github_token')}'\n")
    report = scan_dir(tmp_path)
    assert [(s.path, s.reason) for s in report.files_skipped] == [("broken.py", "syntax_error")]
    assert [f.rule_id for f in report.findings] == ["secret.github_token"]


def test_binary_files_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "blob.dat").write_bytes(b"\x00" + fake("github_token").encode())
    report = scan_dir(tmp_path)
    assert report.findings == [] and [s.reason for s in report.files_skipped] == ["binary"]


# ----- suppression


def test_suppression_with_reason_on_the_line(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import subprocess\nsubprocess.run(CMD, shell=True)  # kestrix: ignore[py.subprocess.shell_true] CMD is fixed\n"
    )
    report = scan_dir(tmp_path)
    assert report.findings == [] and report.suppressed == 1 and report.notes == []


def test_suppression_on_the_line_above_with_several_ids(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import os, pickle\n# kestrix: ignore[py.os.system, py.deserialize.pickle] trusted build script\n"
        "os.system(pickle.loads(B))\n"
    )
    assert scan_dir(tmp_path).suppressed == 2


def test_suppression_without_reason_does_not_suppress(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import subprocess\nsubprocess.run(c, shell=True)  # kestrix: ignore[py.subprocess.shell_true]\n"
    )
    report = scan_dir(tmp_path)
    assert [f.rule_id for f in report.findings] == ["py.subprocess.shell_true"]
    assert report.suppressed == 0
    assert [(n.id, n.path, n.line) for n in report.notes] == [(MISSING_REASON, "a.py", 2)]


def test_suppression_for_another_rule_does_not_apply(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "import subprocess\nsubprocess.run(c, shell=True)  # kestrix: ignore[py.os.system] wrong id\n"
    )
    assert len(scan_dir(tmp_path).findings) == 1


def test_slash_suppression_in_other_text_files(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        f"// kestrix: ignore[secret.github_token] revoked test fixture\nconst t = '{fake('github_token')}';\n"
    )
    report = scan_dir(tmp_path)
    assert report.findings == [] and report.suppressed == 1


# ----- baseline and fingerprints


def test_baseline_round_trip(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text(SHELL)
    first = scan([src], root=src)
    baseline = tmp_path / "baseline.json"
    assert write_baseline(baseline, first.findings) == 1
    assert stat.S_IMODE(baseline.stat().st_mode) == 0o644
    assert json.loads(baseline.read_text()) == [first.findings[0].fingerprint]
    second = scan([src], root=src, baseline=baseline)
    assert second.findings == [] and second.baseline_filtered == 1
    (src / "b.py").write_text("import os\ndef f(n):\n    os.system(n)\n")
    third = scan([src], root=src, baseline=baseline)
    assert [f.rule_id for f in third.findings] == ["py.os.system"] and third.baseline_filtered == 1


def test_fingerprint_survives_line_shifts(tmp_path: Path) -> None:
    path = tmp_path / "a.py"
    path.write_text(SHELL)
    before = scan_dir(tmp_path).findings[0]
    path.write_text(
        "# a new header\n\n\n"
        + SHELL.replace("    subprocess", "        subprocess").replace("def run", "if True:\n  def run")
    )
    after = scan_dir(tmp_path).findings[0]
    assert after.line != before.line and after.fingerprint == before.fingerprint


def test_fingerprint_depends_on_path_and_rule(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(SHELL)
    (tmp_path / "b.py").write_text(SHELL)
    first, second = scan_dir(tmp_path).findings
    assert first.fingerprint != second.fingerprint


@pytest.mark.parametrize("content", ["{", '{"a": 1}', '["not-a-fingerprint"]', "[" * 100000])
def test_invalid_baseline_is_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "b.json"
    path.write_text(content)
    with pytest.raises(Rejected):
        load_baseline(path)


def test_missing_baseline_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(Rejected, match="cannot read baseline"):
        load_baseline(tmp_path / "nope.json")


# ----- targets and exit codes


def test_missing_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(Rejected, match="path not found"):
        scan([tmp_path / "nope"], root=tmp_path)


def test_path_outside_root_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with pytest.raises(Rejected, match="outside the scan root"):
        scan([tmp_path / "b"], root=tmp_path / "a")


def test_default_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text(SHELL)
    monkeypatch.chdir(tmp_path)
    assert scan(["pkg"]).findings[0].path == "pkg/a.py"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert scan([tmp_path / "pkg"]).findings[0].path == "a.py"


def test_invalid_fail_on_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(Rejected):
        scan([tmp_path], root=tmp_path, fail_on="severe")  # type: ignore[arg-type]


def test_exit_codes(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import hashlib\nh = hashlib.md5(b'')\n")  # one medium finding
    report = scan_dir(tmp_path)
    assert exit_code(report) == 0  # default fail_on high
    assert exit_code(report, "medium") == 1 and exit_code(report, "low") == 1
    assert exit_code(report, "none") == 0
    assert exit_code(scan_dir(tmp_path, fail_on="medium")) == 1
    (tmp_path / "a.py").write_text("x = 1\n")
    assert exit_code(scan_dir(tmp_path), "low") == 0


# ----- diff mode


def test_parse_diff() -> None:
    text = (
        "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,0 +2,3 @@\n+a\n@@ -9 +12 @@\n"
        "--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n"
        '+++ "b/sp\\"ace.py"\n@@ -0,0 +1 @@\n'
    )
    assert parse_diff(text) == {"x.py": frozenset({2, 3, 4, 12}), 'sp"ace.py': frozenset({1})}


def test_diff_reports_only_changed_lines(repo: Path, git: Callable[..., str]) -> None:
    (repo / "old.py").write_text(SHELL)
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    (repo / "old.py").write_text("import os\ndef f(n):\n    os.system(n)\n" + SHELL)
    (repo / "new.py").write_text("import pickle\ndef f(b):\n    return pickle.loads(b)\n")
    report = scan([repo], root=repo, diff_base="HEAD")
    assert sorted((f.path, f.rule_id) for f in report.findings) == [
        ("new.py", "py.deserialize.pickle"),
        ("old.py", "py.os.system"),
    ]
    assert report.diff_base == "HEAD"
    assert len(scan([repo], root=repo).findings) == 3


def test_diff_outside_git_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(Rejected, match="not inside a git work tree"):
        scan([tmp_path], root=tmp_path, diff_base="main")


def test_diff_with_unknown_or_option_like_ref_is_rejected(repo: Path, git: Callable[..., str]) -> None:
    (repo / "a.py").write_text("x = 1\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    with pytest.raises(Rejected, match="unknown git ref"):
        scan([repo], root=repo, diff_base="no-such-branch")
    with pytest.raises(Rejected, match="needs a git ref"):
        scan([repo], root=repo, diff_base="--output=/tmp/x")
