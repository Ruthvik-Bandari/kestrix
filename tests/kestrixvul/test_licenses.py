# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import subprocess
from pathlib import Path

import pytest

from kestrixvul import licenses
from kestrixvul.licenses import classify, export, fetch_table, import_table, read_table


@pytest.mark.parametrize(
    ("spdx", "expected"),
    [
        ("MIT", "permissive"),
        ("BSD-3-Clause", "permissive"),
        ("Apache-2.0", "permissive"),
        ("PSF-2.0", "permissive"),
        ("MPL-2.0", "weak_copyleft"),
        ("LGPL-2.1", "weak_copyleft"),
        ("GPL-3.0", "copyleft"),
        ("AGPL-3.0", "copyleft"),
        ("NOASSERTION", "other"),
        ("CC0-1.0", "other"),
        ("NONE", "none"),
        ("NOT_FOUND", "unknown"),
        (None, "unknown"),
    ],
)
def test_classify(spdx: str | None, expected: str):
    assert classify(spdx) == expected


def _pool(root: Path) -> None:
    (root / "work").mkdir()
    rows = [
        {"repo": "github.com/o/mit", "language": "python"},
        {"repo": "github.com/o/gpl", "language": "javascript"},
        {"repo": "gitlab.com/x/y", "language": "python"},
    ]
    (root / "work" / "deduped.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_export_lists_github_repositories_only(tmp_path: Path):
    _pool(tmp_path)
    assert export(tmp_path) == 2
    assert (tmp_path / "licenses" / "repos.txt").read_text() == "o/gpl\no/mit\n"
    assert (tmp_path / "licenses" / "non_github.txt").read_text() == "gitlab.com/x/y\n"


def test_fetch_uses_gh_and_caches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[str, ...]] = []

    def fake_gh(*args: str) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[1] == "rate_limit":
            return subprocess.CompletedProcess(args, 0, "5000\t0\n", "")
        if args[1] == "repos/o/gone":
            return subprocess.CompletedProcess(args, 1, "", "gh: Not Found (HTTP 404)")
        return subprocess.CompletedProcess(args, 0, "MIT\n" if args[1] == "repos/o/mit" else "NONE\n", "")

    monkeypatch.setattr(licenses, "_gh", fake_gh)
    monkeypatch.setattr(licenses, "THROTTLE_S", 0)
    repos = tmp_path / "repos.txt"
    repos.write_text("o/mit\no/bare\no/gone\n")
    out = tmp_path / "licenses.csv"
    assert fetch_table(repos, out) == {"permissive": 1, "none": 1, "unknown": 1}
    assert out.read_text().splitlines()[1] == "o/mit,MIT,permissive"
    calls.clear()
    fetch_table(repos, out)
    assert not [c for c in calls if c[1].startswith("repos/")]  # every answer came from the cache


def test_fetch_refuses_malformed_names(tmp_path: Path):
    repos = tmp_path / "repos.txt"
    repos.write_text("o/p;rm -rf\n")
    with pytest.raises(ValueError, match="malformed"):
        fetch_table(repos, tmp_path / "out.csv")


def test_import_validates_and_summarizes(tmp_path: Path):
    _pool(tmp_path)
    export(tmp_path)
    table = tmp_path / "fetched.csv"
    table.write_text("repo,spdx_id,license_class\no/mit,MIT,permissive\no/gpl,NOT_FOUND,unknown\n")
    assert import_table(tmp_path, table)["repositories_by_class"]["unknown"] == 1
    table.write_text("repo,spdx_id,license_class\no/mit,MIT,permissive\no/gpl,GPL-3.0,copyleft\n")
    summary = import_table(tmp_path, table)
    assert summary["repositories_by_class"]["permissive"] == 1
    assert summary["shipped_weight_pool_records"] == {"javascript": 0, "python": 1}
    assert summary["records_by_language_and_class"]["python"]["unknown"] == 1
    table.write_text("repo,spdx_id\no/mit,MIT\n")
    with pytest.raises(ValueError, match="misses"):
        import_table(tmp_path, table)
    table.write_text("repo,spdx_id\no/mit,MIT\nbad name,MIT\n")
    with pytest.raises(ValueError, match="malformed"):
        read_table(table)
