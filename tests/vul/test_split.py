# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

import pytest

from kestrixvul.split import SplitError, assign, check_disjoint, group_keys, ids_sha256, run


def _r(rid: str, repo: str, published: str | None, advisories: tuple[str, ...] = (), source: str = "cvefixes") -> dict:
    return {
        "id": rid,
        "source": source,
        "repo": repo,
        "repos": [repo],
        "advisory_ids": list(advisories),
        "published": published,
        "language": "python",
        "patched": "x",
    }


def test_shared_advisories_join_repositories_into_one_group():
    records = [_r("a", "github.com/o/a", "2020-01-01", ("CVE-1",)), _r("b", "github.com/o/b", "2021-01-01", ("CVE-1",))]
    keys = group_keys(records)
    assert keys["a"] == keys["b"]


def test_temporal_project_disjoint_assignment():
    records = [
        _r("new1", "github.com/n/new", "2025-01-02", ("CVE-2025-1",)),
        _r("new2", "github.com/n/new", "2024-10-01", ("CVE-2024-9",)),
        _r("old1", "github.com/o/old", "2019-05-05", ("CVE-2019-1",)),
        _r("old2", "github.com/o/old", "2025-03-03", ("CVE-2025-2",)),  # post-cutoff CVE of a pre-cutoff project
        _r("nodate", "github.com/o/old", None),
        _r("sv", "github.com/s/sven", None, source="sven"),
    ]
    assignment, dropped = assign(records)
    assert assignment["new1"] == assignment["new2"] == "test"
    assert assignment["old1"] in {"train", "dev"}
    assert "old2" not in assignment and "nodate" not in assignment
    assert assignment["sv"] == "dev"
    assert dropped == {"post_cutoff_record_in_pre_cutoff_group": 1, "record_without_date": 1}
    check_disjoint(records, assignment)


def test_assignment_is_deterministic_and_seeded():
    records = [_r(f"r{i}", f"github.com/o/p{i}", "2020-01-01", (f"CVE-{i}",)) for i in range(300)]
    first, _ = assign(records)
    assert first == assign(records)[0]
    share = sum(1 for s in first.values() if s == "dev") / len(first)
    assert 0.04 < share < 0.18
    assert first != assign(records, seed="other")[0]


def test_check_disjoint_rejects_a_project_in_two_splits():
    records = [_r("a", "github.com/o/p", "2020-01-01"), _r("b", "github.com/o/p", "2020-01-01")]
    with pytest.raises(SplitError):
        check_disjoint(records, {"a": "train", "b": "test"})


def test_run_writes_an_ids_only_manifest(tmp_path: Path):
    (tmp_path / "work").mkdir()
    records = [_r("x1", "github.com/o/p", "2020-01-01"), _r("x2", "github.com/n/q", "2025-01-01")]
    (tmp_path / "work" / "deduped.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    manifest = run(tmp_path)
    assert manifest["splits"]["test"]["ids"] == ["x2"]
    assert manifest["splits"]["test"]["ids_sha256"] == ids_sha256(["x2"])
    assert manifest["evaluated"] is False and manifest["licenses_applied"] is False
    assert "vulnerable" not in json.dumps(manifest)
    assert (tmp_path / "work" / "split.jsonl").stat().st_mode & 0o777 == 0o600
