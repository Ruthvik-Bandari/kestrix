# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

import pytest

from kestrixvul import extend
from kestrixvul.extend import assign_new, content_sha256, frozen_test, run
from kestrixvul.split import SplitError, ids_sha256


def _r(rid: str, repo: str, published: str | None, advisories: tuple[str, ...] = (), **kw: object) -> dict:
    return {
        "id": rid,
        "source": "ghsa",
        "repo": repo,
        "repos": [repo],
        "advisory_ids": list(advisories),
        "published": published,
        "language": "python",
        "label_rule": "onefunc",
        "patched": "x",
        "vulnerable_sha256": f"v-{rid}",
        "patched_sha256": f"p-{rid}",
    } | kw


FROZEN = [
    _r("tr1", "github.com/o/train", "2020-01-01", ("CVE-2020-1",), split="train", source="cvefixes"),
    _r("te1", "github.com/o/test", "2025-01-01", ("CVE-2025-1",), split="test", source="morefixes"),
    _r("te2", "github.com/o/test2", "2025-02-01", ("CVE-2025-2",), split="test", source="morefixes"),
]


def _manifest(records: list[dict]) -> dict:
    test_ids = sorted(r["id"] for r in records if r["split"] == "test")
    return {"manifest_sha256": "pinned", "splits": {"test": {"ids": test_ids, "ids_sha256": ids_sha256(test_ids)}}}


def _root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, new: list[dict], frozen: list[dict] = FROZEN) -> Path:
    monkeypatch.setattr(extend, "FROZEN_MANIFEST_SHA256", "pinned")
    (tmp_path / "work").mkdir()
    (tmp_path / "reports").mkdir()
    (tmp_path / "work" / "split.jsonl").write_text("".join(json.dumps(r) + "\n" for r in frozen))
    (tmp_path / "reports" / "split-manifest.json").write_text(json.dumps(_manifest(FROZEN)))
    (tmp_path / "work" / "ghsa_deduped.jsonl").write_text("".join(json.dumps(r) + "\n" for r in new))
    return tmp_path


def test_new_records_never_enter_the_frozen_test_split():
    new = [
        _r("n-train", "github.com/o/train", "2021-01-01"),  # joins the train group
        _r("n-late", "github.com/o/train", "2025-05-01"),  # post-cutoff in a train group: dropped
        _r("n-test", "github.com/o/test", "2025-03-01"),  # frozen-test project: held-out extension
        _r("n-old-test", "github.com/o/test", "2023-01-01"),  # pre-cutoff in a held-out group: dropped
        _r("n-fresh", "github.com/f/new", "2025-06-01"),  # unseen project, post-cutoff
    ]
    out, dropped = assign_new(FROZEN, new)
    assert out == {"n-train": "train", "n-test": "test_extension", "n-fresh": "test_extension"}
    assert "test" not in out.values()
    assert dropped == {
        "post_cutoff_record_in_pre_cutoff_group": 1,
        "pre_cutoff_record_in_held_out_group": 1,
    }
    bridge = _r("n-bridge", "github.com/x/y", "2021-01-01", ("CVE-2020-1", "CVE-2025-2"))  # links train and test
    out, dropped = assign_new(FROZEN, [bridge, _r("n-train", "github.com/o/train", "2021-01-01")])
    assert out == {} and dropped == {"bridges_two_frozen_splits": 2}  # the whole linked group is dropped


def test_run_keeps_frozen_test_hashes_and_lists_negatives_apart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _root(tmp_path, monkeypatch, [_r("n1", "github.com/o/train", "2021-01-01")])
    neg = {"id": "neg1", "split": "test", "language": "python"}
    (root / "work" / "negatives.jsonl").write_text(json.dumps(neg) + "\n")
    manifest = run(root)
    assert manifest["frozen_test"]["unchanged"] is True
    assert manifest["frozen_test"]["before"]["ids_sha256"] == _manifest(FROZEN)["splits"]["test"]["ids_sha256"]
    assert manifest["splits"]["test"]["ids"] == ["te1", "te2"]
    assert manifest["splits"]["train"]["ids"] == ["n1", "tr1"]
    assert manifest["negatives"]["test"]["ids"] == ["neg1"]
    assert manifest["prevalence"]["test"]["negatives_per_vulnerable"] == 0.5
    assert '"vulnerable": "' not in json.dumps(manifest) and '"patched"' not in json.dumps(manifest)


def test_run_refuses_a_changed_frozen_test_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tampered = [dict(r) for r in FROZEN]
    tampered[1]["split"] = "train"  # a frozen test record moved out of test
    root = _root(tmp_path, monkeypatch, [], frozen=tampered)
    with pytest.raises(SplitError):
        run(root)


def test_frozen_test_requires_the_pinned_manifest():
    with pytest.raises(SplitError):
        frozen_test(FROZEN, _manifest(FROZEN))  # "pinned" is not the real frozen hash here


def test_content_hash_covers_code_hashes():
    changed = [dict(FROZEN[1], vulnerable_sha256="other")]
    assert content_sha256([FROZEN[1]]) != content_sha256(changed)


def test_audit_filter_lists_excluded_and_confirmed_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _root(tmp_path, monkeypatch, [_r("n1", "github.com/o/train", "2021-01-01", label_rule="nvd_name")])
    (root / "work" / "audit_verdicts.jsonl").write_text(
        json.dumps({"id": "tr1", "final": "vulnerable", "final_by": "ai-consensus"}) + "\n"
    )
    (root / "reports" / "audit.json").write_text(json.dumps({"filter": {"dropped_strata": ["ghsa/python/nvd_name"]}}))
    manifest = run(root)
    assert manifest["filters"]["excluded_ids"]["train"] == ["n1"]
    assert manifest["filters"]["audit_confirmed_ids"]["train"] == ["tr1"]
    assert manifest["ai_audit"]["records"]["tr1"] == {
        "ai_audited": True,
        "verdict": "vulnerable",
        "final_by": "ai-consensus",
    }
