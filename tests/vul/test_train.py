# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import random
from collections import Counter
from pathlib import Path

import pytest

from kestrixvul import train
from kestrixvul.train import (
    DataError,
    HeldOutSplitError,
    assemble,
    context_window,
    cwe_target,
    cwe_vocab,
    make_batches,
    normalize_cwe,
    read_negatives,
    read_records,
    subsample,
)

from .conftest import build

ROOT = Path(__file__).resolve().parents[2]


def _roles(examples):
    return Counter(e["role"] for e in examples)


def test_train_examples_are_vulnerable_patched_and_negatives_at_the_ratio(vul_root):
    ex = assemble(vul_root, "train", neg_ratio=2.0)
    assert _roles(ex) == {"vulnerable": 4, "patched": 3, "negative": 8}
    assert {e["label"] for e in ex if e["role"] == "vulnerable"} == {1}
    assert {e["label"] for e in ex if e["role"] != "vulnerable"} == {0}
    vuln = next(e for e in ex if e["id"] == "tr1:v")
    assert vuln["cwes"] == ["CWE-78"] and vuln["code"].startswith("def run0")
    assert next(e for e in ex if e["id"] == "tr1:p")["cwes"] == []


def test_negative_ratio_none_keeps_all_and_zero_keeps_none(vul_root):
    assert _roles(assemble(vul_root, "train", neg_ratio=None))["negative"] == 20
    assert _roles(assemble(vul_root, "train", neg_ratio=0))["negative"] == 0
    assert _roles(assemble(vul_root, "train", neg_ratio=100.0))["negative"] == 20


def test_negative_sample_is_seeded_and_stable(vul_root):
    first = {e["id"] for e in assemble(vul_root, "train", neg_ratio=1.0)}
    assert first == {e["id"] for e in assemble(vul_root, "train", neg_ratio=1.0)}
    others = [{e["id"] for e in assemble(vul_root, "train", neg_ratio=1.0, seed=f"s{i}")} for i in range(5)]
    assert any(o != first for o in others)


def test_filtered_view_drops_the_excluded_records(vul_root):
    ids = {e["id"] for e in assemble(vul_root, "train", neg_ratio=0, view="filtered")}
    assert "tr2:v" not in ids and "tr2:p" not in ids and "tr1:v" in ids
    with pytest.raises(DataError):
        assemble(vul_root, "train", neg_ratio=0, view="nope")


def test_permissive_pool_uses_record_and_negative_licenses(vul_root):
    ex = assemble(vul_root, "train", neg_ratio=None, permissive_only=True)
    assert {e["license_class"] for e in ex} == {"permissive"}
    assert not any(e["record_id"] == "tr3" for e in ex)
    assert {e["repo"] for e in ex if e["role"] == "negative"} == {"github.com/o/a"}


def test_training_code_refuses_held_out_splits(vul_root):
    for split in ("test", "test_extension"):
        with pytest.raises(HeldOutSplitError):
            assemble(vul_root, split, neg_ratio=None)
    with pytest.raises(HeldOutSplitError):
        read_records(vul_root, ("train", "test"))
    with pytest.raises(HeldOutSplitError):
        read_negatives(vul_root, ("test_extension",))


def test_no_held_out_row_reaches_any_trainable_assembly(vul_root):
    seen = set()
    for split in ("train", "dev"):
        for view in ("full", "filtered"):
            seen |= {e["record_id"] for e in assemble(vul_root, split, neg_ratio=None, view=view)}
    assert not {r for r in seen if r.startswith(("te", "tx", "neg-test"))}


def test_manifest_falls_back_to_v1_and_fails_clearly_without_one(tmp_path):
    v1 = build(tmp_path / "v1", v2=False)
    assert train.manifest_path(v1).name == "split.jsonl"
    empty = tmp_path / "empty"
    (empty / "work").mkdir(parents=True)
    with pytest.raises(DataError, match=r"split-v2\.jsonl"):
        assemble(empty, "train", neg_ratio=0)


def test_missing_negatives_fail_clearly(vul_root):
    (vul_root / "work" / "negatives.jsonl").unlink()
    with pytest.raises(DataError, match=r"negatives\.jsonl"):
        assemble(vul_root, "train", neg_ratio=1.0)
    assert assemble(vul_root, "train", neg_ratio=0)


def test_normalize_cwe():
    assert normalize_cwe("CWE-078") == "CWE-78"
    assert normalize_cwe("cwe-79") == "CWE-79"
    assert normalize_cwe("NVD-CWE-Other") is None
    assert normalize_cwe("NVD-CWE-noinfo") is None


def test_cwe_vocab_and_targets():
    ex = [
        {"label": 1, "cwes": ["CWE-79"]},
        {"label": 1, "cwes": ["CWE-79"]},
        {"label": 1, "cwes": ["CWE-89"]},
        {"label": 1, "cwes": ["CWE-22"]},
        {"label": 0, "cwes": []},
    ]
    vocab = cwe_vocab(ex, 2)
    assert vocab == ["CWE-79", "CWE-22", "other"]
    assert cwe_target(ex[0], vocab) == 0
    assert cwe_target(ex[2], vocab) == 2  # out of vocabulary -> other
    assert cwe_target(ex[4], vocab) == -1


def test_make_batches_covers_every_index_once():
    lengths = [random.Random(1).randint(1, 100) for _ in range(103)]
    batches = make_batches(lengths, 4, random.Random(7), chunk=3)
    flat = [i for b in batches for i in b]
    assert sorted(flat) == list(range(103))
    assert all(len(b) <= 4 for b in batches)
    assert batches == make_batches(lengths, 4, random.Random(7), chunk=3)


def test_context_window_is_cut_around_the_function():
    text = "A" * 100 + "def f():\n    pass\n" + "B" * 100
    before, after = context_window(text, "def f():\n    pass\n", 40)
    assert before == "A" * 20 and after == "B" * 20
    assert context_window(text, "missing", 40) == ("", "")


def test_prompt_includes_context_only_when_present():
    ex = {"language": "python", "path": "p.py", "function": "f", "code": "def f():\n    pass", "file_text": None}
    assert "context" not in train.prompt(ex, ex["code"], 100)
    ex["file_text"] = "import os\n" + ex["code"] + "\nx = 1\n"
    text = train.prompt(ex, ex["code"], 100)
    assert "import os" in text and "x = 1" in text and '"vulnerable"' in text


def test_subsample_is_deterministic():
    ex = [{"id": f"e{i}"} for i in range(50)]
    assert subsample(ex, 10) == subsample(ex, 10)
    assert len(subsample(ex, 10)) == 10 and subsample(ex, 0) == ex


def test_train_cli_fails_clearly_without_the_model_snapshot(vul_root, capsys):
    assert train.main(["teacher", "--root", str(vul_root), "--max-steps", "1"]) == 1
    assert "model snapshot" in capsys.readouterr().err


def test_new_run_dir_refuses_to_overwrite_a_run(vul_root):
    run = train.new_run_dir(vul_root, "r1")
    (run / "run.json").write_text("{}")
    with pytest.raises(DataError):
        train.new_run_dir(vul_root, "r1")


def test_student_revision_matches_the_fetch_script():
    script = (ROOT / "research/hpc/vul/fetch_vul_student_model.sh").read_text()
    assert f"{train.STUDENT_REPO}@{train.STUDENT_REVISION}" in script
    assert f"Qwen2.5-Coder-7B-Instruct@{train.TEACHER_REVISION}" in (ROOT / "research/hpc/detect/m1.sbatch").read_text()
