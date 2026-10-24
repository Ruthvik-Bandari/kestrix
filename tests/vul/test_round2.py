# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import random
from pathlib import Path

import pytest

from kestrixvul import evaluate as ev
from kestrixvul import round2
from kestrixvul.round2 import (
    Round2Error,
    assign_round2,
    assign_tiers,
    choose,
    decide,
    freeze,
    in_val_slice,
    meaningful,
)
from kestrixvul.train import (
    make_unit_batches,
    pair_higher,
    pair_index,
    pairs_in_batch,
    repo_weights,
    require_trainable,
)


def _r(rid: str, repo: str, published: str, advisories: tuple[str, ...] = (), **kw: object) -> dict:
    return {
        "id": rid,
        "source": "ghsa",
        "repo": f"github.com/{repo}",
        "repos": [f"github.com/{repo}"],
        "advisory_ids": list(advisories) or [f"GHSA-{rid}"],
        "published": published,
        "language": "python",
        "label_rule": "onefunc",
        "vulnerable": "def f():\n    pass\n",
        "patched": "def f():\n    return 1\n",
        "vulnerable_sha256": f"v{rid}",
        "patched_sha256": f"p{rid}",
    } | kw


def test_tiers_follow_the_cutoff_and_drop_groups_linked_to_c6():
    recs = [
        _r("a1", "o/new", "2025-03-01"),
        _r("a2", "o/new", "2023-01-01"),  # pre-cutoff record in a tier A group: dropped
        _r("b1", "o/old", "2022-01-01"),
        _r("c1", "o/known", "2025-05-01"),  # repository known to C6
        _r("c2", "o/viaadv", "2025-05-01", ("CVE-2025-9",)),  # shares a CVE with C6
        _r("n1", "o/nodate", ""),
    ]
    excluded = {"repo:github.com/o/known", "adv:CVE-2025-9"}
    a, b, dropped = assign_tiers(recs, excluded)
    assert a == {"a1": "A"} and b == {"b1": "B"}
    assert dropped["pre_cutoff_record_in_tier_a_group"] == 1
    assert dropped["group_shares_a_node_with_c6"] == 2
    assert dropped["record_without_date"] == 1


def test_choose_applies_the_written_rule(monkeypatch):
    monkeypatch.setattr(round2, "MIN_RECORDS", 3)
    monkeypatch.setattr(round2, "MIN_PROJECTS", 2)
    a = [_r(f"a{i}", f"o/a{i}", "2025-01-01") for i in range(3)]
    b = [_r(f"b{i}", f"o/b{i}", "2022-01-01") for i in range(2)]
    assert meaningful(round2.summarize(a))
    assert choose(a, b)[0] == "A"
    assert choose(a[:2], b)[0] == "A+B"
    assert choose(a[:1], b[:1]) == ("none", [])
    one_project = [_r(f"p{i}", "o/same", "2025-01-01") for i in range(5)]
    assert choose(one_project, [])[0] == "none"


def test_freeze_writes_once_and_refuses_a_second_time(tmp_path: Path):
    rows = [_r("a1", "o/new", "2025-03-01") | {"tier": "A", "split": "test2"}]
    freeze(tmp_path, rows, [], {"rule_outcome": "A"})
    claim = json.loads((tmp_path / "reports" / round2.FROZEN_NAME).read_text())
    assert claim["rule_outcome"] == "A" and "pair accuracy" in claim["ship_rule"]
    assert (tmp_path / "work" / "test2.jsonl").is_file()
    with pytest.raises(Round2Error):
        freeze(tmp_path, rows, [], {"rule_outcome": "A"})


def test_validation_split_is_project_disjoint_and_seeded():
    recs = [_r(f"r{i}", f"o/p{i % 40}", "2020-01-01") for i in range(200)]
    recs.append(_r("bridge", "o/p1", "2020-01-01", ("CVE-1",)))
    recs.append(_r("bridge2", "o/p2", "2020-01-01", ("CVE-1",)))  # a CVE joins p1 and p2
    out = assign_round2(recs)
    by_repo: dict[str, set[str]] = {}
    for r in recs:
        by_repo.setdefault(r["repo"], set()).add(out[r["id"]])
    assert all(len(v) == 1 for v in by_repo.values())
    assert out["bridge"] == out["bridge2"]
    assert {"train", "dev"} == set(out.values())
    assert out == assign_round2(recs)
    assert in_val_slice("g", percent=100) and not in_val_slice("g", percent=0)


def test_split_refuses_before_the_freeze(tmp_path: Path):
    (tmp_path / "work").mkdir()
    vul = tmp_path / "vul"
    (vul / "work").mkdir(parents=True)
    (vul / "work" / "split-v2.jsonl").write_text("")
    with pytest.raises(Round2Error, match="not frozen"):
        round2.build_split(tmp_path, vul)


def test_repo_weights_damp_large_projects_and_average_one():
    ex = [{"repo": "big", "role": "vulnerable"}] * 9 + [{"repo": "small", "role": "vulnerable"}]
    ex += [{"repo": "small", "role": "negative"}]
    w = repo_weights(ex, 0.5)
    assert sum(w) / len(w) == pytest.approx(1.0)
    assert w[-1] > w[0] and w[9] > w[0]
    assert repo_weights(ex, 0.0) == [1.0] * len(ex)


def _pair_examples():
    ex = []
    for i in range(6):
        ex.append({"record_id": f"r{i}", "role": "vulnerable"})
        ex.append({"record_id": f"r{i}", "role": "patched"})
    ex.append({"record_id": "lonely", "role": "vulnerable"})
    ex.append({"record_id": "n", "role": "negative"})
    return ex


def test_unit_batches_keep_pairs_together_and_cover_every_example_once():
    ex = _pair_examples()
    pairs = pair_index(ex)
    assert len(pairs) == 6
    batches = make_unit_batches([len(str(i)) for i in range(len(ex))], pairs, 4, random.Random(1), chunk=2)
    flat = sorted(i for b in batches for i in b)
    assert flat == list(range(len(ex)))
    assert all(len(b) <= 4 for b in batches)
    assert sum(len(pairs_in_batch(b, pairs)) for b in batches) == 6


def test_pair_higher_counts_ties_as_half():
    ex = [
        {"record_id": "a", "role": "vulnerable"},
        {"record_id": "a", "role": "patched"},
        {"record_id": "b", "role": "vulnerable"},
        {"record_id": "b", "role": "patched"},
    ]
    scored = [{"logit": 2.0}, {"logit": 1.0}, {"logit": 0.0}, {"logit": 0.0}]
    assert pair_higher(scored, ex) == pytest.approx(0.75)
    assert pair_higher([{"logit": 1.0}], [{"record_id": "x", "role": "negative"}]) is None


def _report(cand_ci, pair):
    def system(ci, pairwise=None):
        return {"pr_auc": sum(ci) / 2, "ci95": {"pr_auc": ci}, "pairwise": pairwise}

    systems = {
        "rules": system([0.04, 0.08]),
        "bow": system([0.10, 0.16]),
        "ensemble": system(cand_ci, {"correct": pair}),
    }
    return {"splits": {"test2": {"views": {"full": {"systems": systems}}}}}


@pytest.mark.parametrize(
    ("ci", "pair", "ship"),
    [([0.20, 0.30], 0.30, True), ([0.12, 0.30], 0.30, False), ([0.20, 0.30], 0.20, False), ([0.05, 0.3], 0.5, False)],
)
def test_ship_rule(ci, pair, ship):
    verdict = decide(_report(ci, pair), "ensemble")
    assert verdict["ship"] is ship
    assert verdict["pair_min"] == 0.25


def test_test2_is_never_a_training_split():
    with pytest.raises(Exception, match="never reads"):
        require_trainable(("test2",))


def test_ensemble_averages_logits_and_needs_two_members():
    s = [
        ev.System(f"teacher:{n}", "probability", {"dev": [ev.Scored(v), ev.Scored(-v)]})
        for n, v in (("a", 1.0), ("b", 3.0))
    ]
    out = ev.ensemble_system(s, ["teacher:a", "teacher:b"])
    assert [x.score for x in out.scored["dev"]] == [2.0, -2.0]
    with pytest.raises(ev.EvalError):
        ev.ensemble_system(s, ["teacher:a"])


def test_read_test2_needs_lock_and_freeze(vul_root: Path):
    claim = ev.claim_locked(vul_root, {"name": "t"}, ev.LOCK_NAME_TEST2)
    with pytest.raises(ev.LockedEvalError, match="not frozen"):
        ev.read_test2(vul_root, claim)
    rows = [_r("a1", "o/new", "2025-03-01") | {"tier": "A", "split": "test2", "cwes": []}]
    freeze(vul_root, rows, [], {"rule_outcome": "A"})
    out = ev.read_test2(vul_root, claim)
    assert sorted(e["role"] for e in out["test2"]) == ["patched", "vulnerable"]
    with pytest.raises(ev.LockedEvalError):
        ev.claim_locked(vul_root, {"name": "again"}, ev.LOCK_NAME_TEST2)


def test_carve_out_is_project_disjoint_and_only_from_dev():
    recs = [_r(f"d{i}", f"o/p{i % 30}", "2020-01-01", split="dev") for i in range(120)]
    recs += [_r(f"t{i}", f"o/q{i}", "2020-01-01", split="train") for i in range(20)]
    carve = round2.carve_dev(recs)
    ids = {r["id"] for r in carve}
    assert ids and all(i.startswith("d") for i in ids)
    assert {r["split"] for r in carve} == {"test2"} and {r["tier"] for r in carve} == {"dev_carve"}
    kept_repos = {r["repo"] for r in carve}
    rest_repos = {r["repo"] for r in recs if r["split"] == "dev" and r["id"] not in ids}
    assert not kept_repos & rest_repos
    assert 0 < len(kept_repos) < 30
