# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json

import pytest

from kestrixvul import evaluate as ev
from kestrixvul.evaluate import (
    BagOfWords,
    LockedEvalError,
    at_k_per_group,
    average_precision,
    best_threshold,
    bootstrap_ci,
    claim_locked,
    confusion_at,
    cwe_topk,
    ece,
    fnr_at_fpr,
    pairwise,
    platt_fit,
    read_held_out,
    sigmoid,
)

S5 = [0.9, 0.8, 0.7, 0.6, 0.5]
Y5 = [1, 0, 1, 0, 1]


def test_average_precision_by_hand():
    assert average_precision([0.9, 0.8, 0.7, 0.6], [1, 0, 1, 0]) == pytest.approx(0.5 + 0.5 * 2 / 3)
    assert average_precision([0.5, 0.5], [1, 0]) == pytest.approx(0.5)  # a tie counts as one threshold
    assert average_precision([0.1, 0.2], [0, 0]) is None


def test_confusion_and_best_f1_threshold_by_hand():
    c = confusion_at(S5, Y5, 0.7)
    assert (c["tp"], c["fp"], c["fn"]) == (2, 1, 1)
    assert c["precision"] == pytest.approx(2 / 3) and c["f1"] == pytest.approx(2 / 3)
    # F1 per threshold: 0.9 -> 0.5, 0.8 -> 0.4, 0.7 -> 0.667, 0.6 -> 0.571, 0.5 -> 0.75
    assert best_threshold(S5, Y5) == 0.5
    assert best_threshold([0.9, 0.8, 0.7, 0.6], [1, 0, 0, 1]) == 0.9  # 0.9 and 0.6 tie at F1 2/3: the higher one
    assert confusion_at(S5, Y5, float("inf"))["precision"] is None


def test_vd_s_miss_rate_at_capped_fpr_by_hand():
    assert fnr_at_fpr(S5, Y5, 0.0) == {"fnr": pytest.approx(2 / 3), "fpr": 0.0, "threshold": 0.9}
    assert fnr_at_fpr(S5, Y5, 0.5) == {"fnr": pytest.approx(1 / 3), "fpr": 0.5, "threshold": 0.7}
    assert fnr_at_fpr(S5, Y5, 1.0)["fnr"] == 0.0
    assert fnr_at_fpr([0.9, 0.1], [0, 1], 0.0) == {"fnr": 1.0, "fpr": 0.0, "threshold": None}
    assert fnr_at_fpr([0.1], [1], 0.01) is None


def test_precision_and_recall_at_k_per_repository_by_hand():
    scores = [0.9, 0.8, 0.1, 0.5, 0.3]
    labels = [0, 1, 0, 1, 0]
    groups = ["a", "a", "a", "b", "c"]  # c has no positive and is left out
    out = at_k_per_group(scores, labels, groups, (1, 5))
    assert out["1"] == {"precision": 0.5, "recall": 0.5, "repos": 2}
    assert out["5"]["precision"] == pytest.approx((1 / 3 + 1) / 2) and out["5"]["recall"] == 1.0


def test_pairwise_outcomes_by_hand():
    out = pairwise([(0.9, 0.1), (0.9, 0.8), (0.2, 0.1), (0.3, 0.6)], 0.5)
    assert {k: out[k] for k in ("correct", "both_vulnerable", "both_benign", "reversed")} == dict.fromkeys(
        ("correct", "both_vulnerable", "both_benign", "reversed"), 0.25
    )
    assert out["vulnerable_scores_higher"] == 0.75
    assert pairwise([(0.5, 0.5)], 0.9)["vulnerable_scores_higher"] == 0.5
    assert pairwise([], 0.5) is None


def test_cwe_top_k_by_hand():
    rows = [({"CWE-79"}, ("CWE-79", "CWE-89")), ({"CWE-22"}, ("CWE-79", "CWE-89", "CWE-22")), ({"CWE-78"}, ())]
    out = cwe_topk(rows)
    assert out == {"n": 3, "top1": pytest.approx(1 / 3), "top3": pytest.approx(2 / 3)}


def test_ece_by_hand():
    # bin 1: mean p 0.1, mean y 0.5 -> 0.4 * 2/4; bin 9: 0.9 vs 1.0 -> 0.1 * 2/4
    assert ece([0.1, 0.1, 0.9, 0.9], [0, 1, 1, 1]) == pytest.approx(0.25)
    assert ece([1.0], [1]) == 0.0


def test_platt_fit_is_flat_for_uninformative_scores_and_increasing_for_informative_ones():
    a, _ = platt_fit([0.0, 1.0, 0.0, 1.0], [0, 0, 1, 1])
    assert abs(a) < 1e-6
    a, _ = platt_fit([-2.0, -1.0, 1.0, 2.0, 0.5, -0.5], [0, 0, 1, 1, 0, 1])
    assert a > 0


def test_sigmoid_is_stable():
    assert sigmoid(1000.0) == 1.0 and sigmoid(-1000.0) == 0.0 and sigmoid(0.0) == 0.5


def test_bootstrap_is_deterministic_and_resamples_whole_repositories():
    groups = ["a", "a", "b"]
    seen = []

    def stat(idx):
        seen.append(len(idx))
        return float(len(idx))

    first = bootstrap_ci(groups, stat, 200, seed=3)
    assert first == bootstrap_ci(groups, stat, 200, seed=3)
    assert set(seen) <= {2, 3, 4}  # two draws of whole groups of size 2 or 1
    labels = [1, 0, 1, 0, 1, 0, 1, 1]
    scores = [0.9, 0.2, 0.6, 0.7, 0.8, 0.1, 0.4, 0.3]
    groups = ["a", "a", "b", "b", "c", "c", "d", "d"]

    def ap(idx):
        return average_precision([scores[i] for i in idx], [labels[i] for i in idx])

    assert bootstrap_ci(groups, ap, 100, seed=1) == bootstrap_ci(groups, ap, 100, seed=1)

    def draws(seed):
        drawn = []
        bootstrap_ci(groups, lambda idx: drawn.append(tuple(idx)) or 0.0, 20, seed)
        return drawn

    assert draws(1) == draws(1) and draws(1) != draws(2)
    assert bootstrap_ci(groups, ap, 0, seed=1) is None


def test_bag_of_words_learns_a_separable_toy():
    codes = ["os.system(x)"] * 10 + ["return x + 1"] * 10
    labels = [1] * 10 + [0] * 10
    bow = BagOfWords(dim=1024).fit(codes, labels)
    assert bow.score("os.system(y)") > 0 > bow.score("return y + 1")


def test_rule_baseline_flags_a_finding_inside_the_function():
    code = "    def run(self, cmd):\n        import subprocess\n        return subprocess.call(cmd, shell=True)\n"
    ex = [
        {"path": "a/b.py", "language": "python", "code": code},
        {"path": "a/c.py", "language": "python", "code": "def f(x):\n    return x\n"},
    ]
    rows = ev.rule_system({"dev": ex}).scored["dev"]
    assert rows[0].score >= 1 and rows[0].cwes[0] == "CWE-78"
    assert rows[1].score == 0


def test_locked_claim_is_exclusive(vul_root):
    claim = claim_locked(vul_root, {"name": "first"})
    assert set(read_held_out(vul_root, claim)) == {"test", "test_extension"}
    with pytest.raises(LockedEvalError, match="first"):
        claim_locked(vul_root, {"name": "second"})


def test_held_out_reader_needs_a_claim(vul_root):
    with pytest.raises(LockedEvalError):
        read_held_out(vul_root, ev.LockedClaim(vul_root / "reports" / ev.LOCK_NAME))


def test_dev_evaluation_end_to_end_without_torch(vul_root):
    out = ev.evaluate(vul_root, vul_root.parent / "models", ev.EvalOptions(name="t", bootstrap=20))
    report = json.loads(out.read_text())
    assert set(report["splits"]) == {"dev"}
    views = report["splits"]["dev"]["views"]
    assert set(views) == {"full", "filtered", "audit_confirmed"}
    assert set(views["full"]["systems"]) == {"rules", "bow", "length", "random"}
    rules = views["full"]["systems"]["rules"]
    assert rules["threshold"] == 1.0 and rules["at_threshold"]["recall"] == 1.0
    assert rules["ece"] is None and rules["score_kind"].startswith("heuristic")
    assert views["full"]["systems"]["bow"]["ece"]["raw"] is not None
    assert "bow" in views["full"]["rules_plus_model"]
    assert views["filtered"]["n"] < views["full"]["n"]
    assert views["audit_confirmed"]["systems"]["rules"]["positives"] == 1
    assert not (vul_root / "reports" / ev.LOCK_NAME).exists()
    assert (vul_root / "eval" / "t" / "dev-rules.jsonl").is_file()


def test_test_split_needs_locked_and_runs_once(vul_root, capsys):
    args = ["--root", str(vul_root), "--bootstrap", "5"]
    assert ev.main([*args, "--split", "test"]) == 2
    assert ev.main([*args, "--locked"]) == 2
    assert not (vul_root / "reports" / ev.LOCK_NAME).exists()
    assert ev.main([*args, "--split", "test", "--locked", "--name", "once"]) == 0
    marker = json.loads((vul_root / "reports" / ev.LOCK_NAME).read_text())
    assert marker["name"] == "once" and marker["finished"] and marker["report"] == "vul-eval-once.json"
    report = json.loads((vul_root / "reports" / "vul-eval-once.json").read_text())
    assert set(report["splits"]) == {"dev", "test", "test_extension"}
    assert set(report["splits"]["test"]["views"]) == {"full", "filtered"}
    capsys.readouterr()
    assert ev.main([*args, "--split", "test", "--locked", "--name", "again"]) == 1
    assert "already ran" in capsys.readouterr().err
    assert not (vul_root / "reports" / "vul-eval-again.json").exists()
