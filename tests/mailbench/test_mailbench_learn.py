# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Non-negative logistic regression: optimality, determinism, grouped folds, thresholds and refusal of test rows."""

import json
import random
from pathlib import Path

import numpy as np
import pytest
from mailbench_data import HIGH, LOW, MEDIUM, row

from kestrixmailbench.common import Layout, MailBenchError
from kestrixmailbench.learn import (
    balanced_weights,
    far_threshold,
    fit_lr,
    grouped_folds,
    learn,
    matched,
    model_scores,
    verdicts,
)
from kestrixmailbench.metrics import CONTENT, Frame, baseline_scoring


def problem(seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    x = (rng.random((400, 5)) < [0.5, 0.3, 0.2, 0.4, 0.1]).astype(float)
    logit = -0.5 + 2.0 * x[:, 0] + 1.0 * x[:, 1] - 3.0 * x[:, 2]  # feature 2 truly lowers risk
    y = (rng.random(400) < 1 / (1 + np.exp(-logit))).astype(float)
    return x, y


def objective_gradient(
    x: np.ndarray, y: np.ndarray, sw: np.ndarray, w: np.ndarray, b: float, l2: float
) -> tuple[np.ndarray, float]:
    p = 1 / (1 + np.exp(-(x @ w + b)))
    r = sw / sw.sum() * (p - y)
    return x.T @ r + l2 * w, float(r.sum())


def test_fit_satisfies_the_constrained_optimality_conditions() -> None:
    x, y = problem()
    sw = balanced_weights(y)
    w, b = fit_lr(x, y, sw, l2=1e-3)
    assert (w >= 0).all()
    gw, gb = objective_gradient(x, y, sw, w, b, 1e-3)
    assert abs(gb) < 1e-6
    for weight, grad in zip(w, gw, strict=True):
        if weight > 1e-9:
            assert abs(grad) < 1e-6  # interior: gradient is zero
        else:
            assert grad > -1e-6  # on the boundary: the loss cannot fall by raising the weight


def test_signs_and_ordering_are_recovered_and_harmful_feature_is_clamped() -> None:
    x, y = problem()
    w, _ = fit_lr(x, y, balanced_weights(y), l2=1e-4)
    assert w[0] > w[1] > 0.3
    assert w[2] == 0.0  # the feature that lowers risk gets no negative weight


def test_unconstrained_fit_can_go_negative() -> None:
    x, y = problem()
    w, _ = fit_lr(x, y, balanced_weights(y), l2=1e-4, nonneg=False)
    assert w[2] < -1.0


def test_fit_is_deterministic() -> None:
    x, y = problem()
    first = fit_lr(x, y, balanced_weights(y), 1e-3)
    second = fit_lr(x.copy(), y.copy(), balanced_weights(y), 1e-3)
    assert np.array_equal(first[0], second[0]) and first[1] == second[1]


def test_cell_balancing_gives_every_cell_an_equal_share_of_its_class() -> None:
    y = np.array([0.0] * 6 + [1.0] * 4)
    cells = np.array(["big/ham"] * 4 + ["small/ham"] * 2 + ["a/spam"] * 3 + ["b/phish"])
    cell_w = balanced_weights(y, cells)
    class_w = balanced_weights(y)
    assert cell_w.sum() == pytest.approx(1.0) and class_w.sum() == pytest.approx(1.0)
    assert cell_w[y == 0].sum() == pytest.approx(0.5) and cell_w[y == 1].sum() == pytest.approx(0.5)
    assert cell_w[:4].sum() == pytest.approx(cell_w[4:6].sum()) == pytest.approx(0.25)
    assert cell_w[6:9].sum() == pytest.approx(cell_w[9]) == pytest.approx(0.25)
    assert class_w[:4].sum() > class_w[4:6].sum()


def test_more_regularization_shrinks_weights() -> None:
    x, y = problem()
    weak, _ = fit_lr(x, y, balanced_weights(y), 1e-5)
    strong, _ = fit_lr(x, y, balanced_weights(y), 1e-1)
    assert strong.sum() < weak.sum()


def test_grouped_folds_keep_groups_whole_and_balance_load() -> None:
    sizes = {f"g{k}": 10 + k for k in range(12)}
    folds = grouped_folds(list(sizes), 3, sizes)
    assert set(folds) == set(sizes)
    load = [sum(s for g, s in sizes.items() if folds[g] == f) for f in range(3)]
    assert max(load) - min(load) <= max(sizes.values())
    assert folds == grouped_folds(list(reversed(list(sizes))), 3, sizes)


def test_far_threshold_respects_every_cap() -> None:
    ham_a = np.array([0.0] * 90 + [1.0] * 6 + [2.0] * 4)  # 10% at or above 1.0, 4% at or above 2.0
    ham_b = np.array([0.0] * 50 + [1.0] * 50)
    assert far_threshold([(ham_a, 0.05)]) == 2.0
    assert far_threshold([(ham_a, 0.10)]) == 1.0
    assert far_threshold([(ham_a, 0.10), (ham_b, 0.10)]) > 1.0  # the second ham set needs a higher threshold
    assert far_threshold([(ham_a, 0.0)]) > 2.0
    z = np.array([0.5, 1.0, 3.0])
    assert list(verdicts(z, 1.0, 3.0)) == ["clean", "suspicious", "malicious"]


def dev_rows(n_groups: int = 12, per_group: int = 40, seed: int = 4) -> list[dict[str, object]]:
    rng = random.Random(seed)
    rows = []
    n = 0
    for g in range(n_groups):
        for k in range(per_group):
            n += 1
            label = "ham" if k % 2 == 0 else ("phishing" if g % 2 else "spam")
            source = "enron" if label == "ham" and g % 3 == 0 else None
            findings = []
            if label != "ham":
                findings += [MEDIUM] if rng.random() < 0.7 else []
                findings += [HIGH] if rng.random() < 0.3 else []
            else:
                findings += [LOW] if rng.random() < 0.15 else []
                findings += [MEDIUM] if rng.random() < 0.03 else []
            rows.append(row(n, label, f"grp{g}", findings, source=source))
    return rows


def test_learn_end_to_end_on_dev_rows(tmp_path: Path) -> None:
    layout = Layout(tmp_path, 4)
    rows = dev_rows()
    model, report = learn(layout, rows, CONTENT, folds=3, reps=10, far_suspicious=0.1, far_malicious=0.02)
    assert all(w >= 0 for w in model["weights"].values())
    assert model["weights"][HIGH[0]] > model["weights"][LOW[0]]
    assert model["thresholds"]["malicious"] >= model["thresholds"]["suspicious"]
    assert model["feature_set"]["exclude_analyzers"] == ["auth"]
    assert model["training"]["messages"] == len(rows) and model["training"]["groups"] == 12
    assert model["kind"] == "kestrix-mail-weights-candidate"
    # the false-alarm targets hold on the out-of-fold scores, for every ham source
    learned = report["learned"]["flagged_rate"]
    assert learned["ham_spamassassin"]["rate"] <= 0.1 and learned["ham_enron"]["rate"] <= 0.1
    assert report["learned"]["malicious_rate"]["ham_all"]["rate"] <= 0.02
    assert report["matched_false_alarm"]["flagged"]["learned_false_alarm"]["ham_all"]["rate"] <= (
        report["matched_false_alarm"]["flagged"]["baseline_false_alarm"]["ham_all"]["rate"] + 1e-9
    )
    json.dumps(model), json.dumps(report)  # both are plain JSON


def test_learning_is_reproducible(tmp_path: Path) -> None:
    layout = Layout(tmp_path, 4)
    one, _ = learn(layout, dev_rows(), CONTENT, folds=3, reps=5)
    two, _ = learn(layout, dev_rows(), CONTENT, folds=3, reps=5)
    for key in ("weights", "intercept", "thresholds", "interactions", "l2"):
        assert one[key] == two[key]
    assert one["training"]["dev_training_ids_sha256"] == two["training"]["dev_training_ids_sha256"]


def test_rare_ids_are_listed_not_learned_and_interactions_need_support(tmp_path: Path) -> None:
    rows = dev_rows()
    rows.append(row(9999, "phishing", "grp0", [["mail.attachments.encrypted_archive", "medium", "attachments"]]))
    model, _ = learn(Layout(tmp_path, 4), rows, CONTENT, folds=3, reps=5, min_support=5)
    assert "mail.attachments.encrypted_archive" in model["unlearned_ids"]
    assert "mail.attachments.encrypted_archive" not in model["weights"]
    assert model["interactions"] == []  # random_host and plain_http never occur here


def test_learning_refuses_test_rows(tmp_path: Path) -> None:
    rows = dev_rows()
    rows[0] = {**rows[0], "split": "test"}
    with pytest.raises(MailBenchError, match="dev rows only"):
        learn(Layout(tmp_path, 4), rows, CONTENT, folds=3)


def test_one_class_folds_are_an_error(tmp_path: Path) -> None:
    rows = [r for r in dev_rows() if r["label"] == "ham"]
    with pytest.raises(MailBenchError, match="one class"):
        learn(Layout(tmp_path, 4), rows, CONTENT, folds=3)


def test_model_scores_apply_weights_and_interactions() -> None:
    model = {
        "intercept": -1.0,
        "weights": {"a": 2.0, "b": 0.5},
        "interactions": [{"ids": ["a", "b"], "weight": 1.5}],
    }
    z = model_scores([frozenset(), frozenset({"a"}), frozenset({"a", "b", "zzz"})], model)
    assert list(z) == [-1.0, 1.0, 3.0]


def test_matched_comparison_caps_learned_false_alarms_at_the_baseline_rate() -> None:
    frame = Frame(dev_rows())
    base = baseline_scoring(frame, CONTENT)
    z = np.array([2.0 if r["findings"] else 0.0 for r in frame.rows])
    out = matched(frame, z, base, "each_source", reps=5, seed=0)
    for level in ("flagged", "malicious"):
        for name in ("ham_spamassassin", "ham_enron"):
            assert (
                out[level]["learned_false_alarm"][name]["rate"]
                <= out[level]["baseline_false_alarm"][name]["rate"] + 1e-9
            )
