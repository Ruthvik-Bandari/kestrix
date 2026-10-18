import pytest

from kestrixbench.compare import CompareError, compare, markdown


def _report(successes, locked=False, split="development"):
    cases = [
        {
            "case_id": f"c{i}",
            "split": split,
            "root_id": f"r{i // 2}",
            "kind": "mapping" if i % 2 else "logic",
            "success": ok,
            "wrong_change": False,
            "abstained": not ok,
        }
        for i, ok in enumerate(successes)
    ]
    return {"cases": cases, "locked_test_included": locked}


def test_paired_difference_and_markdown():
    base = _report([False, False, True, False, False, True, False, False])
    better = _report([True, True, True, False, True, True, False, True])
    result = compare({"b0": base, "b1": better}, "b0", reps=300)
    vs = result["systems"]["b1"]["vs_baseline"]
    assert vs["mean_success_difference"] == 0.5
    assert (vs["cases_won"], vs["cases_lost"]) == (4, 0)
    assert vs["ci95"][0] > 0
    assert result["systems"]["b0"]["by_kind"] == {"logic": 0.25, "mapping": 0.25}
    table = markdown(result)
    assert "| b1 | 0.750 |" in table and "+0.500" in table and "(development split)" in table


def test_train_cases_never_enter_the_comparison():
    base, better = _report([False, True]), _report([True, True])
    for rep, ok in ((base, True), (better, False)):
        rep["cases"].append({**rep["cases"][0], "case_id": "t0", "split": "train", "success": ok})
    result = compare({"b0": base, "b1": better}, "b0", reps=100)
    assert result["cases"] == 2 and result["splits"] == ["development"]
    locked = {"b0": _report([True], locked=True, split="test"), "b1": _report([True], locked=True, split="test")}
    assert compare(locked, "b0")["splits"] == ["test"]


def test_unpaired_or_mixed_evaluations_are_refused():
    with pytest.raises(CompareError, match="paired"):
        compare({"b0": _report([True, False]), "b1": _report([True])}, "b0")
    with pytest.raises(CompareError, match="locked"):
        compare({"b0": _report([True]), "b1": _report([True], locked=True, split="test")}, "b0")
    with pytest.raises(CompareError, match="baseline"):
        compare({"b1": _report([True])}, "b0")
