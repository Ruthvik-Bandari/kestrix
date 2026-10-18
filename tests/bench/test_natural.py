# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import os
import subprocess

import pytest

from kestrix.detect.engine import Elasticsearch
from kestrix.detect.rule import parse_rule
from kestrixbench.natural import (
    build,
    classify,
    extra_roots,
    is_refactor,
    mine,
    summarize_mining,
    to_record,
    verify_all,
)
from kestrixbench.qc import SIGMA_REGRESSION, SIGMA_RULES, SYSMON_CHANNEL

ES_URL = os.environ.get("KESTRIX_ES_URL", "http://127.0.0.1:9200")
RID = "00000000-0000-4000-8000-0000000000cc"


def rule(values, condition="sel", extra="", description="d"):
    vals = ", ".join(f"'\\\\{v}'" for v in values)
    return (
        f"title: lolbin\nid: {RID}\ndescription: {description}\n"
        "logsource: {category: process_creation, product: windows}\n"
        f"detection:\n  sel: {{Image|endswith: [{vals}]}}\n{extra}  condition: {condition}\n"
    )


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def _commit(repo, path, text, message):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.org", "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "work"
    repo.mkdir()
    _git(repo, "init", "-q")
    path = f"{SIGMA_RULES}/proc_creation_win_lolbin.yml"
    _commit(repo, path, rule(["a.exe"]), "add rule")
    _commit(repo, path, rule(["a.exe", "b.exe"]), "fix: cover b.exe (FN)")
    _commit(repo, path, rule(["a.exe", "b.exe"], description="reworded"), "docs only")
    _git(repo, "mv", path, f"{SIGMA_RULES}/proc_creation_win_lolbin_exec.yml")
    _commit(
        repo,
        f"{SIGMA_RULES}/proc_creation_win_lolbin_exec.yml",
        rule(["a.exe", "b.exe"], "sel and not filter", "  filter: {User: 'NT AUTHORITY\\\\SYSTEM'}\n"),
        "rename + FP filter",
    )
    pinned = _commit(
        repo,
        f"{SIGMA_RULES}/proc_creation_win_lolbin_exec.yml",
        rule(["a.exe", "b.exe"], "sel and not filter", "  filter: {User|re: 'x'}\n"),
        "regex filter (outside the subset)",
    )
    bare = tmp_path / "sigma-history.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(bare)], check=True)
    return bare, pinned


def test_classify_change_kinds():
    base = parse_rule(rule(["a.exe"]))
    assert classify(base, parse_rule(rule(["a.exe", "b.exe"]))) == (("values_added",), 1, True)
    assert classify(parse_rule(rule(["a.exe", "b.exe"])), base) == (("values_removed",), 1, True)
    kinds, edits, within = classify(base, parse_rule(rule(["a.exe"], "sel and not f", "  f: {User: s}\n")))
    assert set(kinds) == {"condition", "selection_added"} and edits == 2 and within
    many = parse_rule(rule([f"x{i}.exe" for i in range(9)]))
    assert classify(base, many)[2] is False  # more than 8 values do not fit a candidate predicate
    swapped = parse_rule(rule(["a.exe"]).replace("Image|endswith", "Image|contains"))
    assert classify(base, swapped)[0] == ("modifier",)


def test_mine_follows_renames_and_skips_noise(history):
    bare, pinned = history
    changes, skipped = mine(bare, pinned, {RID})
    assert [c.subject for c in changes] == ["rename + FP filter", "fix: cover b.exe (FN)"]
    assert changes[1].kinds == ("values_added",) and changes[1].within_contract
    assert set(changes[0].kinds) == {"condition", "selection_added"}
    assert skipped == {"metadata_only": 1, "outside_supported_subset": 1}
    assert mine(bare, pinned, set())[0] == []  # unsupported at the pin
    summary = summarize_mining(changes, skipped, pinned)
    assert summary["detection_changes"] == 2 and summary["rules"] == 1
    assert json.loads(json.dumps(to_record(changes[0])))["rule_id"] == RID


def test_refactor_detection():
    base = parse_rule(rule(["a.exe"], "sel and not f", "  f: {User: s}\n"))
    renamed = parse_rule(rule(["a.exe"], "sel and not filter_main", "  filter_main: {User: s}\n"))
    assert is_refactor(base, renamed)
    assert not is_refactor(base, parse_rule(rule(["a.exe"], "sel and f", "  f: {User: s}\n")))


@pytest.mark.engine
def test_verify_against_the_global_pool_then_place_by_split(tmp_path, history):
    from kestrixbench.evaluate import load_case

    bare, pinned = history
    changes = [to_record(c) for c in mine(bare, pinned, {RID})[0]]
    root = tmp_path / "data"
    case = root / "sigma" / SIGMA_REGRESSION / "other_rule"  # a recording made for a different rule
    case.mkdir(parents=True)
    other = "00000000-0000-4000-8000-0000000000dd"
    (case / "info.yml").write_text(f"rule_metadata:\n  - id: {other}\n")
    event = {"Event": {"System": {"EventID": 1, "Channel": SYSMON_CHANNEL}, "EventData": {"Image": "C:\\b.exe"}}}
    (case / f"{other}.json").write_text(json.dumps(event))
    (root / "otrf/datasets/atomic/windows").mkdir(parents=True)
    es = Elasticsearch(ES_URL)
    try:
        verified = verify_all(root, changes, set(), es)
    finally:
        es.close()
    # Only the b.exe coverage fix catches a pool event the old version missed.
    assert verified["verdicts"] == {"not_a_coverage_fix": 1, "verified": 1}
    assert extra_roots(verified) == {RID: [f"sigma:{other}:0"]}

    owned = {"id": RID, "path": "x", "positive_event_ids": [f"sigma:{other}:0"]}
    manifest = {"splits": {"train": [{"rules": [owned]}], "reserve": []}}
    result = build(root, changes, verified, manifest, {"per_rule": {}}, benign=set(), seed="s")
    assert result["placement"] == {"written": 1} and result["cases_by_split"] == {"train": 1}
    # The same event owned by a test root: the train case must not use it.
    taken = {"splits": {"train": [{"rules": [{**owned, "positive_event_ids": []}]}], "reserve": []}}
    assert build(root, changes, verified, taken, {"per_rule": {}}, benign=set(), seed="s")["placement"] == {
        "positives_owned_by_other_split": 1
    }
    stale = {**verified, "verified": [{**verified["verified"][0], "commit": "0" * 40}]}
    with pytest.raises(ValueError, match="re-run natural-verify"):
        build(root, changes, stale, manifest, {"per_rule": {}}, benign=set(), seed="s")
    manifest_case, _ = load_case(next((root / "benchmark/cases/train").glob("*-natural-*")))
    assert manifest_case["provenance"] == "natural" and "fix: cover b.exe" in manifest_case["fault"]["detail"]
    reserve = {"splits": {"reserve": manifest["splits"]["train"]}}
    assert build(root, changes, verified, reserve, {"per_rule": {}}, benign=set(), seed="s")["placement"] == {
        "root_not_in_split": 1
    }


def test_history_script_pins_the_same_commit():
    from pathlib import Path

    from kestrixbench.sources import by_name

    script = (Path(__file__).resolve().parents[2] / "hpc/fetch_history.sh").read_text()
    assert f"PINNED={by_name('sigma').commit}" in script


def test_classify_compares_repeated_fields_by_position():
    """Review finding: (selection, branch, field) keys collided when a map tests one field twice."""
    head = "title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"
    two = head + "  sel:\n    - CommandLine|contains: a\n    - CommandLine|contains: VALUE\n  condition: sel\n"
    assert classify(parse_rule(two.replace("VALUE", "b")), parse_rule(two.replace("VALUE", "c")))[0] == (
        "values_changed",
    )
    branch = head + "  sel:\n    - Image|endswith: x.exe\n  condition: sel\n"
    more = head + "  sel:\n    - User: s\n    - Image|endswith: x.exe\n  condition: sel\n"
    kinds, _, within = classify(parse_rule(branch), parse_rule(more))
    assert kinds == ("field",) and within is False  # a new branch is not a candidate edit
