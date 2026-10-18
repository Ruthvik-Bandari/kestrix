# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import stat
import sys
import zipfile

import pytest

from kestrixbench.qc import SIGMA_RULES, SYSMON_CHANNEL
from kestrixbench.review import ReviewError, status, write_sheet

RULE_A = "00000000-0000-4000-8000-00000000000a"
RULE_B = "00000000-0000-4000-8000-00000000000b"
E0 = "otrf:execution/host/demo:0"
E1 = "otrf:execution/host/demo:1"


@pytest.fixture
def root(tmp_path):
    for rid, title in ((RULE_A, "A"), (RULE_B, "B")):
        path = tmp_path / "sigma" / SIGMA_RULES / f"{title}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"title: {title}\nid: {rid}\nlogsource: {{category: process_creation, product: windows}}\n"
            "detection:\n  sel: {Image|endswith: '\\\\x.exe'}\n  condition: sel\n"
        )
    archive = tmp_path / "otrf/datasets/atomic/windows/execution/host/demo.zip"
    archive.parent.mkdir(parents=True)
    rows = [{"EventID": 1, "Channel": SYSMON_CHANNEL, "Image": f"C:\\x{i}.exe"} for i in range(2)]
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("demo.json", "\n".join(json.dumps(r) for r in rows))
    return tmp_path


def _report(own_a=1):
    return {
        "per_rule": {
            RULE_A: {"own_regression_matched": own_a, "matched_event_ids": [f"sigma:{RULE_A}:0", E0]},
            RULE_B: {"own_regression_matched": 0, "matched_event_ids": [E0, E1]},
        }
    }


def test_sheet_is_private_lists_each_event_once_and_keeps_reviewer_work(root):
    assert write_sheet(root, _report()) == {
        "candidate_events": 2,
        "rules": 2,
        "datasets": 1,
        "labels_file_created": 1,
    }
    review = root / "review"
    lines = [json.loads(x) for x in (review / "candidates.jsonl").read_text().splitlines()]
    assert [c["event_id"] for c in lines] == [E0, E1]
    assert [r["rule_id"] for r in lines[0]["rules"]] == [RULE_A, RULE_B]
    assert lines[0]["rules"][0]["title"] == "A"
    if sys.platform != "win32":
        assert stat.S_IMODE(review.stat().st_mode) == 0o700
        assert stat.S_IMODE((review / "labels.csv").stat().st_mode) == 0o600
    (review / "labels.csv").write_text(f"event_id,label,rationale,reviewer\n{E0},malicious,atomic test,rb\n{E1},,,\n")
    assert write_sheet(root, _report())["labels_file_created"] == 0
    assert "malicious" in (review / "labels.csv").read_text()  # never overwritten


def test_status_counts_verified_roots(root):
    write_sheet(root, _report())
    (root / "review/labels.csv").write_text(
        f"event_id,label,rationale,reviewer\n{E0},malicious,atomic test,rb\n{E1},benign,updater,rb\n"
    )
    result = status(root, _report())
    assert result["reviewed"] == 2
    assert result["labels"] == {"benign": 1, "malicious": 1}
    assert result["problems"] == []
    # A: own regression + E0 malicious = 2; B: E0 malicious only (E1 benign) = 1.
    assert result["roots"] == {"with_1plus_verified_positive": 2, "with_2plus_verified_positives": 1}


@pytest.mark.parametrize(
    ("row", "problem"),
    [
        ("otrf:nope:9,malicious,x,rb", "row 2: unknown event id"),
        (f"{E0},evil,x,rb", "row 2: label must be one of malicious, benign, unknown"),
        (f"{E0},malicious,x,", "row 2: reviewer is required"),
        (f"{E0},benign,,rb", "row 2: rationale is required for benign"),
    ],
)
def test_status_reports_invalid_rows_without_values(root, row, problem):
    write_sheet(root, _report())
    (root / "review/labels.csv").write_text(f"event_id,label,rationale,reviewer\n{row}\n")
    assert status(root, _report())["problems"] == [problem]


def test_wrong_header_and_stale_report_fail(root):
    write_sheet(root, _report())
    (root / "review/labels.csv").write_text("id,label\n")
    with pytest.raises(ReviewError, match="header"):
        status(root, _report())
    stale = _report()
    stale["per_rule"][RULE_B]["matched_event_ids"].append("otrf:execution/host/demo:7")
    with pytest.raises(ReviewError, match="re-run replay"):
        write_sheet(root, stale)


def _metadata(root):
    meta = root / "otrf/datasets/atomic/_metadata/SDWIN-1.yaml"
    meta.parent.mkdir(parents=True)
    link = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/demo.zip"
    meta.write_text(
        "title: Demo attack\ndescription: An adversary runs x.\n"
        "attack_mappings:\n  - technique: T1059\n    sub-technique: '001'\n"
        f"files:\n  - type: Host\n    link: {link}\n"
    )


def test_label_loop_walks_candidates_and_keeps_other_rows(root, capsys):
    from kestrixbench import __main__ as cli
    from kestrixbench.review import format_candidate, next_candidate, set_label

    _metadata(root)
    write_sheet(root, _report())
    item, remaining = next_candidate(root)
    assert (item["event_id"], remaining) == (E0, 2)
    assert item["dataset_info"]["techniques"] == ["T1059.001"]
    text = format_candidate(item, remaining)
    assert "Demo attack" in text and "A (" in text and "Image: C:\\x0.exe" in text

    set_label(root, E0, "Malicious", "in the attack chain", "rb")
    item, remaining = next_candidate(root)
    assert (item["event_id"], remaining) == (E1, 1)
    with pytest.raises(ReviewError, match="rationale is required"):
        set_label(root, E1, "benign", "", "rb")
    with pytest.raises(ReviewError, match="one line"):
        set_label(root, E1, "benign", "two\nlines", "rb")
    with pytest.raises(ReviewError, match="not exactly one row"):
        set_label(root, "otrf:nope:1", "unknown", "", "rb")

    assert cli.main(["review-label", "--root", str(root), "--event", E1, "--label", "unknown", "--reviewer", "rb"]) == 0
    assert "Every candidate is labelled." in capsys.readouterr().out
    result = status(root, _report())
    assert result["labels"] == {"malicious": 1, "unknown": 1} and result["problems"] == []


def test_import_keeps_human_labels_and_rejects_a_bad_batch_atomically(root):
    from kestrixbench.review import import_labels, set_label

    write_sheet(root, _report())
    set_label(root, E0, "benign", "updater", "rb")  # a human decision
    rows = [
        {"event_id": E0, "label": "malicious", "rationale": "ai says so", "reviewer": "ai-consensus"},
        {"event_id": E1, "label": "malicious", "rationale": "launcher child", "reviewer": "ai-consensus"},
    ]
    assert import_labels(root, rows) == {"imported": 1, "kept_existing_human_label": 1}
    result = status(root, _report())
    assert result["labels"] == {"benign": 1, "malicious": 1} and result["ai_assisted"] == 1
    with pytest.raises(ReviewError, match="row 1"):
        import_labels(root, [{"event_id": E1, "label": "evil", "rationale": "", "reviewer": "ai-x"}])
    assert status(root, _report())["labels"] == {"benign": 1, "malicious": 1}  # nothing half-applied


def test_import_tolerates_missing_or_null_fields(root):
    from kestrixbench.review import import_labels

    write_sheet(root, _report())
    counts = import_labels(root, [{"event_id": E1, "label": "unknown", "reviewer": "ai-x", "rationale": None}])
    assert counts["imported"] == 1
    with pytest.raises(ReviewError, match="reviewer is required"):
        import_labels(root, [{"event_id": E0, "label": "unknown"}])


def test_check_page_embeds_hostile_event_text_inertly(root):
    import json as _json
    import re

    from kestrixbench.review import render_check_page

    write_sheet(root, _report())
    sheet = root / "review/candidates.jsonl"
    rows = [_json.loads(x) for x in sheet.read_text().splitlines()]
    rows[0]["fields"]["CommandLine"] = "</script><img src=x onerror=alert(1)>&amp;"
    sheet.write_text("".join(_json.dumps(r) + "\n" for r in rows))
    page = render_check_page(root, [E0])
    data = re.search(r'<script id="data" type="application/json">(.*?)</script>', page, re.S).group(1)
    assert "<" not in data and ">" not in data and "&" not in data  # nothing can close the tag or form markup
    assert _json.loads(data)[0]["fields"]["CommandLine"].startswith("</script><img")  # content preserved
    assert "default-src 'none'" in page  # no network access from the page
    with pytest.raises(ReviewError, match="not a review candidate"):
        render_check_page(root, ["otrf:nope:1"])


def test_ignore_ai_labels_switch_keeps_only_human_labels(root, monkeypatch):
    from kestrixbench import __main__ as cli
    from kestrixbench.review import import_labels, set_label

    write_sheet(root, _report())
    import_labels(root, [{"event_id": E0, "label": "malicious", "rationale": "ai", "reviewer": "ai-consensus"}])
    set_label(root, E1, "benign", "updater", "rb")
    monkeypatch.delenv("KESTRIX_IGNORE_AI_LABELS", raising=False)
    assert cli._reviewed(root, _report()) == {E0: "malicious", E1: "benign"}
    monkeypatch.setenv("KESTRIX_IGNORE_AI_LABELS", "1")
    assert cli._reviewed(root, _report()) == {E1: "benign"}
