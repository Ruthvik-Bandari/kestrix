# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json

import pytest

from kestrix.core.errors import Reason, Rejected
from kestrix.detect.fixtures import load_dataset


def write(tmp_path, rows):
    path = tmp_path / "f.jsonl"
    path.write_text("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n")
    return path


def test_loads_valid_rows(tmp_path):
    ds = load_dataset(write(tmp_path, [{"event_id": "a", "label": "benign", "data": {"x": 1}}]))
    assert ds.events[0].event_id == "a"
    assert len(ds.sha256) == 64


@pytest.mark.parametrize(
    "row",
    [
        {"event_id": "a b", "label": "benign", "data": {}},
        {"event_id": "a", "label": "evil", "data": {}},
        {"event_id": "a", "label": "benign", "data": []},
        {"event_id": "a", "label": "benign", "data": {}, "scenario_id": 3},
        "not json",
        "[1, 2]",
    ],
)
def test_rejects_bad_rows(tmp_path, row):
    with pytest.raises(Rejected):
        load_dataset(write(tmp_path, [row]))


def test_rejects_duplicates_and_size(tmp_path):
    row = {"event_id": "a", "label": "benign", "data": {}}
    with pytest.raises(Rejected, match="duplicate"):
        load_dataset(write(tmp_path, [row, row]))
    with pytest.raises(Rejected) as exc:
        load_dataset(write(tmp_path, [row]), max_bytes=10)
    assert exc.value.reason is Reason.INPUT_TOO_LARGE
