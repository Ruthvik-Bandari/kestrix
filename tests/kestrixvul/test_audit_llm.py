# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import json
import re
from pathlib import Path

from kestrixvul.audit_llm import REVIEWERS, disputed, load_prompt, parse, render, review_all

PACKET = {
    "id": "r1",
    "language": "javascript",
    "path": "lib/a.js",
    "function": "f",
    "cwes": ["CWE-79"],
    "advisories": [{"id": "GHSA-x", "text": "XSS in f"}],
    "before": "function f(x) { return `<b>${x}</b>`; }",
    "after": "function f(x) { return `<b>${esc(x)}</b>`; }",
    "diff": "-a\n+b",
}


def test_prompts_render_code_with_braces_and_cut_long_parts():
    prompt = render(PACKET, load_prompt("vul_audit_reviewer.txt"), 10_000)
    assert "${x}" in prompt and "SPDX" not in prompt and '"verdict"' in prompt
    long = PACKET | {"before": "x" * 50_000}
    assert "[truncated]" in render(long, load_prompt("vul_audit_reviewer.txt"), 10_000)
    reviews = [
        {"verdict": "vulnerable", "patch": "fixes", "reason": "a"},
        {"verdict": "unclear", "patch": "unclear", "reason": "b"},
    ]
    adj = render(PACKET, load_prompt("vul_audit_adjudicator.txt"), 10_000, reviews)
    assert "Review 1: verdict=vulnerable" in adj and "Review 2: verdict=unclear" in adj


def test_parse_takes_the_last_valid_object_and_falls_back_to_unclear():
    assert parse('thinking {"x": 1} then {"verdict": "not_vulnerable", "patch": "bad", "reason": "a\\nb"}') == {
        "verdict": "not_vulnerable",
        "patch": "unclear",
        "reason": "a b",
    }
    assert parse("no json here")["reason"] == "unparseable reply"
    assert parse('{"verdict": "maybe"}')["verdict"] == "unclear"


def test_review_all_resumes_and_finds_disputes(tmp_path: Path):
    calls: list[str] = []

    def fake(prompt: str) -> str:
        calls.append(prompt)
        return '{"verdict": "vulnerable", "patch": "fixes", "reason": "ok"}'

    packets = [PACKET, PACKET | {"id": "r2"}]
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    assert review_all(packets[:1], a, fake, load_prompt("vul_audit_reviewer.txt"), 5000) == 1
    assert review_all(packets, a, fake, load_prompt("vul_audit_reviewer.txt"), 5000) == 1  # r1 is not redone
    assert len(calls) == 2 and a.stat().st_mode & 0o777 == 0o600
    b.write_text(
        json.dumps({"id": "r1", "verdict": "vulnerable"}) + "\n" + json.dumps({"id": "r2", "verdict": "unclear"}) + "\n"
    )
    assert list(disputed(a, b)) == ["r2"]


def test_fetch_script_pins_the_same_revisions():
    script = (Path(__file__).parents[2] / "research/hpc/vul/fetch_vul_audit_models.sh").read_text()
    pinned = set(re.findall(r'"([\w./-]+)@([0-9a-f]{40})"', script))
    assert pinned == {(r.repo, r.revision) for r in REVIEWERS}
