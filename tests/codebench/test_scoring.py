# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The benchmark harness scores like OWASP BenchmarkUtils on a tiny synthetic expected-results file."""

import pytest
from bench import mapping, run, sg_regex
from bench.scoring import Counts, ExpectedResultsError, Finding, case_of, parse_expected, score

EXPECTED = """\
# test name, category, real vulnerability, cwe
T01,cmdi,true,78
T02,cmdi,true,78
T03,cmdi,false,78
T04,cmdi,false,78
T05,sqli,true,89
T06,sqli,false,89
T07,xss,true,79
"""


def finding(path, categories, cwes=(), rule="r"):
    return Finding(path, rule, frozenset(cwes), frozenset(categories))


def test_parse_expected_reads_rows_and_skips_comments():
    cases = parse_expected(EXPECTED)
    assert [c.name for c in cases] == ["T01", "T02", "T03", "T04", "T05", "T06", "T07"]
    assert (cases[2].category, cases[2].real, cases[2].cwe) == ("cmdi", False, 78)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("# only a comment\n", "no test cases"),
        ("T01,cmdi,maybe,78\n", "line 1"),
        ("T01,cmdi,true,78\nT01,cmdi,true,78\n", "duplicate"),
    ],
)
def test_parse_expected_rejects_bad_files(text, message):
    with pytest.raises(ExpectedResultsError, match=message):
        parse_expected(text)


def test_counts_rates_and_youden_index():
    c = Counts(tp=3, fn=1, fp=1, tn=3)
    assert (c.tpr, c.fpr, c.score) == (0.75, 0.25, 0.5)
    assert Counts().tpr == 0.0 and Counts().fpr == 0.0  # empty denominators are 0, as in BenchmarkUtils


def test_score_per_category_and_overall():
    cases = parse_expected(EXPECTED)
    findings = [
        finding("testcode/T01.py", {"cmdi"}),
        finding("testcode/T01.py", {"cmdi"}),  # a second finding in the same case counts once
        finding("testcode/T03.py", {"cmdi"}),  # safe case flagged: FP
        finding("testcode/T04.py", {"sqli"}),  # wrong category for this case: ignored
        finding("testcode/T05.py", {"sqli"}),
        finding("testcode/T06.py", set()),  # unmapped rule: ignored
        finding("helpers/utils.py", {"cmdi"}),  # not a test case: ignored
    ]
    card = score(cases, findings, "category")
    assert card.categories["cmdi"] == Counts(tp=1, fn=1, fp=1, tn=1)
    assert card.categories["sqli"] == Counts(tp=1, fn=0, fp=0, tn=1)
    # No rule for xss: every vulnerable case is a miss, TPR 0.
    assert card.categories["xss"] == Counts(tp=0, fn=1, fp=0, tn=0)
    assert card.flagged == {"T01", "T03", "T05"}
    assert card.tpr == pytest.approx((0.5 + 1.0 + 0.0) / 3)
    assert card.fpr == pytest.approx((0.5 + 0.0 + 0.0) / 3)
    assert card.score == pytest.approx(card.tpr - card.fpr)
    assert card.precision == pytest.approx(2 / 3)


def test_strict_mode_needs_an_equal_cwe():
    cases = parse_expected(EXPECTED)
    findings = [finding("T01.py", {"cmdi"}, cwes={77}), finding("T02.py", {"cmdi"}, cwes={78, 20})]
    assert score(cases, findings, "strict").flagged == {"T02"}
    assert score(cases, findings, "category").flagged == {"T01", "T02"}


def test_case_of_matches_a_directory_or_a_file_stem():
    names = {c.name: c for c in parse_expected("cfg_a,agentconfig,true,494\nT01,cmdi,true,78\n")}
    assert case_of("cfg_a/.claude/settings.json", names).name == "cfg_a"
    assert case_of("testcode/T01.py", names).name == "T01"
    assert case_of("testcode/T011.py", names) is None


def test_mapping_tables():
    assert mapping.kestrix_categories("py.subprocess.shell_true", {78}) == {"cmdi"}
    assert mapping.kestrix_categories("py.llm.output_to_sink", {89}) == {"sqli"}
    assert mapping.kestrix_categories("config.mcp.secret_inline", {798}) == {"agentconfig"}
    assert mapping.kestrix_categories("py.assert.security", {617}) == frozenset()
    assert mapping.bandit_categories("B314", {20}) == {"xxe"}
    assert mapping.bandit_categories("B304", {327}) == frozenset()
    assert mapping.bandit_categories("B324", {327}) == {"hash"}
    assert mapping.security_guidance_categories("eval_injection") == {"codeinj"}
    assert mapping.security_guidance_categories("innerHTML_xss") == frozenset()
    assert set(mapping.CWE_CATEGORY.values()) <= set(mapping.CATEGORIES)
    assert set(mapping.KESTRIX_RULES.values()) <= set(mapping.CATEGORIES)
    assert "| B314 | `xxe` |" in mapping.markdown_tables()


def test_security_guidance_adapter_applies_filters_substrings_and_regexes():
    patterns = [
        {"ruleName": "py_only", "path_filter": lambda p: p.endswith(".py"), "regex": r"\beval\("},
        {"ruleName": "sub", "substrings": ["os.system("]},
        {"ruleName": "broken", "path_filter": lambda p: 1 / 0, "regex": "x"},
        {"ruleName": "path", "path_check": lambda p: p.startswith(".github/workflows/")},
    ]
    assert sg_regex.matched_rules(patterns, "a.py", "eval(x); os.system(y)") == ["py_only", "sub"]
    assert sg_regex.matched_rules(patterns, "a.md", "eval(x)") == []
    assert sg_regex.matched_rules(patterns, ".github/workflows/ci.yml", "") == ["path"]


def test_published_results_leave_out_semgrep():
    result = {
        "tools": {"kestrix": {}, "semgrep": {}, "bandit": {}},
        "environment": {
            "semgrep_ruleset": {"sha256": "x"},
            "tool_environment": ["bandit==1.9.4", "mcp==1.29.0", "semgrep==1.178.0"],
        },
    }
    public = run.publishable(result)
    assert list(public["tools"]) == ["kestrix", "bandit"]
    assert public["environment"] == {"tool_environment": ["bandit==1.9.4"]}
    assert "semgrep" in result["tools"]  # the full result is not modified


def test_owned_cases_have_a_file_each_and_balanced_labels():
    cases = parse_expected((run.OWNED_CASES / "expected.csv").read_text())
    files = {p.relative_to(run.OWNED_CASES).as_posix() for p in run.OWNED_CASES.rglob("*") if p.is_file()}
    for case in cases:
        assert any(f.split("/")[1] in (case.name, f"{case.name}.py") for f in files if f.count("/") >= 1), case.name
        assert case.category in mapping.CATEGORIES
    assert {c.category for c in cases if c.real} == {c.category for c in cases if not c.real}
