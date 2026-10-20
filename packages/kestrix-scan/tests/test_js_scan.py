# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""JavaScript and TypeScript files through the whole scan: routing, suppression, baselines, --diff, secrets, hook."""

import json
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from cli_support import run
from code_samples import fake

from kestrix_scan import hook, scan
from kestrix_scan.analyze import scan_text
from kestrix_scan.js_rules import JS_SUFFIXES, check_js
from kestrix_scan.walk import Candidate

EVAL = "export function calc(text) {\n  return eval(text);\n}\n"


def _scan_one(tmp_path: Path, name: str, text: str) -> tuple[set[str], list[str]]:
    candidate = Candidate(path=tmp_path / name, rel=name)
    findings, notes, _, skip = scan_text(text, candidate)
    return {f.rule_id for f in findings}, [n.id for n in notes] + ([skip.reason] if skip else [])


@pytest.mark.parametrize("suffix", sorted(JS_SUFFIXES))
def test_every_js_suffix_gets_the_js_rules(tmp_path: Path, suffix: str) -> None:
    rule_ids, _ = _scan_one(tmp_path, f"calc{suffix}", EVAL)
    assert rule_ids == {"js.exec.eval"}


@pytest.mark.parametrize("name", ["App.vue", "App.svelte", "calc.py", "notes.md", "calc.js.txt"])
def test_other_files_do_not_get_the_js_rules(tmp_path: Path, name: str) -> None:
    rule_ids, _ = _scan_one(tmp_path, name, "<script>\n" + EVAL + "</script>\n")
    assert not {rule_id for rule_id in rule_ids if rule_id.startswith("js.")}


def test_scan_reports_js_findings_and_skips_minified_files(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "calc.ts").write_text(EVAL)
    (tmp_path / "src" / "ok.tsx").write_text("export const A = () => <p>Don't panic</p>;\n")
    (tmp_path / "src" / "vendor.min.js").write_text(EVAL)
    (tmp_path / "src" / "bundle.js").write_text("var a=eval(x);" * 100)
    report = scan([tmp_path], root=tmp_path)
    assert [(f.path, f.rule_id, f.line) for f in report.findings] == [("src/calc.ts", "js.exec.eval", 2)]
    assert {(s.path, s.reason) for s in report.files_skipped} == {
        ("src/bundle.js", "minified"),
        ("src/vendor.min.js", "minified"),
    }
    assert report.files_scanned == 4


def test_line_comment_suppression_with_a_reason(tmp_path: Path) -> None:
    suppressed = EVAL.replace(
        "eval(text);", "eval(text); // kestrix: ignore[js.exec.eval] text is a build-time constant"
    )
    rule_ids, notes = _scan_one(tmp_path, "calc.js", suppressed)
    assert rule_ids == set() and notes == []
    above = EVAL.replace("  return", "  // kestrix: ignore[js.exec.eval] reviewed: fixed expressions only\n  return")
    assert _scan_one(tmp_path, "calc.js", above)[0] == set()
    no_reason = EVAL.replace("eval(text);", "eval(text); // kestrix: ignore[js.exec.eval]")
    rule_ids, notes = _scan_one(tmp_path, "calc.js", no_reason)
    assert rule_ids == {"js.exec.eval"} and notes == ["kestrix.suppression.missing_reason"]


def test_block_and_jsx_comment_suppression_with_a_reason(tmp_path: Path) -> None:
    text = EVAL.replace("  return", "  /* kestrix: ignore[js.exec.eval] reviewed input */\n  return")
    assert _scan_one(tmp_path, "calc.js", text) == (set(), [])
    jsx = (
        "export const A = ({ html }) => (\n  <div>\n"
        "    {/* kestrix: ignore[js.dom.xss_sink] html is rendered by our Markdown sanitizer */}\n"
        "    <div dangerouslySetInnerHTML={{ __html: html }} />\n  </div>\n);\n"
    )
    assert _scan_one(tmp_path, "a.jsx", jsx) == (set(), [])
    assert _scan_one(tmp_path, "a.jsx", jsx.replace(" html is rendered by our Markdown sanitizer ", " ")) == (
        {"js.dom.xss_sink"},
        ["kestrix.suppression.missing_reason"],
    )


def test_baseline_filters_js_findings(tmp_path: Path) -> None:
    (tmp_path / "calc.js").write_text(EVAL)
    baseline = tmp_path / "baseline.json"
    assert run(str(tmp_path / "calc.js"), "--write-baseline", str(baseline)).exit_code == 0
    report = scan([tmp_path / "calc.js"], root=tmp_path, baseline=baseline)
    assert report.findings == [] and report.baseline_filtered == 1


def test_diff_keeps_only_changed_js_lines(repo: Path, git: Callable[..., str]) -> None:
    (repo / "old.js").write_text(EVAL)
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    (repo / "old.js").write_text(EVAL + "export function g(el, v) {\n  el.innerHTML = v;\n}\n")
    (repo / "new.ts").write_text("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n")
    report = scan([repo], root=repo, diff_base="HEAD")
    assert sorted((f.path, f.rule_id, f.line) for f in report.findings) == [
        ("new.ts", "js.tls.reject_unauthorized", 1),
        ("old.js", "js.dom.xss_sink", 5),
    ]


def test_cli_exit_code_and_text_output(tmp_path: Path) -> None:
    (tmp_path / "calc.js").write_text(EVAL)
    result = run(str(tmp_path / "calc.js"), "--fail-on", "high")
    assert result.exit_code == 1
    assert "js.exec.eval" in result.stdout and "CWE-95" in result.stdout


def test_json_report_carries_a_trace_for_js_taint(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const express = require('express');\nconst app = express();\n"
        "app.get('/go', (req, res) => {\n  res.redirect(req.query.next);\n});\n"
    )
    data = json.loads(run(str(tmp_path / "server.js"), "--format", "json").stdout)
    (finding,) = data["findings"]
    assert finding["rule_id"] == "js.redirect.open"
    assert finding["trace"] == [
        {"line": 4, "note": "Express req.query (source)"},
        {"line": 4, "note": "reaches res.redirect()"},
    ]


# ----- secrets in JavaScript and TypeScript strings


@pytest.mark.parametrize(
    ("template", "kind"),
    [
        ('const apiKey = "{generic}";\n', "generic"),
        ("const apiKey: string = '{generic}';\n", "generic"),
        ("const password = `{generic}`;\n", "generic"),
        ("export const config = {{ clientSecret: '{generic}' }};\n", "generic"),
        ("const headers = {{ Authorization: `token {github_token}` }};\n", "github_token"),
        ("const url = `https://x.example/${{path}}?key={google_api_key}`;\n", "google_api_key"),
        ('const msg = <Key value="{stripe_live_key}" />;\n', "stripe_live_key"),
    ],
)
def test_secrets_in_js_strings_and_template_pieces(tmp_path: Path, template: str, kind: str) -> None:
    secret = fake(kind)
    text = template.format(**{kind: secret})
    candidate = Candidate(path=tmp_path / "config.tsx", rel="config.tsx")
    findings, _, _, _ = scan_text(text, candidate)
    assert [f.rule_id for f in findings] == [f"secret.{kind}"]
    assert secret not in json.dumps([f.to_dict() for f in findings])


def test_template_values_with_substitutions_are_not_generic_secrets(tmp_path: Path) -> None:
    rule_ids, _ = _scan_one(tmp_path, "c.js", "const password = `${process.env.PW}abcdefghijklmnop`;\n")
    assert rule_ids == set()


# ----- hook and performance


def test_hook_reports_a_js_finding_the_edit_introduced(tmp_path: Path) -> None:
    target = tmp_path / "view.tsx"
    target.write_text("export function show(el: HTMLElement, v: string) {\n  el.innerHTML = v;\n}\n")
    payload = {"tool_name": "Write", "tool_input": {"file_path": str(target)}, "tool_response": {"type": "create"}}
    reply = hook.hook_response(json.dumps({**payload, "cwd": str(tmp_path)}))
    assert reply is not None
    context = json.loads(reply)["hookSpecificOutput"]["additionalContext"]
    assert "js.dom.xss_sink" in context and "CWE-79" in context


def test_a_5000_line_typescript_file_is_fast() -> None:
    block = (
        "export async function handler{i}(req: Request<{{ id: string }}>, res: Response): Promise<void> {{\n"
        "  const id: string = req.params.id as string;\n"
        "  const rows = await pool.query<Row>('SELECT name FROM items WHERE id = $1', [id]);\n"
        "  const names = rows.map((r: Row) => r.name.trim()).filter((n) => n.length > {i} % 7);\n"
        "  const label = `item ${{id}} has ${{names.length}} names`;\n"
        "  if (label.length / 2 > 10 && /^[a-z]+$/i.test(id)) {{\n"
        "    res.json({{ label, names, ok: true }});\n"
        "  }}\n"
        "}}\n\n"
    )
    source = "import { Request, Response } from 'express';\n" + "".join(block.format(i=i) for i in range(500))
    assert len(source.splitlines()) >= 5000
    started = time.perf_counter()
    assert check_js(source, "big.ts") == []
    assert (
        time.perf_counter() - started < 6.0
    )  # generous for slow CI runners: measured p50 is about 0.16 s on an M4 Pro


PATHOLOGICAL: dict[str, Callable[[int], str]] = {
    "chained-assignments": lambda n: "a =\n" * n + "1",
    "chained-secret-names": lambda n: "token =\n" * n + "Math.random()",
    "huge-object": lambda n: "x = {\n" + "a: b,\n" * n + "}",
    "nested-calls": lambda n: "f(\n" * n + ")\n" * n,
    "nested-parens": lambda n: "(\n" * n + ")\n" * n,
}


def _best_of_three(source: str) -> float:
    times = []
    for _ in range(3):
        started = time.perf_counter()
        assert isinstance(check_js(source, "p.js"), list)
        times.append(time.perf_counter() - started)
    return min(times)


@pytest.mark.parametrize("shape", sorted(PATHOLOGICAL))
def test_pathological_input_stays_linear(shape: str) -> None:
    """Doubling the input must roughly double the time, not quadruple it.

    A wall-clock limit failed on slower CI runners (4-6 s against 0.8 s locally), so the guard is the growth
    rate instead: a quadratic matcher would take about 4x as long at twice the size.
    """
    build = PATHOLOGICAL[shape]
    small, large = _best_of_three(build(10_000)), _best_of_three(build(20_000))
    assert large < 3.0 * small + 0.05, f"{shape}: {small:.3f}s at n, {large:.3f}s at 2n"
