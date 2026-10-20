# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Intraprocedural taint: sources, propagation, sanitizers, function boundaries and traces in every output."""

import json
import textwrap
import time
from pathlib import Path

import pytest

from kestrix_scan import scan
from kestrix_scan.cli import render_text
from kestrix_scan.hook import describe
from kestrix_scan.models import TraceStep, fingerprint
from kestrix_scan.python_rules import check_python
from kestrix_scan.registry import Hit
from kestrix_scan.sarif import to_sarif
from kestrix_scan.taint import MAX_TRACE

FLASK = "import os, shlex, sqlite3, subprocess, requests\nfrom flask import request, redirect\n"


def hits(source: str) -> list[Hit]:
    result = check_python(textwrap.dedent(source), "app.py")
    assert isinstance(result, list), result
    return result


def only(source: str, rule_id: str) -> Hit:
    (hit,) = [hit for hit in hits(source) if hit.rule_id == rule_id]
    return hit


def notes(hit: Hit) -> list[tuple[int, str]]:
    return [(step.line, step.note) for step in hit.trace]


# ----- propagation


def test_fstring_and_alias_trace() -> None:
    hit = only(
        FLASK
        + "def f(cur):\n"
        + "    name = request.args.get('n')\n"
        + "    alias = name\n"
        + "    q = f\"SELECT * FROM t WHERE n = '{alias}'\"\n"
        + "    cur.execute(q)\n",
        "py.sql.string_built",
    )
    assert hit.confidence == "high"
    assert notes(hit) == [
        (4, "flask request.args (source)"),
        (4, "assigned to `name`"),
        (5, "assigned to `alias`"),
        (6, "assigned to `q`"),
        (7, "reaches execute()"),
    ]
    assert "flask request.args (line 4)" in hit.message


@pytest.mark.parametrize(
    "build",
    [
        "cmd = 'ls ' + x",
        "cmd = 'ls %s' % x",
        "cmd = 'ls {}'.format(x)",
        "cmd = ' '.join(['ls', x])",
        "cmd = str(x).strip().lower()",
        "cmd = 'ls '\n    cmd += x",
        "parts = {'a': x}\n    cmd = parts['a']",
        "parts = [x]\n    cmd = parts[0]",
        "cmd = (x, 1)[0]",
        "cmd = x if x else 'ls'",
        "cmd = [c for c in [x]][0]",
        "for cmd in [x]:\n        pass",
        "if (cmd := x):\n        pass",
        "obj = x\n    cmd = obj.upper()",
    ],
)
def test_propagation(build: str) -> None:
    source = FLASK + f"def f():\n    x = request.form['c']\n    {build}\n    subprocess.run(cmd, shell=True)\n"
    hit = only(source, "py.subprocess.shell_true")
    assert hit.trace, build
    assert hit.trace[0].note == "flask request.form (source)"
    assert hit.trace[-1].note == "reaches subprocess.run(shell=True)"


def test_attributes_and_methods_of_tainted_objects() -> None:
    source = FLASK + (
        "class V:\n"
        "    def get(self):\n"
        "        self.name = request.values['n']\n"
        "        os.system('cat ' + self.name)\n"
        "        data = request.get_json()\n"
        "        os.system(data.get('cmd'))\n"
    )
    found = {hit.line: hit for hit in hits(source) if hit.rule_id == "py.os.system"}
    assert set(found) == {6, 8}
    assert all(hit.confidence == "high" and hit.trace for hit in found.values())
    assert found[8].trace[0].note == "flask request.get_json (source)"


def test_django_sources() -> None:
    source = (
        "import os\nclass V:\n    def get(self, request):\n"
        "        os.system(self.request.GET['a'])\n"
        "        os.system(request.META.get('HTTP_X'))\n"
        "        os.system(request.body.decode())\n"
    )
    assert [hit.trace[0].note for hit in hits(source)] == [
        "request.GET (source)",
        "request.META (source)",
        "request.body (source)",
    ]


def test_branches_are_joined_and_loops_carry_taint() -> None:
    source = FLASK + (
        "def f(flag):\n"
        "    cmd = 'ls'\n"
        "    if flag:\n"
        "        cmd = request.args['c']\n"
        "    os.system(cmd)\n"
        "    acc = ''\n"
        "    for part in request.args.getlist('p'):\n"
        "        acc = acc + part\n"
        "    os.system(acc)\n"
        "    try:\n"
        "        t = request.args['t']\n"
        "    except KeyError:\n"
        "        t = 'x'\n"
        "    os.system(t)\n"
        "    with open('f') as fh:\n"
        "        w = request.args['w']\n"
        "    os.system(w)\n"
    )
    assert all(hit.trace for hit in hits(source))
    assert {hit.line for hit in hits(source)} == {7, 11, 16, 19}


def test_reassignment_to_a_clean_value_clears_taint() -> None:
    source = FLASK + "def f(other):\n    c = request.args['c']\n    c = other\n    os.system(c)\n"
    hit = only(source, "py.os.system")
    assert hit.trace == () and hit.confidence is None


def test_unknown_calls_return_clean_data() -> None:
    source = FLASK + "def f():\n    c = build(request.args['c'])\n    os.system(c)\n"
    assert only(source, "py.os.system").trace == ()


def test_no_taint_across_function_boundaries() -> None:
    source = FLASK + (
        "def helper(c):\n"
        "    os.system(c)\n"
        "def view():\n"
        "    helper(request.args['c'])\n"
        "    x = request.args['x']\n"
        "    def inner():\n"
        "        os.system(x)\n"
        "    run = lambda: os.system(x)\n"
        "    return inner, run\n"
    )
    found = [hit for hit in hits(source) if hit.rule_id == "py.os.system"]
    assert len(found) == 3 and all(hit.trace == () for hit in found)


def test_module_level_flow() -> None:
    source = "import os, sys\ntarget = sys.argv[1]\nos.system('ping ' + target)\n"
    hit = only(source, "py.os.system")
    assert hit.confidence == "medium" and notes(hit)[0] == (2, "sys.argv (source)")


def test_trace_is_capped() -> None:
    chain = "\n".join(f"    v{i + 1} = v{i}" for i in range(MAX_TRACE + 5))
    source = FLASK + f"def f():\n    v0 = request.args['a']\n{chain}\n    os.system(v{MAX_TRACE + 5})\n"
    hit = only(source, "py.os.system")
    assert len(hit.trace) == MAX_TRACE + 1 and hit.trace[-1].note == "reaches os.system()"


# ----- source kinds and confidence


@pytest.mark.parametrize(
    ("source_expr", "confidence"),
    [
        ("request.cookies['c']", "high"),
        ("input('cmd: ')", "medium"),
        ("sys.argv[1]", "medium"),
        ("os.environ.get('CMD')", "low"),
        ("os.getenv('CMD')", "low"),
        ("os.environ['CMD']", "low"),
    ],
)
def test_confidence_follows_the_source(source_expr: str, confidence: str) -> None:
    source = "import os, sys\nfrom flask import request\ndef f():\n    c = " + source_expr + "\n    eval(c)\n"
    assert only(source, "py.exec.eval").confidence == confidence


def test_local_sources_never_fire_taint_only_rules() -> None:
    source = (
        "import os, sys, requests\nfrom flask import redirect\n"
        "def f():\n"
        "    requests.get(os.environ.get('URL'))\n"
        "    open(sys.argv[1])\n"
        "    redirect(input())\n"
    )
    assert hits(source) == []


def test_input_shadowed_by_a_local_definition_is_not_a_source() -> None:
    source = "import os\ndef input(prompt):\n    return 'ls'\ndef f():\n    os.system(input('x'))\n"
    assert only(source, "py.os.system").trace == ()


# ----- sanitizers


def test_shlex_quote_clears_only_the_shell() -> None:
    source = FLASK + (
        "def f(cur):\n"
        "    q = shlex.quote(request.args['q'])\n"
        "    subprocess.run('grep ' + q, shell=True)\n"
        "    cur.execute(f\"SELECT * FROM t WHERE a = '{q}'\")\n"
    )
    shell = only(source, "py.subprocess.shell_true")
    assert shell.trace == () and shell.confidence == "low"  # the shell stays; quoting makes it low confidence
    assert "shlex.quote" in shell.message
    assert only(source, "py.sql.string_built").trace


@pytest.mark.parametrize("wrap", ["int", "float", "uuid.UUID"])
def test_numeric_conversion_clears_every_class(wrap: str) -> None:
    source = (
        FLASK
        + f"import uuid\ndef f(cur):\n    i = {wrap}(request.args['id'])\n    cur.execute(f'SELECT a FROM t WHERE id = {{i}}')\n    open(str(i))\n"
    )
    assert hits(source) == []  # the number is clean for every class and inert for the SQL pattern rule


def test_path_sanitizers_do_not_clear_the_shell() -> None:
    source = FLASK + (
        "from werkzeug.utils import secure_filename\n"
        "def f():\n"
        "    name = secure_filename(request.args['n'])\n"
        "    open(os.path.join('/srv', name))\n"
        "    os.system('rm ' + name)\n"
    )
    assert "py.path.traversal" not in {hit.rule_id for hit in hits(source)}
    assert only(source, "py.os.system").trace


def test_html_escape_clears_markup_but_not_template_source() -> None:
    source = (
        "import html\nfrom flask import request, render_template_string\nfrom markupsafe import Markup\n"
        "def f():\n"
        "    safe = html.escape(request.args['n'])\n"
        "    Markup('<b>' + safe + '</b>')\n"
        "    return render_template_string('Hi ' + safe)\n"
    )
    hit = only(source, "py.xss.markup")
    assert hit.line == 7 and hit.cwe == "CWE-1336"


def test_markup_finding_keeps_cwe_79() -> None:
    source = (
        "from flask import request\nfrom markupsafe import Markup\ndef f():\n    return Markup(request.args['n'])\n"
    )
    assert only(source, "py.xss.markup").cwe is None  # the rule default, CWE-79


def test_path_guard_needs_normalization() -> None:
    guarded = FLASK + (
        "def f():\n"
        "    p = os.path.realpath(os.path.join('/d', request.args['n']))\n"
        "    if not p.startswith('/d/'):\n"
        "        raise ValueError(p)\n"
        "    return open(p)\n"
    )
    assert hits(guarded) == []
    unnormalized = guarded.replace(
        "os.path.realpath(os.path.join('/d', request.args['n']))", "'/d/' + request.args['n']"
    )
    assert only(unnormalized, "py.path.traversal").trace
    positive = FLASK + (
        "from pathlib import Path\n"
        "def f():\n"
        "    p = (Path('/d') / request.args['n']).resolve()\n"
        "    if p.is_relative_to('/d'):\n"
        "        return p.read_text()\n"
        "    return open(p)\n"
    )
    assert [hit.line for hit in hits(positive)] == [8]


@pytest.mark.parametrize(
    "check",
    [
        "if p.is_file() and p.is_relative_to('/d'):\n        return open(p)",
        "if not p.is_relative_to('/d') or not p.exists():\n        raise ValueError\n    return open(p)",
    ],
)
def test_path_guard_inside_boolean_operators(check: str) -> None:
    source = (
        FLASK + f"from pathlib import Path\ndef f():\n    p = (Path('/d') / request.args['n']).resolve()\n    {check}\n"
    )
    assert hits(source) == []
    unguarded = source.replace(" and p.is_relative_to('/d')", " or p.is_relative_to('/d')")
    if unguarded != source:
        assert only(unguarded, "py.path.traversal").trace


def test_parameterized_sql_is_clean() -> None:
    source = FLASK + "def f(cur):\n    cur.execute('SELECT * FROM t WHERE a = ?', (request.args['a'],))\n"
    assert hits(source) == []


def test_fixed_scheme_and_host_through_a_variable() -> None:
    source = (
        FLASK + "def f():\n    url = 'https://api.example.com/v1/' + request.args['p'] + '/x'\n    requests.get(url)\n"
    )
    assert hits(source) == []
    bare = FLASK + "def f():\n    url = 'https://' + request.args['host'] + '/x'\n    requests.get(url)\n"
    assert only(bare, "py.ssrf.request").trace


def test_protocol_relative_redirect_is_reported() -> None:
    source = FLASK + "def f():\n    return redirect('/' + request.args['p'])\n"
    assert only(source, "py.redirect.open").trace


# ----- FastAPI


FASTAPI = "import os\nfrom typing import Annotated, Optional\nfrom fastapi import APIRouter, Depends, FastAPI, Query\napp = FastAPI()\nrouter = APIRouter()\n"


@pytest.mark.parametrize(
    "signature",
    ["cmd", "cmd: str", "cmd: Optional[str] = None", "cmd: str | None = None", "cmd: Annotated[str, Query()]"],
)
def test_fastapi_text_parameters_are_sources(signature: str) -> None:
    source = FASTAPI + f"@router.post('/x')\nasync def f({signature}):\n    os.system(cmd)\n"
    assert only(source, "py.os.system").trace[0].note == "FastAPI parameter `cmd` (source)"


@pytest.mark.parametrize(
    "signature",
    [
        "cmd: int",
        "cmd: str = Depends(get_cmd)",
        "cmd: Annotated[str, Depends(get_cmd)]",
        "cmd: Item",
    ],
)
def test_fastapi_other_parameters_are_not_sources(signature: str) -> None:
    source = FASTAPI + f"@app.get('/x')\ndef f({signature}):\n    os.system(cmd)\n"
    assert only(source, "py.os.system").trace == ()


def test_fastapi_needs_a_route_and_the_import() -> None:
    plain = FASTAPI + "def f(cmd: str):\n    os.system(cmd)\n"
    assert only(plain, "py.os.system").trace == ()
    no_import = "import os\n@app.get('/x')\ndef f(cmd: str):\n    os.system(cmd)\n"
    assert only(no_import, "py.os.system").trace == ()


# ----- LLM output


ANTHROPIC = "import os, subprocess\nimport anthropic\nclient = anthropic.Anthropic()\n"


@pytest.mark.parametrize(
    ("sink", "cwe"),
    [
        ("eval(text)", "CWE-94"),
        ("exec(text)", "CWE-94"),
        ("subprocess.run(text, shell=True)", "CWE-78"),
        ("os.system(text)", "CWE-78"),
        ("cur.execute(f'SELECT * FROM t WHERE a = {text}')", "CWE-89"),
        ("open(text)", "CWE-22"),
    ],
)
def test_llm_output_to_each_sink(sink: str, cwe: str) -> None:
    source = ANTHROPIC + (
        "def f(cur, prompt):\n"
        "    msg = client.messages.create(model='m', max_tokens=9, messages=prompt)\n"
        "    text = msg.content[0].text\n"
        f"    {sink}\n"
    )
    found = hits(source)
    assert [hit.rule_id for hit in found] == ["py.llm.output_to_sink"]  # replaces the pattern rule on that line
    (hit,) = found
    assert hit.cwe == cwe and hit.confidence == "high"
    assert hit.trace[0] == TraceStep(5, "LLM output of messages.create (source)")
    assert "prompt injection" in hit.message


@pytest.mark.parametrize(
    ("imports", "call"),
    [
        ("from openai import OpenAI\nclient = OpenAI()\n", "client.chat.completions.create(model='m', messages=p)"),
        ("import openai\nclient = openai.OpenAI()\n", "client.responses.create(model='m', input=p).output_text"),
        ("import litellm\n", "litellm.completion(model='m', messages=p)"),
        ("from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n", "llm.invoke(p).content"),
        ("import anthropic\n", "await anthropic.AsyncAnthropic().messages.create(messages=p)"),
    ],
)
def test_llm_clients(imports: str, call: str) -> None:
    source = imports + f"async def f(p):\n    out = {call}\n    return eval(str(out))\n"
    assert only(source, "py.llm.output_to_sink").trace


def test_llm_output_reaching_a_url_is_ssrf() -> None:
    source = "import requests, anthropic\nc = anthropic.Anthropic()\ndef f(p):\n    u = c.messages.create(messages=p).content[0].text\n    requests.get(u)\n"
    assert only(source, "py.ssrf.request").trace[0].note == "LLM output of messages.create (source)"


# ----- traces in every output


@pytest.fixture
def tainted_project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        FLASK + "def f(cur):\n    q = 'SELECT * FROM t WHERE a = ' + request.args['a']\n    cur.execute(q)\n"
        "def g(h):\n    os.system(h)\n"
    )
    return tmp_path


def test_trace_in_json(tainted_project: Path) -> None:
    report = json.loads(scan([tainted_project], root=tainted_project).to_json())
    by_rule = {finding["rule_id"]: finding for finding in report["findings"]}
    assert by_rule["py.sql.string_built"]["trace"] == [
        {"line": 4, "note": "flask request.args (source)"},
        {"line": 4, "note": "assigned to `q`"},
        {"line": 5, "note": "reaches execute()"},
    ]
    assert by_rule["py.sql.string_built"]["confidence"] == "high"
    assert "trace" not in by_rule["py.os.system"]  # the key is optional: pattern findings are unchanged
    assert report["schema_version"] == 1


def test_trace_in_sarif_code_flows(tainted_project: Path) -> None:
    results = {r["ruleId"]: r for r in to_sarif(scan([tainted_project], root=tainted_project))["runs"][0]["results"]}
    (flow,) = results["py.sql.string_built"]["codeFlows"]
    (thread,) = flow["threadFlows"]
    steps = [
        (loc["location"]["physicalLocation"]["region"]["startLine"], loc["location"]["message"]["text"])
        for loc in thread["locations"]
    ]
    assert steps == [(4, "flask request.args (source)"), (4, "assigned to `q`"), (5, "reaches execute()")]
    assert thread["locations"][0]["location"]["physicalLocation"]["artifactLocation"] == {
        "uri": "app.py",
        "uriBaseId": "SRCROOT",
    }
    assert "codeFlows" not in results["py.os.system"]


def test_trace_in_text_and_hook_output(tainted_project: Path) -> None:
    report = scan([tainted_project], root=tainted_project)
    text = render_text(report)
    assert "trace: 4 flask request.args (source) → 4 assigned to `q` → 5 reaches execute()" in text
    finding = next(f for f in report.findings if f.rule_id == "py.sql.string_built")
    assert "[trace: L4→L4→L5]" in describe(finding)
    plain = next(f for f in report.findings if f.rule_id == "py.os.system")
    assert "trace" not in describe(plain)


def test_fingerprint_ignores_the_trace(tainted_project: Path) -> None:
    finding = next(f for f in scan([tainted_project], root=tainted_project).findings if f.trace)
    assert finding.fingerprint == fingerprint(finding.rule_id, finding.path, finding.snippet)


def test_a_5000_line_file_full_of_sources_is_fast() -> None:
    handler = (
        "@app.route('/h{i}')\n"
        "def handler_{i}(cursor):\n"
        "    name = request.args.get('name', '')\n"
        "    cursor.execute('SELECT a FROM t WHERE b = ?', (name,))\n"
        "    for part in [p.strip() for p in name.split(',') if p]:\n"
        "        if part.startswith('x'):\n"
        "            subprocess.run(['echo', part], check=True)\n"
        "    return redirect('/items/{i}/' + name)\n\n\n"
    )
    source = FLASK + "app = object()\n" + "".join(handler.format(i=i) for i in range(500))
    assert len(source.splitlines()) >= 5000
    started = time.perf_counter()
    assert hits(source) == []
    assert time.perf_counter() - started < 2.0  # generous: measured p50 is about 0.13 s on an M4 Pro
