# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Shell argument vectors, propagators, guards, constants, weak randomness, reflected XSS, LDAP, XPath, cookies,
sessions and XML parser configuration (the round of rule fixes informed by the BenchmarkPython gap list)."""

import textwrap

import pytest

from kestrix_scan.python_rules import check_python
from kestrix_scan.registry import Hit

FLASK = "import base64, codecs, io, json, os, random, shlex, subprocess\nfrom flask import abort, redirect, request\n"


def hits(source: str) -> list[Hit]:
    result = check_python(textwrap.dedent(source), "app.py")
    assert isinstance(result, list), result
    return result


def ids(source: str) -> set[str]:
    return {hit.rule_id for hit in hits(source)}


def only(source: str, rule_id: str) -> Hit:
    (hit,) = [hit for hit in hits(source) if hit.rule_id == rule_id]
    return hit


# ----- shells started through an argument list


@pytest.mark.parametrize(
    "argv",
    [
        "['sh', '-c', cmd]",
        "('bash', '-c', 'tar czf out.tgz ' + cmd)",
        "['/bin/zsh', '-lc', f'grep {cmd} log']",
        "['/usr/bin/dash', '-ec', cmd, 'argv0']",
        "['cmd.exe', '/c', cmd]",
        "['powershell', '-Command', cmd]",
    ],
)
def test_shell_with_a_command_string_in_an_argument_list(argv: str) -> None:
    source = FLASK + f"def f():\n    cmd = request.args['c']\n    subprocess.run({argv})\n"
    hit = only(source, "py.subprocess.shell_true")
    assert hit.confidence == "high" and hit.trace[0].note == "flask request.args (source)"


def test_shell_argument_list_without_taint_and_through_asyncio() -> None:
    plain = "import subprocess\ndef f(script):\n    subprocess.check_output(['bash', '-c', script])\n"
    assert only(plain, "py.subprocess.shell_true").confidence is None  # the rule default
    asyncio_exec = (
        "import asyncio\nfrom flask import request\n"
        "async def f():\n    await asyncio.create_subprocess_exec('sh', '-c', request.form['s'])\n"
    )
    assert only(asyncio_exec, "py.subprocess.shell_true").trace


@pytest.mark.parametrize(
    "argv",
    [
        "['sh', '-c', 'ls -l /tmp']",  # a fixed script
        "['sh', '-c', 'grep -- \"$1\" app.log', 'sh', cmd]",  # the value is a positional parameter, not script text
        "['sh', script_path, cmd]",  # a script file, not a command string
        "['shellcheck', '-c', cmd]",  # not a shell
        "['bash', '--norc', cmd]",
        "['git', 'log', cmd]",
    ],
)
def test_argument_lists_that_do_not_build_a_shell_script(argv: str) -> None:
    source = FLASK + f"def f(script_path):\n    cmd = request.args['c']\n    subprocess.run({argv})\n"
    assert "py.subprocess.shell_true" not in ids(source)


def test_shlex_quoted_commands_are_low_confidence() -> None:
    quoted = "import shlex, subprocess\ndef f(name):\n    subprocess.run('ls ' + shlex.quote(name), shell=True)\n"
    hit = only(quoted, "py.subprocess.shell_true")
    assert hit.confidence == "low" and "shlex.quote" in hit.message
    via_name = "import os, shlex\ndef f(n):\n    q = shlex.quote(n)\n    os.system(f'cat {q}')\n"
    assert only(via_name, "py.os.system").confidence == "low"
    mixed = "import shlex, subprocess\ndef f(a, b):\n    subprocess.run(f'cp {shlex.quote(a)} {b}', shell=True)\n"
    assert only(mixed, "py.subprocess.shell_true").confidence is None


# ----- propagation


@pytest.mark.parametrize(
    "decode",
    [
        "urllib.parse.unquote(raw)",
        "urllib.parse.unquote_plus(raw)",
        "urllib.parse.quote(raw)",
        "base64.b64decode(raw).decode()",
        "base64.urlsafe_b64decode(raw.encode()).decode('utf-8')",
        "bytes.decode(base64.b64decode(raw))",
        "json.loads(raw)['name']",
        "str.join('/', ['files', raw])",
        "codecs.decode(raw, 'rot13')",
    ],
)
def test_decoding_and_parsing_keep_the_taint(decode: str) -> None:
    source = (
        FLASK + f"import urllib.parse\ndef f():\n    raw = request.args['p']\n    name = {decode}\n    open(name)\n"
    )
    assert only(source, "py.path.traversal").trace[0].note == "flask request.args (source)"


@pytest.mark.parametrize(
    "sink",
    ["codecs.open(os.path.join('/d', n), encoding='utf-8')", "io.open('/d/' + n)", "codecs.open(filename=n)"],
)
def test_codecs_and_io_open_are_path_sinks(sink: str) -> None:
    source = FLASK + f"def f():\n    n = request.args['n']\n    return {sink}\n"
    assert "py.path.traversal" in ids(source)


# ----- guards


@pytest.mark.parametrize(
    "guard",
    [
        "p = (Path('/d') / n).resolve()\n    if not str(p).startswith('/d/'):\n        abort(404)\n    return open(p)",
        "full = os.path.join('/d', n)\n    if not str(Path(full).resolve()).startswith('/d/'):\n        abort(404)\n    return open(full)",
        "full = os.path.join('/d', n)\n    if not os.path.realpath(full).startswith('/d/'):\n        return None\n    return open(full)",
        "full = os.path.join('/d', n)\n    if os.path.realpath(full).startswith('/d/'):\n        return open(full)",
        "p = os.path.abspath(os.path.join('/d', n))\n    if not os.fspath(p).startswith('/d/'):\n        raise PermissionError(p)\n    return open(p)",
    ],
)
def test_resolve_and_contain_guards(guard: str) -> None:
    source = FLASK + f"from pathlib import Path\ndef f():\n    n = request.args['n']\n    {guard}\n"
    assert "py.path.traversal" not in ids(source)


def test_containment_check_without_normalization_is_not_a_guard() -> None:
    source = FLASK + (
        "def f():\n    p = '/d/' + request.args['n']\n    if not str(p).startswith('/d/'):\n        abort(404)\n"
        "    return open(p)\n"
    )
    assert only(source, "py.path.traversal").trace


@pytest.mark.parametrize(
    "check",
    [
        "if urlsplit(target).netloc:\n        abort(400)",
        "parts = urlparse(target)\n    if parts.scheme or parts.netloc:\n        target = '/'",
        "if urlsplit(target).netloc != '':\n        return redirect('/')",
        "if urlsplit(target).netloc not in ALLOWED_HOSTS:\n        return redirect('/')",
        "parts = urlsplit(target)\n    if not (parts.netloc == '' or parts.netloc in ALLOWED_HOSTS):\n        abort(400)",
    ],
)
def test_redirect_guards_on_the_parsed_host(check: str) -> None:
    source = FLASK + (
        "from urllib.parse import urlparse, urlsplit\nALLOWED_HOSTS = {'app.example.com'}\n"
        f"def f():\n    target = request.args['next']\n    {check}\n    return redirect(target)\n"
    )
    assert "py.redirect.open" not in ids(source)


@pytest.mark.parametrize(
    "check",
    [
        "if urlsplit(target).netloc:\n        print('external')",  # no exit: the redirect still runs
        "if urlsplit(other).netloc:\n        abort(400)",  # checks another value
        "if urlsplit(target).netloc in hosts:\n        pass\n    else:\n        pass",  # not a literal allowlist
        "if not target.startswith('http'):\n        target = '/'",
    ],
)
def test_checks_that_do_not_make_a_redirect_local(check: str) -> None:
    source = FLASK + (
        "from urllib.parse import urlsplit\n"
        f"def f(other, hosts):\n    target = request.args['next']\n    {check}\n    return redirect(target)\n"
    )
    assert only(source, "py.redirect.open").trace


@pytest.mark.parametrize(
    "allow",
    [
        "if col not in SORTABLE:\n        return 'bad sort', 400",
        "if col not in ('name', 'created'):\n        abort(400)",
        "if col not in frozenset({'name', 'created'}):\n        col = 'name'",
        "if col not in COLUMNS.keys():\n        raise ValueError(col)",
    ],
)
def test_allowlisted_identifiers_are_constant_for_sql(allow: str) -> None:
    source = FLASK + (
        "SORTABLE = ['name', 'created']\nCOLUMNS = {'name': 1, 'created': 2}\n"
        f"def f(cur):\n    col = request.args['sort']\n    {allow}\n    cur.execute(f'SELECT a FROM t ORDER BY {{col}}')\n"
    )
    assert hits(source) == []


def test_allowlist_must_be_literal_and_unchanged() -> None:
    mutable = FLASK + (
        "SORTABLE = ['name']\nSORTABLE.append(request.args['extra'])\n"
        "def f(cur):\n    col = request.args['sort']\n    if col not in SORTABLE:\n        abort(400)\n"
        "    cur.execute(f'SELECT a FROM t ORDER BY {col}')\n"
    )
    assert "py.sql.string_built" in ids(mutable)
    substring = FLASK + (
        "def f(cur):\n    col = request.args['sort']\n    if col not in 'name,created':\n        abort(400)\n"
        "    cur.execute(f'SELECT a FROM t ORDER BY {col}')\n"
    )
    assert only(substring, "py.sql.string_built").trace


def test_int_cast_values_keep_sql_quiet() -> None:
    source = "def f(cur, raw):\n    i = int(raw)\n    cur.execute(f'SELECT a FROM t WHERE id = {i}')\n"
    assert hits(source) == []
    inline = "def f(cur, raw):\n    cur.execute('DELETE FROM t WHERE id = %d' % int(raw))\n"
    assert hits(inline) == []


# ----- constants


@pytest.mark.parametrize(
    "build",
    [
        "cmd = CMDS['disk']",
        "cmd = CMDS.get('disk', 'df')",
        "cmd = CMDS.get(request.args['k'], 'uptime')",  # every value of the display is a literal
        "cmd = LIST[1]",
        "cmd = 'du -sh {}'.format(BASE)",
        "cmd = ' '.join(['ls', BASE])",
        "cmd = 'ls'\n    if False:\n        cmd = request.args['c']",
        "cmd = 'ls'\n    if DEBUG:\n        cmd = request.args['c']",
        "cmd = request.args['c']\n    cmd = 'uptime'",
        "cmd = request.args['c'] if 7 < 3 else 'ls'\n    cmd = 'ls'",
        "parts = {'a': 'ls', 'b': request.args['c']}\n    cmd = parts['a']",
    ],
)
def test_provably_constant_commands_are_not_reported(build: str) -> None:
    source = FLASK + (
        "CMDS = {'disk': 'df -h', 'load': 'uptime'}\nLIST = ['pwd', 'id']\nBASE = '/srv'\nDEBUG = False\n"
        f"def f():\n    {build}\n    subprocess.run(cmd, shell=True)\n    os.system(cmd)\n    eval(cmd)\n"
    )
    assert hits(source) == []


@pytest.mark.parametrize(
    "build",
    [
        "cmd = CMDS[key]",  # CMDS has a non-literal value
        "cmd = MUTABLE['a']",  # its items are changed elsewhere in the file
        "cmd = 'ls'\n    if flag:\n        cmd = request.args['c']",
        "cmd = 'ls'\n    if DEBUG_FROM_ENV:\n        cmd = request.args['c']",
        "cmd = 'ls {}'.format(key)",
    ],
)
def test_values_that_are_not_provably_constant_are_reported(build: str) -> None:
    source = FLASK + (
        "CMDS = {'a': 'ls', 'b': request.args.get('x')}\nMUTABLE = {'a': 'ls'}\nMUTABLE['a'] = input()\n"
        "DEBUG_FROM_ENV = os.environ.get('D') == '1'\n"
        f"def f(key, flag):\n    {build}\n    os.system(cmd)\n"
    )
    assert "py.os.system" in ids(source)


def test_code_in_a_branch_that_cannot_run_is_not_reported() -> None:
    source = (
        FLASK + "def f():\n    if False:\n        eval(request.args['e'])\n    while 0:\n        os.system(input())\n"
    )
    assert hits(source) == []
    live = FLASK + "def f():\n    if True:\n        pass\n    else:\n        pass\n    eval(request.args['e'])\n"
    assert "py.exec.eval" in ids(live)


def test_pickle_and_yaml_of_a_literal_are_not_reported() -> None:
    assert hits("import pickle\nDATA = b'\\x80\\x04K\\x01.'\nvalue = pickle.loads(DATA)\n") == []
    assert hits("import yaml\nCONFIG = 'a: 1'\nvalue = yaml.load(CONFIG, Loader=yaml.Loader)\n") == []
    assert "py.deserialize.pickle" in ids("import pickle\ndef f(blob):\n    return pickle.loads(blob)\n")
    assert "py.deserialize.pickle" in ids("import pickle\nwith open('x', 'rb') as fh:\n    pickle.load(fh)\n")


def test_placeholder_lists_are_literal_sql() -> None:
    source = "def f(cur, ids):\n    marks = ','.join('?' for _ in ids)\n    cur.execute('SELECT a FROM t WHERE id IN (' + marks + ')', ids)\n"
    assert hits(source) == []
    raw = "def f(cur, ids):\n    cur.execute('SELECT a FROM t WHERE id IN (' + ','.join(ids) + ')')\n"
    assert "py.sql.string_built" in ids(raw)


# ----- weak randomness


@pytest.mark.parametrize(
    ("statement", "confidence"),
    [
        ("resp.set_cookie('sid', str(random.randint(1, 10**9)), secure=True, httponly=True)", "medium"),
        ("resp.set_cookie(key='sid', value=value, secure=True, httponly=True)", "medium"),
        ("session['challenge'] = value", "medium"),
        ("resp.headers['X-Auth-Challenge'] = '%x' % int(value * 1e9)", "low"),
        ("issue(user, reset_token=value)", None),
        ("csrf = hex(rng.getrandbits(64))", None),
    ],
)
def test_weak_random_values_in_cookies_sessions_headers_and_secrets(statement: str, confidence: str | None) -> None:
    source = (
        "import random\nfrom flask import session\n"
        "def f(resp, user):\n    rng = random.Random()\n    value = random.random()\n"
        f"    {statement}\n"
    )
    hit = only(source, "py.crypto.insecure_random")
    assert hit.confidence == confidence
    assert hit.trace and "random." in hit.trace[0].note


@pytest.mark.parametrize(
    "statement",
    [
        "resp.set_cookie('sid', secrets.token_hex(16), secure=True, httponly=True)",
        "session['challenge'] = secrets.randbits(64)",
        "resp.headers['X-Token'] = str(random.SystemRandom().random())",
        "random.shuffle(order)\n    session['order'] = order",
        "resp.headers['X-Count'] = str(len(order))",
        "jitter = random.random()\n    issue(user, delay=jitter)",
    ],
)
def test_secure_or_unrelated_randomness_is_not_reported(statement: str) -> None:
    source = f"import random, secrets\nfrom flask import session\ndef f(resp, user, order):\n    {statement}\n"
    assert "py.crypto.insecure_random" not in ids(source)


def test_weak_randomness_is_not_attacker_input() -> None:
    source = "import random, subprocess\ndef f():\n    n = random.randint(1, 9)\n    subprocess.run(f'sleep {n}', shell=True)\n"
    assert only(source, "py.subprocess.shell_true").trace == ()


# ----- reflected XSS


@pytest.mark.parametrize(
    "view",
    [
        "html = '<ul><li>' + request.args['item'] + '</li></ul>'\n    return html",
        "return make_response('<p>%s</p>' % request.form['m'])",
        "return Response('<p>{}</p>'.format(request.args['m']))",
        "return Response(f'<p>{request.args[\"m\"]}</p>', mimetype='text/html')",
    ],
)
def test_flask_views_returning_html_with_request_data(view: str) -> None:
    source = f"from flask import Response, make_response, request\ndef f():\n    {view}\n"
    hit = only(source, "py.xss.reflected")
    assert hit.confidence == "high" and hit.trace


def test_fastapi_html_responses() -> None:
    base = "from fastapi import FastAPI\nfrom fastapi.responses import HTMLResponse\napp = FastAPI()\n"
    wrapped = base + "@app.get('/h')\ndef h(name: str):\n    return HTMLResponse('<p>' + name + '</p>')\n"
    assert "py.xss.reflected" in ids(wrapped)
    declared = base + "@app.get('/h', response_class=HTMLResponse)\ndef h(name: str):\n    return f'<p>{name}</p>'\n"
    assert "py.xss.reflected" in ids(declared)


@pytest.mark.parametrize(
    "view",
    [
        "return Response(f'<p>{request.args[\"m\"]}</p>', mimetype='application/json')",
        "return '<p>' + html.escape(request.args['m']) + '</p>'",
        "return f'<p>{len(request.args)}</p>'",
        "return '<p>Hello</p>' + 'world'",
        "return render_template('p.html', m=request.args['m'])",
    ],
)
def test_html_that_is_escaped_fixed_or_not_html(view: str) -> None:
    source = f"import html\nfrom flask import Response, render_template, request\ndef f():\n    {view}\n"
    assert "py.xss.reflected" not in ids(source)


def test_django_view_returning_a_string_is_not_reflected_xss() -> None:
    # Django needs an HttpResponse; only the wrapped string is sent as HTML.
    source = "def view(request):\n    return f\"<p>{request.GET['q']}</p>\"\n"
    assert "py.xss.reflected" not in ids(source)


# ----- LDAP and XPath


def test_ldap_filter_position_per_library() -> None:
    ldap3_base = "import ldap3\nfrom flask import request\ndef f(c):\n    u = request.args['u']\n"
    assert "py.ldap.injection" not in ids(ldap3_base + "    c.search(f'ou={u},dc=x', '(objectClass=*)')\n")
    assert "py.ldap.injection" in ids(ldap3_base + "    c.search('dc=x', f'(uid={u})')\n")
    python_ldap = "import ldap\nfrom flask import request\ndef f(c):\n    u = request.args['u']\n"
    assert "py.ldap.injection" in ids(
        python_ldap + "    c.search_ext_s('dc=x', ldap.SCOPE_ONELEVEL, filterstr='(uid=' + u + ')')\n"
    )
    assert "py.ldap.injection" not in ids(python_ldap + "    c.search_s('dc=x', ldap.SCOPE_ONELEVEL, '(uid=admin)')\n")
    no_library = "from flask import request\ndef f(index):\n    return index.search('docs', request.args['q'])\n"
    assert "py.ldap.injection" not in ids(no_library)


def test_xpath_compiled_and_beautifulsoup() -> None:
    compiled = "from lxml import etree\ndef view(request):\n    return etree.XPath(\"//a[@id='\" + request.GET['i'] + \"']\")\n"
    assert "py.xpath.injection" in ids(compiled)
    soup = "import xml.etree.ElementTree as ET\nimport bs4\nfrom flask import request\ndef f(s):\n    return s.find(f\"div[@id='{request.args['i']}']\")\n"
    assert "py.xpath.injection" not in ids(soup)
    regex = "import re\nimport xml.etree.ElementTree as ET\nfrom flask import request\ndef f(t):\n    return re.findall(f'[{request.args[\"c\"]}]', t)\n"
    assert "py.xpath.injection" not in ids(regex)


# ----- cookies and sessions


def test_cookie_severity_and_cwe() -> None:
    base = "from flask import make_response\nr = make_response('')\n"
    missing = only(base + "r.set_cookie('sid', 'v')\n", "py.cookie.insecure")
    assert missing.severity == "low" and missing.cwe is None and "no secure and no httponly" in missing.message
    disabled = only(base + "r.set_cookie('sid', 'v', secure=False, httponly=True)\n", "py.cookie.insecure")
    assert disabled.severity is None  # the rule default, medium
    httponly_only = only(base + "r.set_cookie('sid', 'v', secure=True)\n", "py.cookie.insecure")
    assert httponly_only.cwe == "CWE-1004"
    configured = base + "def f(cfg):\n    r.set_cookie('sid', 'v', secure=cfg.secure, httponly=cfg.httponly)\n"
    assert "py.cookie.insecure" not in ids(configured)
    no_framework = "def f(jar):\n    jar.set_cookie('sid', 'v')\n"
    assert "py.cookie.insecure" not in ids(no_framework)


def test_session_storage_of_request_data() -> None:
    starlette = "def f(request):\n    request.session['theme'] = request.GET['theme']\n"
    hit = only(starlette, "py.trust_boundary.session")
    assert hit.trace[-1].note == "reaches session[...]"
    derived = "from flask import request, session\ndef f(user):\n    session['uid'] = user.id\n"
    assert "py.trust_boundary.session" not in ids(derived)
    local_dict = "from flask import request\ndef f():\n    session = {}\n    session['x'] = request.args['x']\n"
    assert "py.trust_boundary.session" not in ids(local_dict)


# ----- soundness: what stops a value from being constant


@pytest.mark.parametrize(
    "body",
    [
        "c = []\n    c.append(request.args['x'])\n    subprocess.run(' '.join(c), shell=True)",
        "c = ['ls']\n    c.append(request.args['x'])\n    subprocess.run(c, shell=True)",
        "c = set()\n    c.add(request.args['x'])\n    subprocess.run(str(c), shell=True)",
        "c = []\n    fill(c)\n    subprocess.run(' '.join(c), shell=True)",
        "c = 'ls'\n    del c\n    subprocess.run(c, shell=True)",
        "c = 'ls'\n    import shutil as c\n    subprocess.run(c, shell=True)",
        "c = 'ls'\n    try:\n        pass\n    except Exception as c:\n        pass\n    subprocess.run(str(c), shell=True)",
        "c = 'ls'\n    match request.args.getlist('x'):\n        case [c]:\n            pass\n    subprocess.run(c, shell=True)",
        "c = 'ls'\n    def g():\n        nonlocal c\n        c = request.args['x']\n    g()\n    subprocess.run(c, shell=True)",
    ],
)
def test_changed_or_rebound_names_are_not_constant(body: str) -> None:
    source = FLASK + f"def f():\n    {body}\n"
    assert "py.subprocess.shell_true" in ids(source)


def test_a_global_rebound_in_a_function_is_not_constant() -> None:
    source = FLASK + (
        "CMD = 'ls'\ndef configure():\n    global CMD\n    CMD = request.args['c']\n"
        "def run():\n    subprocess.run(CMD, shell=True)\n"
    )
    assert "py.subprocess.shell_true" in ids(source)


def test_comprehension_variables_do_not_leak() -> None:
    source = FLASK + "def f(items):\n    c = 'ls'\n    names = [c for c in items]\n    subprocess.run(c, shell=True)\n"
    assert hits(source) == []


@pytest.mark.parametrize("loop", ["for i in items:", "while items:"])
@pytest.mark.parametrize("jump", ["break", "continue"])
def test_break_and_continue_carry_their_state_out_of_the_branch(loop: str, jump: str) -> None:
    source = FLASK + (
        f"def f(items):\n    c = 'ls'\n    {loop}\n        if items:\n            c = request.args['x']\n"
        f"            {jump}\n        c = 'ls'\n    subprocess.run(c, shell=True)\n"
    )
    hit = only(source, "py.subprocess.shell_true")
    assert hit.trace[0].note == "flask request.args (source)"


def test_guard_with_continue_still_cleans_the_rest_of_the_loop_body() -> None:
    source = FLASK + (
        "def f():\n    for n in request.args.getlist('n'):\n        p = os.path.realpath(os.path.join('/d', n))\n"
        "        if not p.startswith('/d/'):\n            continue\n        open(p)\n"
    )
    assert hits(source) == []
