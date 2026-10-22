# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Round-2 JavaScript and TypeScript rule changes (judged on the tuning data, see docs/benchmarks/cvefixes.md): a
positive and a negative case for every kept change."""

import textwrap

import pytest

from kestrix_scan.js_rules import check_js
from kestrix_scan.registry import Hit


def hits(source: str, rel: str = "app.js") -> list[Hit]:
    result = check_js(textwrap.dedent(source), rel)
    assert isinstance(result, list), result
    return result


def ids(source: str, rel: str = "app.js") -> set[str]:
    return {hit.rule_id for hit in hits(source, rel)}


# ----- r2.1 the request target and the hapi payload are sources


@pytest.mark.parametrize(
    "source",
    [
        "const fs = require('fs'), path = require('path');\n"
        "require('http').createServer((req, res) => {\n"
        "  fs.readFile(path.join(ROOT, req.url), (e, d) => res.end(d));\n"
        "});",
        "app.get('/f', (req, res) => { res.sendFile(req.originalUrl) });",
        "const fs = require('fs');\nserver.route({ handler: (request, h) => fs.readFileSync(request.payload.name) });",
        "const fs = require('fs');\nrouter.get('/f', async (ctx) => { ctx.body = fs.readFileSync(ctx.path) });",
        "const fs = require('fs');\nrouter.post('/f', async (ctx) => { ctx.body = fs.readFileSync(ctx.request.url) });",
    ],
)
def test_request_target_and_payload_are_sources(source: str) -> None:
    assert "js.path.traversal" in ids(source)


@pytest.mark.parametrize(
    "source",
    [
        "const fs = require('fs'), path = require('path');\n"
        "http.createServer((req, res) => { fs.readFile(path.basename(req.url), cb) });",
        "const fs = require('fs');\nhttp.createServer((req, res) => { fs.readFile('/srv/index.html', cb) });",
        "const fs = require('fs');\nfunction f(file) { fs.readFile(file.url, cb) }",  # `file` is not a request name
    ],
)
def test_request_target_negatives(source: str) -> None:
    assert "js.path.traversal" not in ids(source)


# ----- r2.2 more file-system sinks


@pytest.mark.parametrize(
    "call",
    [
        "fs.readdir(req.query.d, cb)",
        "fs.statSync(req.query.d)",
        "fs.existsSync(req.query.d)",
        "fs.mkdirSync(req.body.d)",
        "fs.rename(req.query.a, '/srv/x', cb)",
        "fs.rename('/srv/x', req.query.b, cb)",
        "fs.copyFile('/srv/x', req.body.dest, cb)",
        "fsx.remove(req.query.d)",
        "fsx.copy('/srv/x', req.body.dest)",
    ],
)
def test_more_file_system_sinks(call: str) -> None:
    source = f"const fs = require('fs');\nconst fsx = require('fs-extra');\napp.post('/x', (req, res) => {{ {call} }});"
    assert "js.path.traversal" in ids(source)


@pytest.mark.parametrize(
    "call",
    [
        "fs.readdir('/srv/uploads', cb)",
        "fs.readdir(path.basename(req.query.d), cb)",
        "fs.statSync(Number(req.query.d))",
        "fs.rename('/srv/a', '/srv/b', cb)",
    ],
)
def test_file_system_sinks_need_tainted_paths(call: str) -> None:
    source = f"const fs = require('fs');\nconst path = require('path');\napp.post('/x', (req, res) => {{ {call} }});"
    assert "js.path.traversal" not in ids(source)


# ----- r2.3 more redirect sinks


@pytest.mark.parametrize(
    "call",
    [
        "res.location(req.query.next)",
        "res.setHeader('Location', req.query.next)",
        "res.header('location', req.query.next)",
        "res.writeHead(302, { Location: req.query.next })",
    ],
)
def test_more_redirect_sinks(call: str) -> None:
    assert "js.redirect.open" in ids(f"app.get('/go', (req, res) => {{ {call}; res.end() }});")


@pytest.mark.parametrize(
    "call",
    [
        "res.location('/home')",
        "res.setHeader('Content-Type', req.query.t)",
        "res.setHeader('Location', 'https://example.com/' + req.query.p)",  # a fixed scheme and host
        "res.writeHead(200, { 'X-Next': req.query.next })",
    ],
)
def test_redirect_sink_negatives(call: str) -> None:
    assert "js.redirect.open" not in ids(f"app.get('/go', (req, res) => {{ {call}; res.end() }});")


# ----- r2.4 a shell started with -c, and the shell helpers of shelljs and execa


@pytest.mark.parametrize(
    "source",
    [
        "const cp = require('child_process');\nfunction f(x) { cp.spawn('sh', ['-c', `ls ${x}`]) }",
        "const cp = require('child_process');\nfunction f(x) { cp.execFile('/bin/bash', ['-c', 'cat ' + x]) }",
        "const cp = require('child_process');\nfunction f(x) { cp.spawnSync('cmd.exe', ['/c', `dir ${x}`]) }",
        "const shell = require('shelljs');\nfunction f(x) { shell.exec(`git log ${x}`) }",
        "const execa = require('execa');\nasync function f(x) { await execa.command(`ls ${x}`) }",
    ],
)
def test_shell_script_and_helpers(source: str) -> None:
    assert "js.child_process.shell" in ids(source)


@pytest.mark.parametrize(
    "source",
    [
        "const cp = require('child_process');\nfunction f(x) { cp.spawn('sh', ['-c', 'ls /srv']) }",  # a fixed script
        "const cp = require('child_process');\nfunction f(x) { cp.spawn('ls', ['-l', x]) }",  # no shell
        "const cp = require('child_process');\nfunction f(x) { cp.spawn('sh', [x]) }",  # no -c
        "const shell = require('shelljs');\nfunction f(x) { shell.exec('git status') }",
    ],
)
def test_shell_script_negatives(source: str) -> None:
    assert "js.child_process.shell" not in ids(source)
