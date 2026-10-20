# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""js.* rules: a positive and a negative case for every shape each rule covers."""

import textwrap

import pytest

from kestrix_scan.js_rules import check_js, secret_name
from kestrix_scan.registry import RULES, Hit

EXPRESS = "const express = require('express');\nconst app = express();\n"


def hits(source: str, rel: str = "app.js") -> list[Hit]:
    result = check_js(textwrap.dedent(source), rel)
    assert isinstance(result, list), result
    return result


def ids(source: str, rel: str = "app.js") -> set[str]:
    return {hit.rule_id for hit in hits(source, rel)}


def only(source: str, rule_id: str, rel: str = "app.js") -> Hit:
    found = [hit for hit in hits(source, rel) if hit.rule_id == rule_id]
    assert len(found) == 1, found
    return found[0]


POSITIVE = [
    # js.exec.eval
    ("js.exec.eval", "function f(x) { return eval(x) }"),
    ("js.exec.eval", "function f(x) { return window.eval('(' + x + ')') }"),
    ("js.exec.eval", "const f = new Function('a', body)"),
    ("js.exec.eval", "const f = Function(src)"),
    ("js.exec.eval", "function f(id) { setTimeout(`load(${id})`, 10) }"),
    ("js.exec.eval", "function f(n) { const code = 'run(' + n + ')'; setInterval(code, 100) }"),
    ("js.exec.eval", "setTimeout('tick()', 10)"),
    # js.child_process.shell
    ("js.child_process.shell", "const cp = require('child_process');\nfunction f(h) { cp.exec(`ping ${h}`) }"),
    (
        "js.child_process.shell",
        "const { execSync: run } = require('node:child_process');\nfunction f(h) { run('ls ' + h) }",
    ),
    ("js.child_process.shell", "import { exec } from 'child_process';\nexport function f(h) { exec(`git log ${h}`) }"),
    (
        "js.child_process.shell",
        "import * as cp from 'node:child_process';\nconst f = (h) => cp.execSync('rm -rf ' + h);",
    ),
    ("js.child_process.shell", "import cp from 'child_process';\nfunction f(h) { cp.exec(`x ${h}`) }"),
    ("js.child_process.shell", "const exec = require('child_process').exec;\nfunction f(h) { exec(`x ${h}`) }"),
    (
        "js.child_process.shell",
        "const util = require('util');\nconst { exec } = require('child_process');\n"
        "const execP = util.promisify(exec);\nasync function f(h) { await execP(`ls ${h}`) }",
    ),
    ("js.child_process.shell", "const cp = require('child_process');\nconst run = cp.execSync;\nrun(`a ${b}`)"),
    (
        "js.child_process.shell",
        "const { spawn } = require('child_process');\nfunction f(c) { spawn(c, { shell: true }) }",
    ),
    (
        "js.child_process.shell",
        "const { spawn } = require('child_process');\nfunction f(a) { spawn('git', ['log', a], { shell: true }) }",
    ),
    (
        "js.child_process.shell",
        "const { execFile } = require('child_process');\nconst opts = { shell: true };\nfunction f(c) { execFile(c, [], opts) }",
    ),
    ("js.child_process.shell", "const { exec } = await import('node:child_process');\nexec(`x ${y}`)"),
    # js.dom.xss_sink
    ("js.dom.xss_sink", "function f(el, v) { el.innerHTML = v }"),
    ("js.dom.xss_sink", "function f(el, v) { el.outerHTML = `<b>${v}</b>` }"),
    ("js.dom.xss_sink", "function f(el, v) { el.innerHTML += v }"),
    ("js.dom.xss_sink", "function f(v) { document.querySelector('#o')?.insertAdjacentHTML('beforeend', v) }"),
    ("js.dom.xss_sink", "function f(v) { document.write(v) }"),
    ("js.dom.xss_sink", "function f(v) { document.writeln('<p>' + v) }"),
    ("js.dom.xss_sink", "function f(d) { $('#out').html(d.name) }"),
    ("js.dom.xss_sink", "function f(d) { jQuery('.x').first().html(d) }"),
    ("js.dom.xss_sink", "function f($el, d) { $el.html(d) }"),
    ("js.dom.xss_sink", "export const A = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;"),
    (
        "js.dom.xss_sink",
        "const markup = { __html: body };\nexport const A = () => <div dangerouslySetInnerHTML={markup} />;",
    ),
    ("js.dom.xss_sink", "React.createElement('div', { dangerouslySetInnerHTML: { __html: props.body } })"),
    # js.sql.string_built
    ("js.sql.string_built", "async function f(id) { return pool.query(`SELECT * FROM users WHERE id = ${id}`) }"),
    ("js.sql.string_built", "function f(n) { db.query('DELETE FROM t WHERE name = \"' + n + '\"') }"),
    ("js.sql.string_built", "function f(id) { return knex.raw(`select * from t where id = ${id}`) }"),
    ("js.sql.string_built", "function f(id) { return sequelize.query('SELECT a FROM t WHERE b = ' + id) }"),
    ("js.sql.string_built", "function f(id) { return conn.execute(`UPDATE t SET a = ${id}`) }"),
    ("js.sql.string_built", "function f(id) { const q = `SELECT a FROM t WHERE b = ${id}`; return db.query(q) }"),
    (
        "js.sql.string_built",
        "const BASE = 'SELECT * FROM users WHERE id = ';\nfunction f(id) { return db.query(BASE + id) }",
    ),
    ("js.sql.string_built", "function f(id) { return prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${id}`) }"),
    # js.tls.reject_unauthorized
    ("js.tls.reject_unauthorized", "const agent = new https.Agent({ rejectUnauthorized: false });"),
    ("js.tls.reject_unauthorized", "tls.connect({ host, port, 'rejectUnauthorized': false })"),
    ("js.tls.reject_unauthorized", "options.rejectUnauthorized = false;"),
    ("js.tls.reject_unauthorized", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"),
    ("js.tls.reject_unauthorized", "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = \"0\";"),
    ("js.tls.reject_unauthorized", "spawn('node', ['a.js'], { env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' } })"),
    # js.crypto.weak_hash
    (
        "js.crypto.weak_hash",
        "const crypto = require('crypto');\nconst h = crypto.createHash('md5').update(x).digest('hex');",
    ),
    ("js.crypto.weak_hash", "import { createHash } from 'node:crypto';\ncreateHash('sha1')"),
    ("js.crypto.weak_hash", "import * as c from 'crypto';\nc.createHash('SHA-1')"),
    # js.crypto.insecure_random
    ("js.crypto.insecure_random", "const resetToken = Math.random().toString(36).slice(2);"),
    ("js.crypto.insecure_random", "function generateToken() { return Math.random().toString(36) }"),
    ("js.crypto.insecure_random", "user.sessionSecret = Math.random() * 1e9"),
    ("js.crypto.insecure_random", "const creds = { apiKey: Math.floor(Math.random() * 1e16) };"),
    ("js.crypto.insecure_random", "let otp;\notp = String(Math.floor(Math.random() * 1e6));"),
    # js.jwt.no_verify
    ("js.jwt.no_verify", "const jwt = require('jsonwebtoken');\njwt.verify(t, k, { algorithms: ['none', 'HS256'] })"),
    ("js.jwt.no_verify", "import jwt from 'jsonwebtoken';\njwt.verify(t, k, { ignoreExpiration: true })"),
    (
        "js.jwt.no_verify",
        "import { verify } from 'jsonwebtoken';\nconst o = { algorithms: ['None'] };\nverify(t, k, o, cb)",
    ),
    # js.path.traversal
    (
        "js.path.traversal",
        "const fs = require('fs');\napp.get('/f', (req, res) => { fs.readFile(req.query.name, cb) })",
    ),
    (
        "js.path.traversal",
        "const fs = require('fs');\nconst path = require('path');\napp.get('/f/:n', (req, res) => {\n"
        "  const p = path.join(__dirname, 'files', req.params.n)\n  fs.createReadStream(p).pipe(res)\n})",
    ),
    (
        "js.path.traversal",
        "const path = require('path');\napp.get('/f', (req, res) => res.sendFile(path.join(DIR, req.query.f)))",
    ),
    ("js.path.traversal", "app.get('/f', (req, res) => { res.download(req.query.f) })"),
    (
        "js.path.traversal",
        "import { readFile } from 'node:fs/promises';\nexport async function h(req, res) {\n"
        "  const { file } = req.body;\n  res.send(await readFile(`/data/${file}`))\n}",
    ),
    (
        "js.path.traversal",
        "const fs = require('fs');\napp.post('/u', (req, res) => { fs.writeFileSync(req.body.to, data) })",
    ),
    # js.ssrf.request
    ("js.ssrf.request", "app.get('/p', async (req, res) => { const r = await fetch(req.query.url) })"),
    (
        "js.ssrf.request",
        "import axios from 'axios';\nrouter.post('/p', async (req, res) => { await axios.get(req.body.target) })",
    ),
    (
        "js.ssrf.request",
        "import axios from 'axios';\napp.get('/p', async (req, res) => { await axios({ url: req.query.u }) })",
    ),
    ("js.ssrf.request", "const got = require('got');\napp.get('/p', async (req, res) => { await got(req.query.u) })"),
    ("js.ssrf.request", "const https = require('https');\napp.get('/p', (req, res) => { https.get(req.query.u, cb) })"),
    ("js.ssrf.request", "app.get('/p', async (req, res) => { const u = new URL(req.query.u); await fetch(u) })"),
    ("js.ssrf.request", "app.get('/p', async (req, res) => { await fetch('https://' + req.query.host + '/x') })"),
    # js.redirect.open
    ("js.redirect.open", "app.get('/l', (req, res) => res.redirect(req.query.next))"),
    ("js.redirect.open", "app.get('/l', (req, res) => { const n = req.query.next; res.redirect(302, n) })"),
    ("js.redirect.open", "router.get('/r', async (ctx) => { ctx.redirect(ctx.query.next) })"),
    ("js.redirect.open", "app.get('/l', (req, res) => res.redirect(req.get('referer')))"),
    # js.proto.pollution
    (
        "js.proto.pollution",
        "app.post('/s', (req, res) => { for (const key in req.body) { settings[key] = req.body[key] } })",
    ),
    ("js.proto.pollution", "app.post('/s', (req, res) => { const { a, b, v } = req.body; cfg[a][b] = v })"),
    (
        "js.proto.pollution",
        "app.post('/x', (req, res) => { for (const [k, v] of Object.entries(req.body)) { target[k][v.name] = v.value } })",
    ),
    (
        "js.proto.pollution",
        "app.post('/x', (req, res) => { Object.keys(req.body).forEach((k) => { obj[k] = req.body[k] }) })",
    ),
    ("js.proto.pollution", "const _ = require('lodash');\napp.post('/m', (req, res) => { _.merge(config, req.body) })"),
    (
        "js.proto.pollution",
        "import merge from 'lodash/merge';\napp.post('/m', (req, res) => { merge({}, defaults, req.body) })",
    ),
    (
        "js.proto.pollution",
        "import { defaultsDeep } from 'lodash-es';\napp.post('/m', (req, res) => { defaultsDeep(cfg, req.body) })",
    ),
    # js.cors.wildcard_credentials
    (
        "js.cors.wildcard_credentials",
        "const cors = require('cors');\napp.use(cors({ origin: true, credentials: true }))",
    ),
    ("js.cors.wildcard_credentials", "import cors from 'cors';\napp.use(cors({ credentials: true, origin: '*' }))"),
    (
        "js.cors.wildcard_credentials",
        "app.use((req, res, next) => {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n"
        "  res.setHeader('Access-Control-Allow-Credentials', 'true');\n  next()\n})",
    ),
    (
        "js.cors.wildcard_credentials",
        "export function GET() {\n  return new Response('x', { headers: {\n"
        "    'Access-Control-Allow-Origin': '*',\n    'Access-Control-Allow-Credentials': 'true' } })\n}",
    ),
]

NEGATIVE = [
    # js.exec.eval: literals, functions passed to timers, methods that are not the global eval
    ("js.exec.eval", "eval('1 + 1'); const C = 'x'; eval(C + 'y')"),
    ("js.exec.eval", "setTimeout(tick, 10); setInterval(() => go(), 5); setTimeout(function () {}, 1)"),
    ("js.exec.eval", "const o = { eval: 1 }; o.eval(x); mongo.eval(code)"),
    ("js.exec.eval", "function eval2(x) { return x }\nconst eval = (x) => x;\neval(input)"),
    ("js.exec.eval", "class R {\n  eval(x: string): string {\n    return x;\n  }\n}"),
    ("js.exec.eval", "// eval(userInput) would be bad\nconst s = 'eval(x)';"),
    ("js.exec.eval", "const f = new Function('a', 'return a + 1')"),
    # js.child_process.shell: literal commands, argument arrays, other exec methods
    ("js.child_process.shell", "const { exec } = require('child_process'); exec('ls -la')"),
    (
        "js.child_process.shell",
        "const { execFile } = require('child_process');\nfunction f(a) { execFile('git', ['log', a]) }",
    ),
    (
        "js.child_process.shell",
        "const { spawn } = require('child_process');\nfunction f(a) { spawn('git', ['log', a]) }",
    ),
    ("js.child_process.shell", "const { spawn } = require('child_process');\nspawn('ls', ['-la'], { shell: true })"),
    ("js.child_process.shell", "function f(h) { regex.exec(`${h}`); db.exec(`x ${h}`) }"),
    ("js.child_process.shell", "const { exec } = require('child_process');\nfunction f(cmd) { exec(cmd) }"),
    (
        "js.child_process.shell",
        "const CMD = 'npm test';\nconst { exec } = require('child_process');\nexec(`${CMD} --ci`)",
    ),
    # js.dom.xss_sink: literals, text sinks, sanitizers, unrelated .html methods
    ("js.dom.xss_sink", "el.innerHTML = ''; el.innerHTML = '<b>x</b>'; const T = '<i>'; el.innerHTML = T"),
    ("js.dom.xss_sink", "function f(el, v) { el.textContent = v; el.innerText = v }"),
    ("js.dom.xss_sink", "import DOMPurify from 'dompurify';\nfunction f(v) { el.innerHTML = DOMPurify.sanitize(v) }"),
    ("js.dom.xss_sink", "function f(v) { el.innerHTML = escapeHtml(v) }"),
    ("js.dom.xss_sink", "if (el.innerHTML == v) {} const same = el.innerHTML === v"),
    ("js.dom.xss_sink", "export const A = () => <div dangerouslySetInnerHTML={{ __html: '<b>x</b>' }} />;"),
    ("js.dom.xss_sink", "function f(v) { res.html(v); template.html(v) }"),
    ("js.dom.xss_sink", "const html = el.innerHTML;"),
    # js.sql.string_built: parameters, tagged templates, no SQL text, literal templates
    ("js.sql.string_built", "function f(id) { return pool.query('SELECT * FROM users WHERE id = $1', [id]) }"),
    (
        "js.sql.string_built",
        "import sql from 'slonik';\nfunction f(id) { return pool.query(sql`SELECT * FROM t WHERE id = ${id}`) }",
    ),
    (
        "js.sql.string_built",
        "import postgres from 'postgres';\nconst sql = postgres();\nfunction f(id) { return sql`SELECT * FROM t WHERE id = ${id}` }",
    ),
    ("js.sql.string_built", "function f(id) { return knex.raw('select * from t where id = ?', [id]) }"),
    ("js.sql.string_built", "const T = 'users';\nfunction f() { return db.query(`SELECT * FROM ${T} WHERE a = 1`) }"),
    ("js.sql.string_built", "function f(id) { return client.query(`query { user(id: ${id}) { name } }`) }"),
    ("js.sql.string_built", "function f(s) { return document.querySelector(`#${s}`) }"),
    # js.tls.reject_unauthorized
    ("js.tls.reject_unauthorized", "const agent = new https.Agent({ rejectUnauthorized: true });"),
    ("js.tls.reject_unauthorized", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';"),
    ("js.tls.reject_unauthorized", "if (opts.rejectUnauthorized === false) warn()"),
    ("js.tls.reject_unauthorized", "const strict = { rejectUnauthorized: isProd };"),
    # js.crypto.weak_hash
    ("js.crypto.weak_hash", "const crypto = require('crypto');\ncrypto.createHash('sha256')"),
    ("js.crypto.weak_hash", "function createHash(a) {}\ncreateHash('md5')"),
    ("js.crypto.weak_hash", "const crypto = require('crypto');\ncrypto.createHmac('md5', key)"),
    # js.crypto.insecure_random: React keys, non-secret names, crypto APIs
    (
        "js.crypto.insecure_random",
        "items.map(i => <li key={Math.random()}>{i}</li>);\nconst o = { key: Math.random() };",
    ),
    ("js.crypto.insecure_random", "const jitter = Math.random() * 100; const cacheKey = Math.random();"),
    ("js.crypto.insecure_random", "const token = crypto.randomUUID(); const salt = crypto.randomBytes(16);"),
    ("js.crypto.insecure_random", "const queryKey = ['x', Math.random()];"),
    # js.jwt.no_verify
    ("js.jwt.no_verify", "import jwt from 'jsonwebtoken';\njwt.verify(t, k, { algorithms: ['RS256'] })"),
    ("js.jwt.no_verify", "import jwt from 'jsonwebtoken';\njwt.verify(t, k, { ignoreExpiration: false })"),
    ("js.jwt.no_verify", "import jwt from 'jsonwebtoken';\nconst header = jwt.decode(t, { complete: true }).header;"),
    ("js.jwt.no_verify", "other.verify(t, k, { algorithms: ['none'] })"),
    # js.path.traversal: basename, guards, sendFile root, not request data
    (
        "js.path.traversal",
        "const fs = require('fs');\nconst path = require('path');\n"
        "app.get('/f/:n', (req, res) => { fs.readFile(path.join(DIR, path.basename(req.params.n)), cb) })",
    ),
    (
        "js.path.traversal",
        "const fs = require('fs');\nconst path = require('path');\napp.get('/f', (req, res) => {\n"
        "  const p = path.resolve(ROOT, req.query.f);\n  if (!p.startsWith(ROOT + path.sep)) return res.sendStatus(403);\n"
        "  fs.readFile(p, cb)\n})",
    ),
    (
        "js.path.traversal",
        "const fs = require('fs');\nconst path = require('path');\napp.get('/f', (req, res) => {\n"
        "  const p = path.join(ROOT, req.query.f);\n  const rel = path.relative(ROOT, p);\n"
        "  if (rel.startsWith('..')) return;\n  fs.readFile(p, cb)\n})",
    ),
    ("js.path.traversal", "app.get('/f', (req, res) => { res.sendFile(req.query.f, { root: DIR }) })"),
    ("js.path.traversal", "const fs = require('fs');\nfunction load(name) { return fs.readFileSync(name) }"),
    (
        "js.path.traversal",
        "const fs = require('fs');\napp.get('/f', (req, res) => { fs.readFile(String(Number(req.query.n)), cb) })",
    ),
    ("js.path.traversal", "const fs = require('fs');\nconst req = { query: {} };\nfs.readFile(req.query.f, cb)"),
    # js.ssrf.request: fixed scheme and host, not request data
    (
        "js.ssrf.request",
        "app.get('/p', async (req, res) => { await fetch(`https://api.example.com/items/${req.query.id}`) })",
    ),
    (
        "js.ssrf.request",
        "app.get('/p', async (req, res) => { await fetch('https://api.example.com/q?s=' + req.query.s) })",
    ),
    ("js.ssrf.request", "async function load(url) { return fetch(url) }"),
    (
        "js.ssrf.request",
        "import axios from 'axios';\napp.get('/p', async (req, res) => { await axios({ method: 'get' }) })",
    ),
    ("js.ssrf.request", "app.get('/p', async (req, res) => { await fetch('/api/items', { body: req.body }) })"),
    # js.redirect.open: local paths, allowlists, fixed hosts
    ("js.redirect.open", "app.get('/l', (req, res) => res.redirect('/home/' + req.query.next))"),
    ("js.redirect.open", "const P = { a: '/a' };\napp.get('/l', (req, res) => res.redirect(P[req.query.n] ?? '/'))"),
    ("js.redirect.open", "app.get('/l', (req, res) => res.redirect(req.query.ok ? '/a' : '/b'))"),
    ("js.redirect.open", "app.get('/l', (req, res) => res.redirect(`https://example.com/${req.query.p}`))"),
    ("js.redirect.open", "function go(url) { res.redirect(url) }"),
    # js.proto.pollution: guards, allowlists, counters, Maps and null-prototype objects
    (
        "js.proto.pollution",
        "app.post('/s', (req, res) => { for (const key in req.body) { if (key === '__proto__') continue; settings[key] = req.body[key] } })",
    ),
    (
        "js.proto.pollution",
        "const OK = new Set(['a']);\napp.post('/s', (req, res) => { for (const k in req.body) { if (OK.has(k)) s[k] = req.body[k] } })",
    ),
    ("js.proto.pollution", "app.get('/c', (req, res) => { counts[req.query.cat] = (counts[req.query.cat] || 0) + 1 })"),
    (
        "js.proto.pollution",
        "app.post('/s', (req, res) => { const store = Object.create(null); for (const k in req.body) { store[k] = req.body[k] } })",
    ),
    ("js.proto.pollution", "const _ = require('lodash');\napp.post('/m', (req, res) => { _.merge(config, defaults) })"),
    ("js.proto.pollution", "app.post('/m', (req, res) => { Object.assign(config, req.body) })"),
    ("js.proto.pollution", "function f(obj, key, v) { obj[key] = v }"),
    # js.cors.wildcard_credentials
    (
        "js.cors.wildcard_credentials",
        "const cors = require('cors');\napp.use(cors({ origin: ['https://a.example'], credentials: true }))",
    ),
    ("js.cors.wildcard_credentials", "const cors = require('cors');\napp.use(cors({ origin: '*' }))"),
    (
        "js.cors.wildcard_credentials",
        "app.use((req, res, next) => { res.setHeader('Access-Control-Allow-Origin', '*'); next() })",
    ),
    (
        "js.cors.wildcard_credentials",
        "app.use((req, res, next) => {\n  res.setHeader('Access-Control-Allow-Origin', 'https://a.example');\n"
        "  res.setHeader('Access-Control-Allow-Credentials', 'true');\n  next()\n})",
    ),
]


@pytest.mark.parametrize(("rule_id", "source"), POSITIVE, ids=[f"{r}-{i}" for i, (r, _) in enumerate(POSITIVE)])
def test_positive(rule_id: str, source: str) -> None:
    assert rule_id in ids(source, "app.jsx")


@pytest.mark.parametrize(("rule_id", "source"), NEGATIVE, ids=[f"{r}-{i}" for i, (r, _) in enumerate(NEGATIVE)])
def test_negative(rule_id: str, source: str) -> None:
    assert rule_id not in ids(source, "app.tsx" if ": string" in source else "app.jsx")


def test_every_js_rule_has_positive_and_negative_cases() -> None:
    js_rules = {rule.id for rule in RULES.values() if rule.language == "javascript"}
    positive = {rule_id for rule_id, _ in POSITIVE} | {"js.llm.output_to_sink"}
    negative = {rule_id for rule_id, _ in NEGATIVE} | {"js.llm.output_to_sink"}
    assert js_rules == positive == negative


# ----- severities, confidence and traces


def test_xss_is_medium_without_a_url_source_and_high_with_one() -> None:
    assert only("function f(el, v) { el.innerHTML = v }", "js.dom.xss_sink").severity == "medium"
    source = """
    const q = new URLSearchParams(location.search).get('q');
    document.getElementById('o').innerHTML = q;
    """
    hit = only(source, "js.dom.xss_sink")
    assert hit.severity is None  # the rule default, high
    assert hit.confidence == "high"
    assert [step.line for step in hit.trace] == [2, 2, 3]
    assert "location" in hit.message


@pytest.mark.parametrize(
    "source",
    [
        "function f() { out.innerHTML = `<p>${window.location.hash.slice(1)}</p>` }",
        "document.write(document.URL)",
        "el.innerHTML = window.name",
        "window.addEventListener('message', (e) => { box.innerHTML = e.data.html })",
        "self.onmessage = function (ev) { panel.insertAdjacentHTML('beforeend', ev.data) }",
        "import { useSearchParams } from 'react-router-dom';\nexport function P() {\n"
        "  const [params] = useSearchParams();\n  return <div dangerouslySetInnerHTML={{ __html: params.get('q') }} />;\n}",
    ],
)
def test_dom_sources_raise_xss_to_high(source: str) -> None:
    hit = only(source, "js.dom.xss_sink", "app.tsx")
    assert hit.severity is None and hit.confidence == "high"


def test_a_message_listener_parameter_elsewhere_is_not_a_source() -> None:
    source = "function show(e) { box.innerHTML = e.data }"
    assert only(source, "js.dom.xss_sink").severity == "medium"


def test_shadowed_location_is_not_a_source() -> None:
    source = "function f(location) { el.innerHTML = location.search }"
    assert only(source, "js.dom.xss_sink").severity == "medium"


def test_timer_with_a_fixed_string_is_low() -> None:
    assert only("setTimeout('tick()', 10)", "js.exec.eval").severity == "low"
    assert only("function f(i) { setTimeout('tick(' + i + ')', 10) }", "js.exec.eval").severity is None


def test_jwt_ignore_expiration_is_low_and_none_algorithm_high() -> None:
    assert (
        only(
            "import jwt from 'jsonwebtoken';\njwt.verify(t, k, { ignoreExpiration: true })", "js.jwt.no_verify"
        ).severity
        == "low"
    )
    assert (
        only("import jwt from 'jsonwebtoken';\njwt.verify(t, k, { algorithms: ['none'] })", "js.jwt.no_verify").severity
        is None
    )


def test_request_data_reaching_a_pattern_sink_adds_a_trace() -> None:
    source = (
        EXPRESS
        + "const { exec } = require('child_process');\napp.get('/', (req, res) => {\n  const c = req.query.cmd;\n  exec(c);\n});"
    )
    hit = only(source, "js.child_process.shell")
    assert hit.confidence == "high"
    assert [(step.line, step.note) for step in hit.trace] == [
        (5, "Express req.query (source)"),
        (5, "assigned to c"),
        (6, "reaches exec()"),
    ]
    assert "Express req.query (line 5)" in hit.message


def test_request_sources_need_a_parameter_named_req() -> None:
    source = "const fs = require('fs');\nconst req = loadConfig();\nfs.readFile(req.query.file, cb)"
    assert "js.path.traversal" not in ids(source)


def test_path_traversal_trace_follows_assignments() -> None:
    source = (
        "const fs = require('fs');\nconst path = require('path');\napp.get('/f/:n', (req, res) => {\n"
        "  const name = req.params.n;\n  const p = path.join(DIR, name);\n  fs.readFile(p, cb);\n});"
    )
    hit = only(source, "js.path.traversal")
    assert [step.line for step in hit.trace] == [4, 4, 5, 6]
    assert hit.message == "fs.readFile() receives a path taken from Express req.params (line 4)."


def test_an_unguarded_resolve_still_reports() -> None:
    source = (
        "const fs = require('fs');\nconst path = require('path');\napp.get('/f', (req, res) => {\n"
        "  const p = path.resolve(ROOT, req.query.f);\n  fs.readFile(p, cb);\n});"
    )
    assert "js.path.traversal" in ids(source)


def test_typescript_express_handler() -> None:
    source = """
    import express, { Request, Response } from 'express';
    import { readFile } from 'node:fs/promises';
    import path from 'node:path';
    const app = express();
    app.get('/file/:name', async (req: Request<{ name: string }>, res: Response): Promise<void> => {
      const name: string = req.params.name as string;
      const data = await readFile(path.join('/srv', name), 'utf8');
      res.send(data);
    });
    """
    assert only(source, "js.path.traversal", "server.ts").line == 8


def test_typescript_generic_call_is_still_a_call() -> None:
    source = "import axios from 'axios';\nexport async function p(req: any, res: any) {\n  await axios.get<string>(req.query.target);\n}"
    assert only(source, "js.ssrf.request", "proxy.ts").line == 3


# ----- LLM output


LLM_EVAL = """
import OpenAI from 'openai';
const openai = new OpenAI();
async function run(q) {
  const c = await openai.chat.completions.create({ model: 'x', messages: [{ role: 'user', content: q }] });
  const code = c.choices[0].message.content;
  return eval(code);
}
"""


def test_llm_output_to_eval_reports_the_llm_rule_instead() -> None:
    found = hits(LLM_EVAL)
    assert [hit.rule_id for hit in found] == ["js.llm.output_to_sink"]
    assert found[0].cwe == "CWE-94" and found[0].confidence == "high"
    assert [step.line for step in found[0].trace] == [5, 5, 6, 7]


@pytest.mark.parametrize(
    ("source", "cwe"),
    [
        (
            "import Anthropic from '@anthropic-ai/sdk';\nconst client = new Anthropic();\nasync function show() {\n"
            "  const msg = await client.messages.create({ model: 'm', max_tokens: 9, messages: [] });\n"
            "  out.innerHTML = msg.content[0].text;\n}",
            "CWE-79",
        ),
        (
            "import OpenAI from 'openai';\nimport { execSync } from 'child_process';\nconst openai = new OpenAI();\n"
            "async function run() {\n  const r = await openai.responses.create({ model: 'x', input: 'cmd' });\n"
            "  execSync(r.output_text);\n}",
            "CWE-78",
        ),
        (
            "import OpenAI from 'openai';\nimport { spawn } from 'child_process';\nconst ai = new OpenAI();\n"
            "async function run() {\n  const r = await ai.chat.completions.create({});\n"
            "  spawn(r.choices[0].message.content, []);\n}",
            "CWE-78",
        ),
    ],
)
def test_llm_output_to_html_and_shell(source: str, cwe: str) -> None:
    assert only(source, "js.llm.output_to_sink").cwe == cwe


def test_llm_sources_need_the_sdk_import() -> None:
    source = LLM_EVAL.replace("import OpenAI from 'openai';", "")
    assert ids(source) == {"js.exec.eval"}


def test_llm_output_through_a_parser_is_not_reported() -> None:
    source = LLM_EVAL.replace("return eval(code);", "return Number(code);")
    assert hits(source) == []


# ----- names and misc


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("resetToken", True),
        ("api_key", True),
        ("sessionSecret", True),
        ("PASSWORD", True),
        ("csrfToken", True),
        ("signingKey", True),
        ("key", False),
        ("cacheKey", False),
        ("queryKey", False),
        ("storageKey", False),
        ("monkey", False),
        ("tokenizer", False),
    ],
)
def test_secret_name(name: str, expected: bool) -> None:
    assert secret_name(name) is expected


def test_one_finding_per_rule_per_line() -> None:
    assert len(hits("function f(a, b) { el.innerHTML = a; el.innerHTML = b }")) == 1


def test_findings_point_at_the_sink() -> None:
    hit = only("function f(x) {\n  return   eval(x)\n}", "js.exec.eval")
    assert (hit.line, hit.column, hit.snippet) == (2, 12, "return   eval(x)")
