# Changelog

All notable changes to `kestrix-scan`. Rule ids and the JSON report (`schema_version`) are a stable
interface: renaming a rule or a report key is a breaking change and is recorded here.

## Unreleased

- **Install guard: typosquat warning.** A requested PyPI, npm, crates.io or Packagist package that is not popular but
  is a near-miss of a popular one (swapped, dropped, doubled or neighbouring-key letters, look-alike characters,
  removed separators, `python-`/`-js` affixes) and has no advisory now gets a non-blocking warning that names the
  likely package; known malware is still denied. Offline, from the bundled `popular_names.json` (top 5,000 names per
  ecosystem, refreshed by hand with `scripts/refresh_popular_names.py`); `install-allow` in `[tool.kestrix]` lists
  names it never flags. Measurements and limits: `docs/modules/code.md`.
- **Phase 1 of the language roadmap: the web stack (13 new rules, 73 in all; tuning numbers, not a held-out result).**
  - New files read: `.vue`, `.svelte`, `.html`, `.htm`, `.css`, `.scss` and `next.config.*`, with a bounded stdlib tag
    scanner (`html_tokens.py`, `web_rules.py`). `<script>` blocks of Vue, Svelte and HTML files go through the `js.*` rules
    with the file's line numbers, `<style>` blocks through the CSS rules. Suppress with `<!-- kestrix: ignore[id] reason -->`
    in markup (`//` and `/* */` in scripts, styles and CSS as before). New skipped directories: `.next`, `.nuxt`,
    `.svelte-kit`, `.output`, `.angular`. The Claude Code hook and plugin scan the new extensions too (the hook context still lists
    medium severity and above, so the low-severity web rules show up in scans and CI).
  - New rules: `vue.xss.v_html` (CWE-79), `svelte.xss.at_html` (CWE-79), `web.url.dynamic_scheme` (CWE-79, low unless the
    value reads the route), `html.inline.event_handler` and `html.url.javascript_scheme` (CWE-693, low),
    `html.link.target_blank` (CWE-1022, low), `html.form.http_action` (CWE-319, medium), `html.mixed.http_resource`
    (CWE-319, low), `html.angular.inner_html` (CWE-79, low), `css.import.http` (CWE-319, low), `css.expression.legacy`
    (CWE-79, low), `next.images.wildcard_host` (CWE-918, low) and `js.angular.bypass_trust` (CWE-79, `bypassSecurityTrust*`
    of a non-literal). A missing Content-Security-Policy is deliberately not reported.
  - Wider sources and sinks for existing rules: Next.js route-handler `params`/`searchParams`/`context.params`,
    `request.json()`/`formData()`/`text()`, server-action `FormData`, `redirect()`/`permanentRedirect()`/`NextResponse.redirect()`/
    `Response.redirect()` (open redirect), `useSearchParams()` from `next/navigation`; Koa `ctx.get()`, `ctx.headers`; NestJS `@Query()`,
    `@Body()`, `@Param()`, `@Headers()` parameters (and `@Req()` makes `req` a parameter); Fastify was covered. In
    `new URL(input, base)` only `input` carries taint (19 fewer alerts on the tuning data).
  - The registry grows from 60 to 73 rules; the SARIF rule list, the rules table, the provenance page, the fix playbook and the plugin's
    skill text list them. Rule ids of existing rules are unchanged.
  - Measured on the tuning data (docs/benchmarks/cvefixes.md, "Phase 1"): JavaScript and TypeScript detection 6.72% to 6.80%
    (+4 pairs), alerts +0.2%; `js.angular.bypass_trust` +3 pairs for 0 alerts, NestJS +1 for 1 alert, the `new URL`
    narrowing -19 alerts; the Next.js, Koa and request-body sources added no detection (+10 alerts together) and are kept
    because they were asked for. On 92 web-file pairs of CVE fixes (73 in scope) the web rules detect 27.4% [7.4, 50.9] (13 pairs by
    `vue.xss.v_html`), where the scanner detected none before. Scan speed on 39,420 mixed files: 42.2 files per second before, 42.4 after (no measurable slowdown).
  - `kestrixcodebench`: web files are a language (`web`) in a benchmark root of their own, `rule-rates` and `web-corpus` commands,
    and `test2-select --published-after` with `hpc/codebench_heldout_future.sh` for a future test3.

- **Dependency checks the day an advisory drops: fresher data, more ecosystems.**
  - Ecosystems: Packagist (`composer.lock`), Go (`go.mod`, `go.sum`), crates.io (`Cargo.lock`), Maven (`pom.xml`,
    `gradle.lockfile`), RubyGems (`Gemfile.lock`), NuGet (`packages.lock.json`), Pub (`pubspec.lock`) and Bun
    (`bun.lock`; `bun.lockb` is reported as unsupported), next to PyPI and npm. Version ordering per ecosystem:
    SemVer (Go incl. pseudo-versions, crates.io, Pub), Composer, `Gem::Version`, NuGet and a port of Maven's
    `ComparableVersion`. A version or range event that cannot be parsed is reported as "possibly affected"
    (`dep.vulnerable`, low confidence) instead of being skipped.
  - `db update` downloads only the ecosystems the project needs (its lockfiles, the index's, `db-ecosystems`);
    `--all` takes all nine. It sends `If-None-Match` and `If-Modified-Since`; when every export is unchanged the index
    is not rebuilt and `checked.json` records the check. Reused cached zips are verified against their SHA-256.
    `db status --json` is new.
  - Freshness: `db-max-age-days` in `[tool.kestrix]` and `KESTRIX_SCAN_MAX_AGE_DAYS` set the 7-day default. The stale
    note now also appears in SARIF output (a `toolExecutionNotification`; the golden SARIF changed), one line is added
    to the Claude hook context when a dependency file is edited, `/kestrix:status` shows the index age, and the
    install guard says its result may be stale. New note `dep.ecosystem_missing`. The `dep.not_checked` message no
    longer says "== pin".
  - Install guard: `bun add`, `composer require`, `go get`/`go install`, `cargo add crate@=x`, `gem install` and
    `dotnet add package`; an ecosystem missing from the index is named instead of passing silently.
  - `kestrix-scan init --ci github` writes a workflow that also runs daily (cron) and caches the OSV downloads.
  - Not covered: language runtimes (PHP itself) are not lockfile dependencies; Maven versions managed by a parent
    POM or BOM are not resolved.

- **CVE-fix benchmark, round 2 (measured on the tuning data of `docs/benchmarks/cvefixes.md`: round-1 dev plus the
  spent round-1 test).** Nine changes kept, all of them wider sources or sinks of existing rules (no new rule id),
  fourteen tried and reverted. Each change was measured alone against the round-1 scanner.
  - Python sources: Flask route parameters (`<name>`, `<path:name>`), `request.view_args`, `get_data()`, `query_string`,
    `stream`; the request objects of Django REST, Starlette, aiohttp, Pyramid, Sanic, Tornado, Bottle and Falcon.
  - `py.ssrf.request` also reports `.get`/`.post`/`.request` on HTTP sessions and clients, `urlretrieve` and
    `http.client` hosts; `py.xss.markup` also reports `Markup`/`mark_safe` of Markdown renderer output with no
    sanitizer; `py.archive.extract` also reports `shutil.unpack_archive` without `filter=`.
  - JavaScript sources: `req.url`, `originalUrl`, `path`, `baseUrl`, `payload`, `rawBody`, `nextUrl`, Koa `ctx.url`
    and `ctx.path`. `js.path.traversal` also covers `readdir`, `stat`, `exists`, `rename`, `copyFile`, `mkdir`, `rmdir`
    and fs-extra, `js.redirect.open` also covers `res.location`, a `Location` header and `h.redirect`, and
    `js.child_process.shell` also covers `spawn('sh', ['-c', script])`, `shelljs.exec` and `execa.command`.
  - Rule titles and texts of `py.xss.markup`, `py.archive.extract`, `js.child_process.shell`, `js.redirect.open` and
    `js.path.traversal` changed, so the SARIF rule descriptions did.
  - Tried and reverted: more Python file sinks (two forms), Django URL parameters, template-source and
    `subprocess` argument sinks, a Jinja2 `autoescape` rule (two forms), more JS HTTP clients, `vm` and template
    engine code sinks, `spawn` argument taint, reflected `res.send`, DOM `href`/`src` assignment, and two narrower
    forms of `js.dom.xss_sink` (alerts down 35 to 54%, detection down 0.5 to 2.5 points).
- **CVE-fix benchmark, round 1 (measured on the development half of `docs/benchmarks/cvefixes.md`).** Two changes
  kept, three reverted.
  - New rule `py.archive.extract` (CWE-22, medium severity, low confidence): `tarfile` `extract` and `extractall` on
    an archive opened in the same file, with no `filter=` and no member list.
  - `py.deserialize.pickle` also reports `pandas.read_pickle`, `jsonpickle.decode`, `numpy.load(allow_pickle=True)`
    and a ZeroMQ socket's `recv_pyobj()`. Its title and text name them, so the SARIF rule description changed.
  - Tried and reverted for adding too many alerts on fixed and unchanged files: `mark_safe` or `Markup` of a value
    built at run time, jQuery insertion methods and the `$()` constructor given built markup, and a ReDoS check
    for Python and JavaScript regular expressions.
  - The registry has 60 rules (28 Python, 14 JS/TS, 11 secret, 2 dependency, 5 agent-config).
- **Claude Code plugin: visible scan states, Bash coverage, `/kestrix:status`.**
  - A scan that could not run (`kestrix-scan` missing, timed out or crashed) is no longer silent: the user gets one
    `systemMessage` per session for each cause and Claude gets a line saying the file was not security-checked.
    `kestrix-scan --hook` still exits 0 on a crash but prints `{"kestrix_error": "<ExceptionType>"}`, and a hook
    reply carries `kestrix: {"new", "existing"}` counts, which the plugin script reads and removes.
  - New `PostToolUse` and `PostToolUseFailure` hooks on `Bash` scan the source-like files (at most 20) a command
    changed in a git repository (`git status` and modification times against a start mark recorded by the
    `PreToolUse` Bash hook; the text before is the `HEAD` version). The hook payload gains `kestrix_files` for the
    `Bash` tool. Outside a git repository the user is told once that changed files are not scanned.
  - New `/kestrix:status` command skill and a once-per-session "scanning is on" line at `SessionStart`.
  - The `secure-code-review` skill description is rewritten in the third person with concrete trigger phrases.
  - Plugin repository: README starts with a before / finding / after example generated from the real hook output,
    a Coverage section, an exact per-family rule count (checked against the registry), and a "Does it help?" section;
    `evals/ab/` is a paired with/without-plugin eval (13 tasks), with a runner and report script and a results
    template that reads "not yet run". No effectiveness numbers are claimed.
  - The kestrix-scan README said 54 rules; the registry has 59 (27 Python, 14 JS/TS, 11 secret, 2 dependency, 5
    agent-config).
- **Claude Code plugin, for the directory listing:** `plugin.json` adds `displayName`, `documentationUrl`,
  `supportUrl` and `privacyPolicyUrl`, and its `homepage` and `repository` are now the plugin's own repository,
  https://github.com/Ruthvik-Bandari/kestrix-claude-plugin. The missing-scanner message says to install
  `kestrix-scan` from PyPI and names no command line, and the `kestrix-security` skill offers `uv tool install kestrix`
  from PyPI instead of a git URL.
- **Python rule gaps closed (informed by the BenchmarkPython gap analysis; see
  [the scorecard](../../docs/benchmarks/benchmarkpython.md)):**
  - New rules: `py.xss.reflected` (CWE-79), `py.ldap.injection` (CWE-90), `py.xpath.injection` (CWE-643),
    `py.cookie.insecure` (CWE-614, or CWE-1004 when only HttpOnly is missing) and `py.trust_boundary.session`
    (CWE-501). They sit after `py.ml.unsafe_model_load` in the registry, so the SARIF `ruleIndex` of every later rule
    (`config.*`, `secret.*`, `dep.*`, `js.*`) moved by 5.
  - `py.subprocess.shell_true` also reports a shell started through an argument list (`["sh", "-c", script]`,
    `cmd /c`, `powershell -Command`, `asyncio.create_subprocess_exec`). A command whose values all pass through
    `shlex.quote` is reported at low confidence. A provably fixed `shell=True` command is no longer reported (it was
    low).
  - `py.xml.unsafe_parser` is now CWE-611 (medium, high confidence). It follows the Python documentation's XML
    vulnerabilities table: standard-library parsers with their defaults are no longer reported. lxml with
    `resolve_entities=True` or `no_network=False`, and SAX external-entity features, are reported; lxml `huge_tree=True`
    is reported at low severity as CWE-776.
  - `py.crypto.weak_hash` no longer reports `usedforsecurity=False` (it was low).
  - `py.crypto.insecure_random` also follows `random` values (new `weak_random` taint kind) into `set_cookie`,
    `session[...]`, response headers and secret-named arguments.
  - Taint: more propagators (`urllib.parse` unquote/quote, `base64`, `codecs`, `json.loads`, `str.join`/`bytes.decode`
    called on the type), `codecs.open` as a path sink, and new guards: inline normalize-and-contain checks, `urlsplit`
    netloc checks, and literal-allowlist membership.
  - Constants: the pattern rules stay quiet on values that are provably constant (flow-sensitive constants, literal
    dict and list items, `format`/`join` of literals, `int()` casts, and branches whose condition is a constant), and
    on `pickle.loads`/`yaml.load` of a literal.
  - Fix: a branch ending in `break` or `continue` no longer drops its taint at the loop exit or head.
- **JavaScript and TypeScript rules (ADR 0005 slice C3):** 14 `js.*` rules for `.js`, `.mjs`, `.cjs`, `.jsx`,
  `.ts`, `.tsx`, `.mts` and `.cts`, with no new dependency: a bounded tokenizer (strings, nested templates,
  comments, regex versus division, JSX, TypeScript) and a structural matcher (calls, member chains, assignments,
  object keys, JSX attributes, function scopes, `import`/`require`/`promisify` aliases) with a light same-function
  taint from Express/Koa request data, the URL and `postMessage` (`location`, `URLSearchParams`, React Router
  hooks) and OpenAI/Anthropic SDK output. Rules: `js.exec.eval` (CWE-95), `js.child_process.shell` (CWE-78),
  `js.dom.xss_sink` (CWE-79; high with a URL source, medium otherwise), `js.sql.string_built` (CWE-89; binding
  tagged templates are fine), `js.tls.reject_unauthorized` (CWE-295), `js.crypto.weak_hash` (CWE-328),
  `js.crypto.insecure_random` (CWE-330), `js.jwt.no_verify` (CWE-347), `js.path.traversal` (CWE-22),
  `js.ssrf.request` (CWE-918), `js.redirect.open` (CWE-601), `js.proto.pollution` (CWE-1321),
  `js.cors.wildcard_credentials` (CWE-942) and `js.llm.output_to_sink` (CWE-94/78/79 by sink). They are appended
  to the registry, so earlier SARIF `ruleIndex` values are unchanged.
- **New skip reason `minified`** in `files_skipped` for `.min.` files and files whose average line is longer than
  500 characters; the secret rules still run on them.
- **Suppressions** may also be written as `/* kestrix: ignore[rule-id] reason */`, the form JSX needs.
- **Secrets:** `secret.generic` also reads values in backtick template literals without `${...}`.
- The `fixing-security-findings` playbook and the `secure-code-review` skill cover the `js.*` rules.

- **Taint analysis (Python):** an intraprocedural forward data flow from Flask, Django and FastAPI request
  data, LLM client output (Anthropic, OpenAI, LiteLLM, Ollama, Google GenAI, LangChain), `input()`/`sys.argv`
  and environment variables, with per-sink sanitizers (`shlex.quote`, `basename`/`secure_filename`,
  `html.escape`, numeric conversion, resolve-and-contain guards). `py.exec.*`, `py.subprocess.shell_true`,
  `py.os.system` and `py.sql.string_built` keep their pattern behaviour and gain the source's confidence and a
  trace when tainted data reaches them. `py.path.traversal` is now taint-based: it reports at the file operation
  (`open`, `send_file`, `FileResponse`, `Path.read_text` ...) instead of at `os.path.join`, follows FastAPI
  parameters and LLM output, and accepts a resolve-and-contain guard only on the guarded name.
- **New rules:** `py.ssrf.request` (CWE-918), `py.redirect.open` (CWE-601), `py.xss.markup` (CWE-79, CWE-1336 for
  template source), `py.llm.output_to_sink` (CWE-94/78/89/22 by sink; replaces the pattern finding on that
  line), `py.ml.unsafe_model_load` (CWE-502; `torch.load`, `joblib.load`, pickled model files, Keras
  `safe_mode=False`, `trust_remote_code=True`), and `config.claude.hook_remote_exec`,
  `config.claude.permissions_bypass`, `config.mcp.unpinned_launcher`, `config.mcp.secret_inline` and
  `config.claude.env_leak` for `.claude/settings*.json`, plugin `hooks/hooks.json` and `.mcp.json`.
- **Report:** findings may carry `trace` (a list of `{line, note}`); the key is present only on taint findings,
  so `schema_version` stays 1 and existing reports are unchanged. SARIF results carry it as `codeFlows`; the
  text report prints a `trace:` line and the hook context a compact `[trace: L4→L7]`. A finding's `cwe` and
  `confidence` can now differ from the rule default.
- **Behaviour changes:** `pickle.load` of a model file reports `py.ml.unsafe_model_load` instead of
  `py.deserialize.pickle`; a secret in a configuration file reports the `config.*` rule instead of `secret.*`.
  New rules sit after `py.path.traversal` in the registry, so SARIF `ruleIndex` values of the `secret.*`
  rules moved.
### Added

- **Offline dependency scanning.** `kestrix-scan db update [--ecosystem PyPI npm]` downloads the OSV exports
  over HTTPS (2 GiB cap, atomic writes, ETag reuse) and builds a local SQLite index with each download's
  SHA-256 and time; it is the only command that uses the network. `kestrix-scan db status` shows its age and
  counts. Scans then check `requirements*.txt` (exact pins), `uv.lock`, `poetry.lock`, `pdm.lock`,
  `Pipfile.lock`, `package-lock.json` v2/v3, `yarn.lock` v1 and Berry, and `pnpm-lock.yaml` with PEP 440 and
  SemVer range matching.
- **New rules** `dep.vulnerable` (CVSS-based severity, OSV CWE, "upgrade to" fix) and `dep.malicious`
  (critical; OpenSSF `MAL-` reports), appended to the registry, so earlier SARIF `ruleIndex` values are
  unchanged. Notes `dep.db_stale` (missing or 7-day-old index, once per scan), `dep.not_checked` and
  `dep.unsupported`.
- **Configuration:** `ignore-advisories = {"GHSA-..." = "reason"}` and `claude.install-guard = false`.
  Requirements lines accept `# kestrix: ignore[<advisory id>] reason`.
- **Claude Code install guard:** a `PreToolUse` hook on `Bash` that denies installing a known malicious
  package and warns about a known-vulnerable pinned version (`pip`, `uv`, `npm`, `pnpm`, `yarn`). It fails
  open and is turned off with `KESTRIX_INSTALL_GUARD=0`.
- `kestrix-scan init --ci github` runs `kestrix-scan db update` before the scan.

### Changed

- Lockfiles up to 64 MiB are scanned (other files keep the 1 MiB limit); a lockfile over 1 MiB gets only the
  dependency check.

## 0.1.0

First release as its own package (ADR 0006). The scanner, its rules and the Claude Code plugin come from
`kestrix.code` and `kestrix.integrations` in Kestrix 0.1.0; their behaviour and output are unchanged.

- **Scanner:** Python AST rules (`py.*`) and secret rules (`secret.*`), inline suppressions with a required
  reason, baselines, `--diff`, and text, JSON (`schema_version` 1) and SARIF 2.1.0 output. Exit codes
  0, 1 and 2.
- **No runtime dependencies** on Python 3.11 and newer; `tomli` on 3.10. Python 3.10 to 3.13.
- **Command:** `kestrix-scan [scan] PATH ...` and `python -m kestrix_scan`, with `rules`, `version`, `init`
  and the Claude plugin and skill installers.
- **Configuration:** `[tool.kestrix]` in `pyproject.toml` or `.kestrix.toml`: `fail-on`, `exclude`,
  `rules.enable`, `rules.disable` and `baseline`. Flags override it; unknown keys warn; unknown rule ids
  exit 2 with a suggestion.
- **`kestrix-scan init`:** `[tool.kestrix]`, a pre-commit entry, a GitHub workflow that uploads SARIF with
  SHA-pinned actions, and the Claude Code plugin; idempotent.
- **pre-commit hook** `kestrix-scan` (`.pre-commit-hooks.yaml` at the repository root).
- **pytest plugin:** `pytest --kestrix [--kestrix-fail-on=LEVEL]`, off unless asked.
- **Python API:** `kestrix_scan.scan`, `Finding`, `ScanReport`, `rules()`, `load_config`, typed (`py.typed`).
- **Claude Code plugin:** hooks run `kestrix-scan`, falling back to `kestrix code scan`, and fail open.
