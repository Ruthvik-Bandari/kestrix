# Code security scanning

The code module looks for common security mistakes in Python, JavaScript and TypeScript source code, and in HTML, Vue, Svelte and CSS files, before they ship: shell and SQL injection, XSS sinks, unsafe deserialization, disabled TLS checks, weak hashes and randomness, hard-coded secrets, and [dependencies](#dependencies) with known vulnerabilities or reported as malware. Run it on a checkout, in CI, or from a Claude Code hook on every file the assistant writes. Each finding names a rule, a CWE, why it matters and how to fix it. It is available from the CLI, pre-commit, pytest and as a Python function; there is no API route or dashboard page yet.

It is pattern analysis, not a proof. Rules miss things, and a finding can be wrong in context. No real-world detection or false-positive rate is claimed (a first measurement on CVE-fix files, with its approximations, is in the [CVE-fix benchmark](../benchmarks/cvefixes.md)), and "no findings" means no rule fired, not that the code is secure. Category coverage has been measured on synthetic code only: the [benchmark scorecard](../benchmarks/benchmarkpython.md) compares `kestrix-scan` with Bandit and the security-guidance regex layer on OWASP BenchmarkPython v0.1 and on the project's own labelled cases, with the method, mapping and caveats. The design is recorded in [ADR 0005](../adr/0005-code-security.md); this page describes slices C1 and C3: the Python rules, the JavaScript and TypeScript rules, the secret rules, the CLI, the output formats, exit codes, suppression and baselines. Since [ADR 0006](../adr/0006-two-packages.md) the scanner is its own package, `kestrix-scan` (import name `kestrix_scan`), with no runtime dependencies on Python 3.11+ (`tomli` on 3.10); its source is under [`packages/kestrix-scan/src/kestrix_scan/`](../../packages/kestrix-scan/src/kestrix_scan/) and its user guide is [packages/kestrix-scan/README.md](../../packages/kestrix-scan/README.md). The workbench depends on it: `kestrix code scan` runs `kestrix-scan scan` with the same options, output and exit codes, and `kestrix.code` re-exports its Python API.

## Privacy and safety

The scanner reads files as bytes and decodes them as UTF-8 (invalid bytes replaced). Python source is parsed with the standard-library `ast` module; nothing is imported, executed or sent off the machine. Secret values never leave the scanner: findings, JSON, SARIF, text output, baselines and hook output hold only the secret's kind, its location and its first four characters (for example `github_token:ghp_…`). Secrets found anywhere on a reported line are also redacted from the snippets of other findings.

`kestrix-scan db update` is the only command that uses the network: it downloads the public OSV vulnerability exports over HTTPS. Scans, the hooks and the install guard read the local copy and open no sockets; the test suite checks this with every socket call refused. Nothing about your project is sent anywhere, including by `db update`, which sends a plain GET for each ecosystem's export.

## Commands

| Command | Options | Exit codes |
| --- | --- | --- |
| `kestrix-scan [scan] [PATH ...]` (or `kestrix code scan [PATH ...]`) | `--format text\|json\|sarif`, `--output FILE`, `--fail-on low\|medium\|high\|critical\|none` (default `high`, or `[tool.kestrix]` `fail-on`), `--baseline FILE`, `--write-baseline FILE`, `--diff BASE`, `--hook`, `--config FILE`, `--no-config` | 0 no findings at or above `--fail-on`; 1 findings at or above it; 2 usage or input error |
| `kestrix-scan init` | `--ci github`, `--pre-commit`, `--claude-plugin`, `--force`, `--dir DIR` | 0 done; 2 refused |
| `kestrix-scan rules` | | 0 |
| `kestrix-scan db update` (network) | `--ecosystem PyPI npm` (default: both) | 0 done; 2 download or index error |
| `kestrix-scan db status` | | 0 index present; 1 no index |

`PATH` defaults to `.`; `scan` is the default command, so `kestrix-scan src` is `kestrix-scan scan src`. Errors print `Rejected (<reason>): <detail>` to stderr and exit 2: a missing path, an unreadable or malformed baseline, `--diff` outside a git work tree or with an unknown ref, a bad option, or bad [configuration](#configuration).

```text
$ kestrix-scan app.py
app.py
  4:5  HIGH  py.subprocess.shell_true  CWE-78
      subprocess.run runs a built command through the shell (shell=True).
      fix: Pass the command as a list of arguments without shell=True, for example subprocess.run(['git', 'log', ref], check=True). Use shlex.quote only when a shell is unavoidable.

1 finding(s): 0 critical, 1 high, 0 medium, 0 low in 1 file(s); 0 suppressed, 0 in baseline, 0 skipped; fail-on high.
```

Text output groups findings by file. Severities are colored only when stdout is a terminal. The last line is the notice that rules can miss things.

**Options.**

- `--format json` prints the full report (below). `--format sarif` prints SARIF 2.1.0 for GitHub code scanning.
- `--output FILE` writes the report to `FILE` instead of stdout; the exit code is the same.
- `--fail-on` sets the lowest severity that makes the command exit 1. `none` always exits 0 after a successful scan.
- `--baseline FILE` leaves out findings whose fingerprint is in `FILE`, a JSON list of fingerprints. `--write-baseline FILE` scans, writes the fingerprints of every current finding to `FILE` (sorted, mode 0644, written to a temporary file and renamed), prints how many it wrote and exits 0. It ignores `--baseline`, so the new file covers everything found today.
- `--diff BASE` keeps only findings on lines added or changed since the git ref `BASE`, comparing the working tree (staged or not) with `git diff --unified=0`. Untracked files that are not ignored count as wholly new. Refs that start with `-` are refused.
- `--hook` is the Claude Code mode described [below](#claude-code-hook). It ignores the other options.
- `--config FILE` reads settings from that `.kestrix.toml` or `pyproject.toml` instead of searching for one; `--no-config` ignores settings files.

## Configuration

Settings come from `[tool.kestrix]` in `pyproject.toml`, or from `.kestrix.toml` with the same keys at the top level:

```toml
[tool.kestrix]
fail-on = "medium"
exclude = ["tests/fixtures/", "*.min.js"]
baseline = ".kestrix-baseline.json"
rules.enable = ["py.", "secret."]
rules.disable = ["py.crypto.weak_hash"]
ignore-advisories = {"GHSA-xxxx-xxxx-xxxx" = "not reachable: we never parse untrusted XML"}
claude.install-guard = false
```

| Key | Meaning |
| --- | --- |
| `fail-on` | the default for `--fail-on` |
| `exclude` | globs of files and directories to leave out, with `.gitignore` semantics: a glob with a `/` matches the path from the scan root, one without matches any file or directory name, `*` stays within a name and `**` crosses directories. Excluded files are neither scanned nor listed as skipped, also when named on the command line (as pre-commit does). |
| `baseline` | the default for `--baseline`, relative to the settings file |
| `rules.enable` | rule ids or prefixes (`py.`, `secret.`, `py.crypto`) to report; default: every rule |
| `rules.disable` | rule ids or prefixes to leave out, applied after `enable` |
| `ignore-advisories` | a table of advisory id (or alias, such as a CVE) to the reason it does not apply; the reason is required. Those advisories are left out of [dependency findings](#dependencies) and install-guard decisions. |
| `claude.install-guard` | `false` turns off the Claude Code [install guard](../claude-plugin.md#pretooluse-on-bash-the-install-guard) for this project |

The scanner looks for settings from the scan root upwards: in each directory it reads `.kestrix.toml` first, then `pyproject.toml` if it has a `[tool.kestrix]` table, and the first one found wins. The search stops at the directory holding `.git`. Command-line options override settings. An unknown key prints a `warning:` line on stderr and is ignored; an unknown rule id or prefix, a bad value or invalid TOML is an error (exit 2), and a misspelled rule id gets a suggestion (`did you mean 'py.subprocess.shell_true'?`). The Claude Code hook applies `rules` and `exclude` too (not `baseline`, since it already reports only new findings), and so does `pytest --kestrix`.

`kestrix-scan init` appends a minimal `[tool.kestrix]` (`fail-on = "high"`, `exclude = []`) to `pyproject.toml` as text, or writes `.kestrix.toml` when there is no `pyproject.toml`. It leaves an existing table alone unless `--force`, which replaces only a plain `[tool.kestrix]` section. `--pre-commit` writes `.pre-commit-config.yaml` when it is missing or empty and otherwise prints the entry to add; `--ci github` writes `.github/workflows/kestrix.yml`, which installs `kestrix-scan`, runs `kestrix-scan db update` (so that CI job needs network access to `storage.googleapis.com`), scans with `--format sarif` and uploads the result with `github/codeql-action/upload-sarif`, with actions pinned to commit SHAs and only `contents: read` and `security-events: write`; `--claude-plugin` installs the Claude Code plugin. Each step prints one line, and running `init` again changes nothing.

## pre-commit and pytest

The repository root has a `.pre-commit-hooks.yaml` with the hook `kestrix-scan` (`types_or: [python, text]`, file names passed). `pytest --kestrix` adds one test item, `kestrix-scan`, that scans the rootdir with its settings and fails when findings are at or above `--kestrix-fail-on` (default: `fail-on`, else `high`); its failure report is the text report. Without `--kestrix` the pytest plugin only registers the two options.

## What is scanned

- **Directories** are walked without following symbolic links. These directories are always skipped: `.git`, `.hg`, `.svn`, `node_modules`, `bower_components`, `.venv`, `venv`, `dist`, `build`, `__pycache__`, `.mypy_cache`, `.ruff_cache`, `.pytest_cache`, `.tox`, `site-packages`, `vendor`, `third_party`, and the framework build directories `.next`, `.nuxt`, `.svelte-kit`, `.output` and `.angular`.
- **`.gitignore`** is honored. Inside a git work tree Kestrix asks git (`git ls-files --cached --others --exclude-standard`), so nested ignore files and global excludes apply. Elsewhere it reads the root `.gitignore` with a small parser that supports comments, `!` negation, trailing `/` for directories, anchored patterns, `*`, `?`, `[...]` and `**`.
- **A file named on the command line** is scanned even if it is ignored, so a hook can check a file such as `.env`.
- **Limits:** files over 1 MiB are skipped as `too_large`; files with a NUL byte in their first 8 KiB as `binary`; at most 20,000 files per scan, after which `truncated` is true. A symbolic link whose target is outside the scan root is skipped as `symlink_outside_root`; a link inside the root is scanned once, under its target's path.
- **Python rules** run on `.py` and `.pyw` files. A file that does not parse is listed as `syntax_error` (or `too_complex` for pathological nesting); the secret rules still run on it.
- **JavaScript and TypeScript rules** run on `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.mts` and `.cts` files (see [JavaScript and TypeScript](#javascript-and-typescript)). A minified file (a `.min.` name, a name ending in `-min.js`, or an average line longer than 500 characters) is listed as `minified`, and one beyond the tokenizer's bounds as `too_complex`; the secret rules still run on both. Script blocks of `.vue`, `.svelte` and `.html` files go through the same rules.
- **Web file rules** run on `.vue`, `.svelte`, `.html`, `.htm`, `.css` and `.scss` files and on `next.config.js`, `.mjs`, `.cjs` and `.ts` (see [Web files](#web-files)). Minified files (`.min.` names, an average line over 500 characters) are `minified`; more than 200,000 start tags make a file `too_complex`.
- **Configuration rules** run on `.claude/settings.json`, `.claude/settings.local.json`, `hooks/hooks.json` and `.mcp.json` (see [Claude Code and MCP configuration](#claude-code-and-mcp-configuration)). A walk inside a git work tree only sees files git does not ignore, so name an ignored `settings.local.json` explicitly to check it.
- **Secret rules** run on every text file.
- **Dependency files** (below) are checked against the local vulnerability index. They may be up to 64 MiB; one over 1 MiB gets only the dependency check, not the secret rules.

Finding paths are relative to the scan root: the current directory when every path is inside it, otherwise the paths' common parent.

## Rules

Every rule was written for Kestrix from public CWE guidance; none is copied from another scanner. Each has positive and negative tests in [`tests/code/`](../../tests/code/). The table is generated from the registry in [`rules.py`](../../src/kestrix/code/rules.py) by `scripts/build_code_rules_doc.py`, and a test fails if it drifts.

<!-- rules:start (generated by scripts/build_code_rules_doc.py) -->
| Rule id | Applies to | CWE | Severity | Confidence | What it finds |
| --- | --- | --- | --- | --- | --- |
| `py.exec.eval` | Python | CWE-95 | high | medium | eval() of a value that is not a literal |
| `py.exec.exec` | Python | CWE-95 | high | medium | exec() of a value that is not a literal |
| `py.exec.compile` | Python | CWE-95 | medium | medium | compile() of a value that is not a literal |
| `py.subprocess.shell_true` | Python | CWE-78 | high | high | Command run through a shell |
| `py.os.system` | Python | CWE-78 | high | high | os.system or os.popen with a built command |
| `py.deserialize.pickle` | Python | CWE-502 | high | medium | Unsafe deserialization (pickle, dill, shelve, marshal, pandas.read_pickle, ZeroMQ recv_pyobj) |
| `py.deserialize.yaml_unsafe` | Python | CWE-502 | high | high | YAML loaded with a loader that can build objects |
| `py.sql.string_built` | Python | CWE-89 | high | medium | SQL statement built from strings |
| `py.tls.verify_disabled` | Python | CWE-295 | high | high | TLS certificate or hostname verification disabled |
| `py.crypto.weak_hash` | Python | CWE-328 | medium | medium | MD5 or SHA-1 hash |
| `py.crypto.insecure_random` | Python | CWE-330 | medium | medium | random module used for a secret, cookie or session value |
| `py.tempfile.mktemp` | Python | CWE-377 | medium | high | tempfile.mktemp returns a name, not a file |
| `py.flask.debug` | Python | CWE-489 | medium | medium | Debug mode enabled |
| `py.jwt.no_verify` | Python | CWE-347 | high | high | JWT decoded without verifying the signature |
| `py.xml.unsafe_parser` | Python | CWE-611 | medium | high | XML parser set to resolve external entities |
| `py.assert.security` | Python | CWE-617 | low | medium | assert used for an access check |
| `py.path.traversal` | Python | CWE-22 | medium | medium | File path built from request data |
| `py.ssrf.request` | Python | CWE-918 | medium | medium | HTTP request to a URL taken from request data or model output |
| `py.redirect.open` | Python | CWE-601 | medium | medium | Redirect to a location taken from request data |
| `py.xss.markup` | Python | CWE-79 | high | medium | Request data or rendered Markdown marked as safe HTML, or request data used as a template |
| `py.llm.output_to_sink` | Python | CWE-94 | high | medium | LLM output used as code, a shell command, SQL or a file path |
| `py.ml.unsafe_model_load` | Python | CWE-502 | high | medium | Model loaded in a way that can run code from the file |
| `py.xss.reflected` | Python | CWE-79 | medium | medium | HTML response built from request data without escaping |
| `py.ldap.injection` | Python | CWE-90 | high | medium | LDAP search filter built from request data |
| `py.xpath.injection` | Python | CWE-643 | high | medium | XPath expression built from request data |
| `py.cookie.insecure` | Python | CWE-614 | medium | medium | Cookie set without the Secure or HttpOnly flag |
| `py.trust_boundary.session` | Python | CWE-501 | low | medium | Request data stored in the session without validation |
| `py.archive.extract` | Python | CWE-22 | medium | low | Tar archive extracted without a member filter |
| `config.claude.hook_remote_exec` | Claude Code and MCP config | CWE-494 | critical | high | Claude Code hook runs a script downloaded at run time |
| `config.claude.permissions_bypass` | Claude Code and MCP config | CWE-250 | high | high | Project settings skip Claude Code permission prompts |
| `config.mcp.unpinned_launcher` | Claude Code and MCP config | CWE-829 | medium | high | MCP server launched from a package without a pinned version |
| `config.mcp.secret_inline` | Claude Code and MCP config | CWE-798 | critical | medium | Credential written into .mcp.json |
| `config.claude.env_leak` | Claude Code and MCP config | CWE-798 | critical | medium | Credential written into the env block of Claude Code settings |
| `secret.aws_access_key_id` | any text file | CWE-798 | high | high | AWS access key id |
| `secret.aws_secret_access_key` | any text file | CWE-798 | critical | medium | AWS secret access key |
| `secret.github_token` | any text file | CWE-798 | critical | high | GitHub token |
| `secret.slack_token` | any text file | CWE-798 | critical | high | Slack token |
| `secret.stripe_live_key` | any text file | CWE-798 | critical | high | Stripe live secret or restricted key |
| `secret.google_api_key` | any text file | CWE-798 | high | high | Google API key |
| `secret.private_key` | any text file | CWE-798 | critical | high | Private key block |
| `secret.jwt` | any text file | CWE-798 | high | medium | JSON Web Token |
| `secret.anthropic_api_key` | any text file | CWE-798 | critical | high | Anthropic API key |
| `secret.openai_api_key` | any text file | CWE-798 | critical | medium | OpenAI-style API key |
| `secret.generic` | any text file | CWE-798 | high | medium | Hard-coded credential |
| `dep.vulnerable` | lockfiles | CWE-1395 | critical | high | Dependency version with a known vulnerability (OSV) |
| `dep.malicious` | lockfiles | CWE-506 | critical | high | Dependency reported as a malicious package (OSV MAL-) |
| `js.exec.eval` | JavaScript, TypeScript | CWE-95 | high | medium | eval, new Function or a string timer with code that is not a literal |
| `js.child_process.shell` | JavaScript, TypeScript | CWE-78 | high | high | child_process command built from strings and run through a shell |
| `js.dom.xss_sink` | JavaScript, TypeScript | CWE-79 | high | medium | HTML sink given a value that is not a literal |
| `js.sql.string_built` | JavaScript, TypeScript | CWE-89 | high | medium | SQL text built with a template literal or concatenation |
| `js.tls.reject_unauthorized` | JavaScript, TypeScript | CWE-295 | high | high | TLS certificate verification disabled |
| `js.crypto.weak_hash` | JavaScript, TypeScript | CWE-328 | medium | medium | MD5 or SHA-1 hash |
| `js.crypto.insecure_random` | JavaScript, TypeScript | CWE-330 | medium | medium | Math.random() used for a secret value |
| `js.jwt.no_verify` | JavaScript, TypeScript | CWE-347 | high | high | JWT verified with the 'none' algorithm allowed or expiry ignored |
| `js.path.traversal` | JavaScript, TypeScript | CWE-22 | medium | medium | File path built from Express request data |
| `js.ssrf.request` | JavaScript, TypeScript | CWE-918 | medium | medium | HTTP request to a URL taken from Express request data |
| `js.redirect.open` | JavaScript, TypeScript | CWE-601 | medium | medium | Redirect to a location taken from request data |
| `js.proto.pollution` | JavaScript, TypeScript | CWE-1321 | medium | medium | Object keys from request data written without a __proto__ guard |
| `js.cors.wildcard_credentials` | JavaScript, TypeScript | CWE-942 | medium | high | CORS allows any origin together with credentials |
| `js.llm.output_to_sink` | JavaScript, TypeScript | CWE-94 | high | medium | LLM output used as code, a shell command or HTML |
| `js.angular.bypass_trust` | JavaScript, TypeScript | CWE-79 | high | medium | Angular bypassSecurityTrust* of a value that is not a literal |
| `vue.xss.v_html` | HTML, Vue, Svelte, CSS, next.config | CWE-79 | high | medium | Vue v-html with a value that is not a literal |
| `svelte.xss.at_html` | HTML, Vue, Svelte, CSS, next.config | CWE-79 | high | medium | Svelte {@html} with a value that is not a literal |
| `web.url.dynamic_scheme` | HTML, Vue, Svelte, CSS, next.config | CWE-79 | medium | low | Link or frame URL bound to a value that is not a literal (javascript: URLs) |
| `html.inline.event_handler` | HTML, Vue, Svelte, CSS, next.config | CWE-693 | low | medium | Inline event handler attribute (onclick and the like) |
| `html.url.javascript_scheme` | HTML, Vue, Svelte, CSS, next.config | CWE-693 | low | medium | javascript: URL in href, src, action or formaction |
| `html.link.target_blank` | HTML, Vue, Svelte, CSS, next.config | CWE-1022 | low | medium | target="_blank" link to an external page without rel="noopener" |
| `html.form.http_action` | HTML, Vue, Svelte, CSS, next.config | CWE-319 | medium | high | Form that posts to an http: URL |
| `html.mixed.http_resource` | HTML, Vue, Svelte, CSS, next.config | CWE-319 | low | medium | Script, stylesheet, frame or image loaded over http: |
| `html.angular.inner_html` | HTML, Vue, Svelte, CSS, next.config | CWE-79 | low | low | Angular [innerHTML] binding of a value that is not a literal |
| `css.import.http` | HTML, Vue, Svelte, CSS, next.config | CWE-319 | low | medium | CSS @import or url() over http: |
| `css.expression.legacy` | HTML, Vue, Svelte, CSS, next.config | CWE-79 | low | medium | CSS expression() (Internet Explorer 7 and older) |
| `next.images.wildcard_host` | HTML, Vue, Svelte, CSS, next.config | CWE-918 | low | high | next.config images.remotePatterns allows hostname '**' |
<!-- rules:end -->

**How the Python rules decide.** Calls are resolved through imports and aliases (`import subprocess as sp`, `from os import system`). A provably constant command, code string, pickle or YAML document, or query is not reported (`shell=True`, `os.system`, `eval`/`exec`, `pickle.loads`, `yaml.load`, SQL). A value is constant when it is a literal or built only from literals; a name whose every assignment in its function, or an enclosing scope, is constant, ignoring assignments in a branch that cannot run (`if False:`, or `if FLAG:` with `FLAG` assigned one constant); an item of a literal dict, list or tuple taken with a literal key, or of one whose values are all literals, when the file never writes to its items; `"...".format()`/`"sep".join()` of literals, `str()` of a literal, or a number made by `int()`, `float()` or `uuid.UUID()`; or a name the taint analysis proves constant at that point (assigned a constant on every path, or checked against a literal allowlist). Code in a branch that cannot run is not reported. When an argument cannot be classified, the rule stays quiet: the rules prefer missing a case to flagging safe code.

- `py.subprocess.shell_true` reports `shell=True` with a built command, and a program list that starts a shell with its command-string option and a built script: `["sh"|"bash"|"zsh"|"dash"|"ksh"|"/bin/sh", "-c" (or `-lc`, `-ec` ...), script]`, `["cmd", "/c", ...]`, `["powershell"|"pwsh", "-Command", ...]`, through `subprocess.*` and `asyncio.create_subprocess_exec`. Values passed after the script (`["sh", "-c", 'grep -- "$1" log', "sh", pattern]`) are positional parameters, not script text, and are fine. A command whose every non-literal part is `shlex.quote(...)` (or `shlex.join`) is reported at **low** confidence. `subprocess.getoutput`, `subprocess.getstatusoutput` and `asyncio.create_subprocess_shell` always use a shell and are reported with a built command.
- `py.crypto.weak_hash` is not reported with `usedforsecurity=False`, which declares a checksum or identifier.
- `py.deserialize.yaml_unsafe` accepts `SafeLoader`, `CSafeLoader` and classes defined in the same file that derive from them; a loader it cannot resolve is not reported.
- `py.sql.string_built` reports `execute`, `executemany`, `executescript`, `.raw()` and SQLAlchemy `text()` when the first argument is an f-string, `%`-formatted, `+`-concatenated or `.format()`-ed string (directly or through a variable) whose literal text contains SQL such as `SELECT ... FROM`, `WHERE ... =` or `INSERT INTO`.
- `py.crypto.insecure_random` reports `random.*` calls in a value assigned to a name, attribute or key whose words include token, secret, password, key, nonce, salt, otp or csrf (not sort or cache keys), and in the return value of a function named that way. Through the taint analysis's `weak_random` kind it also reports values made with `random` (including a `random.Random()` instance, and after `str`, `int`, `hex`, f-strings or `"".join`) that reach a `set_cookie` value or a `session[...]` entry (medium confidence), a `response.headers[...]` entry (low confidence), or a keyword argument with a secret-like name. `random.SystemRandom` and `secrets` are fine, and random values used elsewhere (shuffling, jitter) are not reported.
- `py.xml.unsafe_parser` (CWE-611) follows the Python documentation's XML vulnerabilities table: the standard-library parsers with their defaults are not reported, since `xml.etree`, `minidom`, `pulldom` and `sax` do not resolve external entities (sax and pulldom since 3.7.1) and Expat 2.4.1 and newer resists entity expansion. It reports lxml `XMLParser`/`XMLPullParser`/`iterparse` with `resolve_entities=True` or `no_network=False`, a SAX parser's `setFeature(feature_external_ges | feature_external_pes, True)` (also the feature URIs), and, at low severity as CWE-776, lxml's `huge_tree=True`.
- `py.cookie.insecure` reports `set_cookie(...)` in files that import Flask, Django, Starlette, FastAPI or Werkzeug when `secure` or `httponly` is set to False (medium) or left out (low); only HttpOnly missing is CWE-1004. Non-literal flags, `**options`, flags passed by position and the delete idiom (`set_cookie(name, "", expires=0)`) are not reported.
- `py.xss.reflected`, `py.ldap.injection`, `py.xpath.injection` and `py.trust_boundary.session` are taint-based; see [Taint analysis](#taint-analysis).
- `py.flask.debug` reports `app.run(debug=True)`, `app.debug = True` and `app.config["DEBUG"] = True` in files that import Flask, and a module-level `DEBUG = True` in `settings*.py` or a `settings/` package.
- `py.assert.security` ignores test files (`tests/`, `test_*.py`, `*_test.py`, `conftest.py`).
- `py.path.traversal` is taint-based (see [Taint analysis](#taint-analysis)): request or LLM data (Flask URL parameters, Flask `view_args` and the request objects of other frameworks included) reaching `open`, `io.open`, `codecs.open`, `os.open`, `flask.send_file`, Starlette/FastAPI `FileResponse`, or `Path.open`/`read_text`/`read_bytes`/`write_text`/`write_bytes` in a file that imports `pathlib`. `os.path.join` and `Path(...)` pass the taint on to the file operation, which is where the finding is reported. `sys.argv`, `input()` and environment variables do not fire it.
- `py.ml.unsafe_model_load` reports `torch.load` without `weights_only` (**medium**: torch 2.6 and newer default to `weights_only=True`, older versions do not) or with `weights_only=False` (high); `joblib.load`; `pickle.load`/`loads` of a model file (a `.pkl`, `.joblib`, `.pt`, `.pth`, `.ckpt`, `.bin`, `.model` or `.sav` literal, or a name with model, weights, checkpoint, estimator or classifier in it), which then replaces `py.deserialize.pickle` on that line; Keras `load_model(..., safe_mode=False)`; and any call with `trust_remote_code=True` (medium, CWE-94).
- `py.llm.secret_in_prompt` was considered and not written: telling a credential from any other string in a prompt needs the same guesswork as the generic secret rule, and the secret rules already report literal keys wherever they sit.
- One finding per rule per line.

## Taint analysis

The Python rules include an intraprocedural taint analysis ([`taint.py`](../../packages/kestrix-scan/src/kestrix_scan/taint.py), standard-library `ast` only). It is a forward data flow over each function body, each class body and the module top level. Branches are joined and loops run twice. It stops at function boundaries: parameters start clean (except FastAPI route parameters), and nested functions and lambdas are analyzed as scopes of their own.

| Source | Kind | Confidence |
| --- | --- | --- |
| Flask `request.args`, `form`, `values`, `json`, `get_json()`, `files`, `headers`, `cookies`, `data`, `get_data()`, `view_args`, `query_string`, `stream` | request | high |
| Parameters of a Flask view that its route names as `<name>`, `<string:name>` or `<path:name>` (not `int:`, `float:` or `uuid:`), in a file that imports Flask | request | high |
| Django `request.GET`, `POST`, `body`, `headers`, `COOKIES`, `FILES`, `META` (a name `request` that is not an import, or `self.request`) | request | high |
| Other frameworks' request objects, on the same `request` name: Django REST `data` and `query_params`; Starlette `query_params`, `path_params`, `json()`, `form()`; aiohttp `match_info`, `query`, `post()`, `json()`; Pyramid `params`, `matchdict`, `json_body`; Sanic `args`, `form`. Tornado `self.get_argument()` and its relatives and `self.request.arguments`/`path`/`body` (files that import tornado); Bottle `bottle.request.query`/`forms`/`params`/`json`; Falcon `req.params`, `get_param()`, `media` (files that import falcon) | request | high |
| Parameters of FastAPI `@app.get/post/put/patch/delete/...` and `@router.*` handlers that are unannotated or annotated as text (`str`, `bytes`, `Optional[str]`, `str \| None`, `list[str]`, `Annotated[str, ...]`). Parameters with `Depends`/`Security`, and any other type, are skipped. | request | high |
| Anthropic `...messages.create(...)`, OpenAI `...chat.completions.create(...)` and `...responses.create(...)`, `litellm.completion`, `ollama.chat`/`generate`, Google GenAI `generate_content`, LangChain `invoke`; each only when the file imports that library. Attributes and items of the result (`.content[0].text`) stay tainted. | llm | high |
| `input()`, `sys.argv` | cli | medium |
| `os.environ.get`, `os.getenv`, `os.environ[...]` | env | low |
| `random.random`, `randint`, `randrange`, `choice`, `choices`, `sample`, `getrandbits`, `randbytes`, `uniform` ... and `random.Random()` instances. Not attacker input: only the weak-randomness checks use it, and `int`/`float`/`hex` keep it. | weak_random | medium |

**Propagation:** assignment and augmented assignment (also tuple targets, `:=` and loop variables), f-strings, `%`, `+`, `str.format` and the other `str` methods, list/tuple/set/dict literals and comprehensions, subscripts, attribute access on tainted objects (`self.x = ...` is tracked within the function), `dict.get`-style methods, and the calls `str`, `bytes`, `"".join` (also `str.join(sep, items)` and `bytes.decode(b)`), `os.path.join`, `os.fspath`, `pathlib.Path`, `json.loads`/`load`, `urllib.parse.unquote`/`unquote_plus`/`quote`/`quote_plus`, the `base64` encoders and decoders, `codecs.encode`/`decode` and `html.unescape`. Any other call returns clean data. Assigning a clean value to a name clears it. A branch whose condition is a constant is analyzed only when it can run.

**Sanitizers** apply only to their own sink class:

| Sink class | Sanitizers |
| --- | --- |
| Every class | `int`, `float`, `uuid.UUID` (the result is a number or an id); membership in a literal allowlist (`if x not in ALLOWED: return`, or the body of `if x in ("a", "b"):`), which also makes `x` a constant for the pattern rules |
| Shell | `shlex.quote` |
| Path | `os.path.basename`, `werkzeug.utils.secure_filename`; or `os.path.realpath`/`abspath`/`normpath`/`Path.resolve()` followed by a guard on the same name: `if not p.startswith(base)`, `if not str(p).startswith(base)` or `if not p.is_relative_to(base)` whose body raises, returns or aborts, or the body of `if p.is_relative_to(base):`, also inside `and` / `or`; or the normalization inline in the guard: `os.path.realpath(x).startswith(base)`, `str(Path(x).resolve()).startswith(base)`. A guard without normalization does not count. |
| HTML | `html.escape`, `markupsafe.escape` (not template source: escaping does not stop `{{ }}`) |
| SQL | parameters: only the first argument of `execute` is checked, so values passed separately are fine |
| LDAP filters | `ldap.filter.escape_filter_chars`, `ldap.filter.filter_format`, `ldap3.utils.conv.escape_filter_chars` |
| SSRF and redirects | a literal start that fixes the scheme and host (`f"https://api.example.com/{x}"`); for redirects also a literal start of `/` plus a path character (`"/profile/" + x`, but not `"/" + x`); and a check that the `netloc` of `urlsplit(x)`/`urlparse(x)` is empty or in a literal allowlist (`if urlsplit(x).netloc: abort(400)`). The empty-netloc check does not reject a backslash such as `/\evil.example`, which some browsers read as `//`; Django's `url_has_allowed_host_and_scheme` does. |

**Sinks.** For `py.exec.eval`, `py.exec.exec`, `py.subprocess.shell_true`, `py.os.system` and `py.sql.string_built`, the pattern rule decides whether to report as before; when tainted data reaches the sink the finding gets the source's confidence, a sentence naming the source and a `trace`. When that data is LLM output, `py.llm.output_to_sink` is reported on that line instead, with CWE-94 (code), CWE-78 (shell), CWE-89 (SQL) or CWE-22 (path). `py.path.traversal`, `py.ssrf.request` (requests, httpx and `urllib.request`, and `.get`/`.post`/`.request` and the other verbs on a `requests.Session`, `httpx.Client`, `aiohttp.ClientSession` or `urllib3.PoolManager`, or on a name such as `session`, `client` or `http_client`, in a file that imports one of those libraries; `urllib.request.urlretrieve`; `http.client.HTTPConnection` host), `py.redirect.open` (Flask `redirect`, Django `redirect`/`HttpResponseRedirect`, Starlette `RedirectResponse`) and `py.xss.markup` (`Markup`, `mark_safe`; `render_template_string` and `jinja2.Template` source as CWE-1336; also `Markup`/`mark_safe` of the output of `markdown.markdown`, `markdown2.markdown`, `mistune` or `commonmark`, with no `bleach.clean`/`nh3.clean` around it, at medium confidence and with or without taint), `py.xss.reflected` (a Flask view returning, or Flask `Response`/`make_response`, Django `HttpResponse` or FastAPI `HTMLResponse` sending, an f-string, `+`, `%` or `.format()` string with markup such as `<p` and unescaped request data; a FastAPI route's plain `str` counts only with `response_class=HTMLResponse`, and a content type without `html` is skipped), `py.ldap.injection` (python-ldap `search`/`search_s`/`search_st`/`search_ext`/`search_ext_s` filter, the third argument; ldap3 `search`/`paged_search` filter, the second), `py.xpath.injection` (lxml `.xpath()` and `etree.XPath()`/`ETXPath()`; ElementTree or lxml `find`/`findall`/`findtext`/`iterfind` when the path is built with XPath syntax such as `[`, `@` or `//`, not in files that import BeautifulSoup; values passed as XPath variables are fine) and `py.trust_boundary.session` (request data stored in Flask `session[...]` or `request.session[...]` without an allowlist check or a conversion) fire only on taint, and only from request or LLM sources: a URL from an environment variable or a path from `sys.argv` is not reported.

**Traces.** A taint finding carries `trace`, a list of `{line, note}` from the source to the sink. It appears in the JSON report (only on findings that have one), as SARIF `codeFlows`, as a `trace:` line in the text report, and as `[trace: L4→L5→L7]` in the hook context. The fingerprint does not include it.

## JavaScript and TypeScript

The `js.*` rules ([`js_rules.py`](../../packages/kestrix-scan/src/kestrix_scan/js_rules.py)) work without a JavaScript parser, because `kestrix-scan` has no dependencies. They are **precision first**: each rule matches one precise shape and stays quiet when the code is ambiguous, so they miss more than a parser-based tool would. The source is read as text and never run.

**Tokenizer** ([`js_tokens.py`](../../packages/kestrix-scan/src/kestrix_scan/js_tokens.py)). Strings in `'` and `"`; template literals, split around each `${...}`, which may nest further templates; `//`, `/* */`, `#!` and `<!--` comments, which are dropped; numbers and names. A `/` starts a regular expression after an operator, an opening bracket, `}`, a keyword such as `return` or `typeof`, or at the start, and divides after a name, a number, a string, `)` or `]`; a regex that does not close on its line is read as division. In `.js`, `.mjs`, `.cjs`, `.jsx` and `.tsx` files a `<` where an expression may start, followed by a tag name or `>`, opens a JSX element: text between tags is dropped (so `Don't` is not a string), attributes become their own tokens, and `{...}` holds code. In `.tsx`, `<T,>` and `<T extends U>` stay type parameters, and in `.ts` files `<T>x` is a type assertion. TypeScript annotations, generics, `as` and `!` are ordinary tokens the matcher steps over. Unterminated strings, templates, comments and elements end at the line or the file. More than 500,000 tokens or 512 open braces, templates and elements make the file `too_complex`.

**Structural matcher** ([`js_index.py`](../../packages/kestrix-scan/src/kestrix_scan/js_index.py)). It pairs every bracket and template, so a call's arguments are split at top-level commas; reads member chains (`a.b?.c`, `require('x').y`, `f(...).g`, `a[0]`, `f<T>(...)`); finds function bodies (after `=>`, or after `(...)` that follows a name that is not `if`, `for`, `while`, `switch` or `catch`, also with a TypeScript return type) and their parameters; and records bindings per function: `const`/`let`/`var` with destructuring, assignments, `for (... of|in ...)` variables and the first parameter of a `forEach`/`map`/`filter` callback. Module aliases follow `import` (default, `* as`, named, `as`), `require` (whole, destructured, `require('m').x`), `await import(...)`, `util.promisify(x)` and copies such as `const run = cp.exec`, with `node:` prefixes and `fs/promises` folded in. `eval`, `document`, `fetch`, `Math` and the other globals resolve only when the file does not declare the name. A value is a literal when it is a string, number, template without non-literal parts, array of literals, or a name whose every binding is one; a string is built when it is a template with a non-literal `${}` or a `+` concatenation with a non-literal part.

**Taint** is lightweight. It follows a value inside its function and the functions around it (closures), never into a called function, and only through bindings, `+`, templates, `||`/`??`/`&&`, ternary branches, `await`, array and object literals, member access and indexing, string and array methods on tainted data, and `path.join`/`resolve`/`normalize`, `String`, `decodeURIComponent`, `JSON.parse`, `Buffer.from`, `Object.keys`/`values`/`entries`/`fromEntries`, `Array.from`, `new URL` and `new URLSearchParams`. For `new URL(input, base)` only `input` carries taint, so `NextResponse.redirect(new URL('/login', request.url))` is clean while `new URL(next, request.url)` with a request-controlled `next` is not. Every other call returns clean data; comparisons, `!`, `typeof` and `Number`/`parseInt`/`parseFloat` give clean values.

| Source | Kind | Confidence |
| --- | --- | --- |
| Express and Fastify `req`/`request` `.params`, `.query`, `.body`, `.headers`, `.cookies`, `.signedCookies`, `.files`, `.url`, `.originalUrl`, `.path`, `.baseUrl`, `.payload` (hapi), `.rawBody`, `.nextUrl`, `req.param()`, `req.get()`, `req.header()`, and the Fetch-API readers `request.json()`, `.formData()`, `.text()`, `.arrayBuffer()`, `.blob()` (Next.js route handlers); Koa `ctx.query`, `ctx.params`, `ctx.querystring`, `ctx.url`, `ctx.originalUrl`, `ctx.path`, `ctx.headers`, `ctx.get()`, `ctx.request.query`/`body`/`url`/`path`/`files`/`headers`. The name must be a parameter of some function in the file. | request | high |
| In a Next.js file (an import of `next` or `next/...`, a `'use server'` directive, `pages/api/`, or `app/**/route|page|layout`): the `params` and `searchParams` parameters or destructured names, and `context.params`; in a `'use server'` file a parameter named `formData`, `form` or `fd`, or annotated `FormData`. NestJS: a parameter decorated `@Query()`, `@Body()`, `@Param()` or `@Headers()` (not with a `Parse*Pipe`, not typed `number` or `boolean`); `@Req() req` makes `req.query` and the other Express fields sources. | request | high |
| `location` and `window.location`, `document.location`, `document.URL`, `document.documentURI`, `window.name`, the `data` of the first parameter of a `message` listener (`addEventListener('message', ...)`, `onmessage = ...`), and `useSearchParams()`, `useParams()`, `useLocation()` imported from `react-router`, `react-router-dom` or (`useSearchParams`, `useParams`) `next/navigation` | dom | high |
| `....chat.completions.create(...)`, `....messages.create(...)`, `....responses.create(...)`, `....completions.create(...)` in a file that imports `openai` or `@anthropic-ai/sdk` | llm | high |

| Sink class | Sanitizers |
| --- | --- |
| Path | `path.basename`; a name built with `path.resolve`/`normalize`/`fs.realpath` and then checked with `name.startsWith(...)` before the sink; `rel = path.relative(base, name)` checked with `rel.startsWith(...)`; `res.sendFile(name, { root })` |
| HTML | `DOMPurify.sanitize` and any call named `sanitize`, `sanitizeHtml`, `escapeHtml`, `escape` or `encode`; `encodeURIComponent` |
| URL and redirect | a literal start that fixes the scheme and host (`` `https://api.example.com/${x}` ``); for redirects also one that starts with `/` and a path character |
| Object keys | a file that names `__proto__`, `constructor` or `prototype` in a string; `.has(key)`, `.includes(key)` or `.hasOwnProperty(key)` earlier in the function; a target made with `Object.create(null)` or a `Map` |

**Rules in detail.**

- `js.exec.eval`: `eval(x)` (also `window.eval`) and `new Function(...)`/`Function(...)` when an argument is not a literal; `setTimeout`/`setInterval`/`setImmediate` with a built string (high) or a fixed string (**low**). A function or a name bound to one is fine.
- `js.child_process.shell`: `exec`/`execSync` with a built command, and `spawn`/`spawnSync`/`execFile`/`execFileSync` with `shell: true` (in an object literal or a name bound to one) and a command or argument array that is not literal. Also `spawn`/`spawnSync`/`execFile`/`execFileSync` with a shell as the program (`sh`, `bash`, `zsh`, `/bin/sh`, `cmd`, `cmd.exe`, `powershell`) and its command-string option (`-c`, `/c`, `-Command`) followed by a built script, and the built commands of `shelljs.exec`, `execa.command` and `execa.shell`. Request data reaching `exec` is reported even as a plain name, with a trace.
- `js.dom.xss_sink`: `.innerHTML`/`.outerHTML` `=` or `+=`, `insertAdjacentHTML`'s second argument, `document.write`/`writeln`, React `dangerouslySetInnerHTML` (JSX attribute or a `createElement` props key) with a non-literal `__html`, and jQuery `.html(x)` on `$(...)`, `jQuery(...)` or a `$name`. **Medium** by default, **high** when a `dom` source reaches the value.
- `js.sql.string_built`: `.query`, `.execute`, `.raw`, `.unsafe`, `$queryRawUnsafe` and `$executeRawUnsafe` whose first argument is built and whose literal text looks like SQL (`SELECT ... FROM`, `INSERT INTO`, `WHERE ... =` ...). Tagged templates such as `` sql`...${id}` `` (postgres.js, slonik) bind their values and are not reported.
- `js.tls.reject_unauthorized`: `rejectUnauthorized: false` as an object key, `x.rejectUnauthorized = false`, and `NODE_TLS_REJECT_UNAUTHORIZED` set to `'0'`/`0` through `process.env` or an `env` object.
- `js.crypto.weak_hash`: `crypto.createHash` with `'md5'`, `'md4'`, `'sha1'` or `'sha-1'` (any case).
- `js.crypto.insecure_random`: `Math.random()` in the value of a binding, member or object key whose name has token, secret, password, nonce, salt, otp, csrf or apikey in it, or key with api, secret, private, access, auth, signing, encryption, session or hmac; and in the return value of a function named that way. A bare `key` (React list keys), `cacheKey` and `queryKey` are not secrets.
- `js.jwt.no_verify`: `jsonwebtoken` `verify` with `algorithms` containing `'none'` (high) or `ignoreExpiration: true` (**low**). `jwt.decode` is not reported: it has legitimate uses (reading the header before verifying) that a token matcher cannot tell apart.
- `js.path.traversal` (`fs` read, write, list, stat, exists, rename, copy, mkdir, rmdir and remove functions, with the destination of a copy or a rename too; the same names of `fs-extra`; `res.sendFile` without a `root`; `res.download`), `js.ssrf.request` (`fetch`, `node-fetch`, `undici`, `axios` and its verbs or `{ url }` config, `got`, `superagent`, `http`/`https.get`/`request`), `js.redirect.open` (`res`/`response`/`ctx`/`reply`/`h` `.redirect`, last argument; `.location(x)`; `setHeader`/`header`/`set`/`append` of `Location`; `writeHead(30x, { Location: x })`) and the `obj[key] = v` form of `js.proto.pollution` fire only on `request` data. `js.proto.pollution` needs a nested key (`obj[a][b] = v`) or a request-controlled value, so counters such as `counts[req.query.c] += 1` stay quiet; it also reports lodash `merge`, `mergeWith` and `defaultsDeep` of request data.
- `js.cors.wildcard_credentials`: `cors({ origin: true | '*', credentials: true })`, and, in one function, `Access-Control-Allow-Origin` set to `*` or to the request's Origin (through `setHeader`/`header`/`set`/`append` or a headers object) together with `Access-Control-Allow-Credentials: true`.
- `js.redirect.open` also covers `redirect()` and `permanentRedirect()` from `next/navigation`, `NextResponse.redirect()` and `Response.redirect()`.
- `js.angular.bypass_trust`: `bypassSecurityTrustHtml`, `Url`, `Script`, `ResourceUrl` and `Style` called on any receiver with a value that is not a literal and not wrapped in a `sanitize*`/`escape*` call; **medium**, **high** when the value comes from the URL or `window.name` in the same function.
- `js.llm.output_to_sink`: `llm` data reaching `eval`/`Function`/a string timer (CWE-94), any `child_process` function (CWE-78) or an HTML sink (CWE-79), reported instead of the pattern rule on that line.

Tests check that a 5,000-line TypeScript file scans in under 2 s in-process (about 0.16 s measured on an M4 Pro) and that pathological input (100,000 chained assignments, 80,000 nested parentheses) stays linear.

## Web files

The web rules ([`web_rules.py`](../../packages/kestrix-scan/src/kestrix_scan/web_rules.py)) read HTML, Vue and Svelte files through a bounded tag scanner ([`html_tokens.py`](../../packages/kestrix-scan/src/kestrix_scan/html_tokens.py)) and CSS with a few comment-aware patterns. There is no HTML parser: the scanner finds start tags with their attributes and the bodies of `<script>` and `<style>`, and each rule matches one attribute shape.

**Tag scanner.** Start tags with double-quoted, single-quoted and bare attribute values (a `>` inside quotes does not end the tag), Svelte `{...}` values and `{...spread}` / `{shorthand}` attributes, balanced across nested braces and strings up to 8,192 characters; comments, declarations and CDATA are skipped, and the body of `<script>`, `<style>` and a non-HTML Vue `<template lang="pug">` runs to the closing tag. A script body is handed to the JavaScript rules behind blank lines and spaces, so a finding has the file's line and column, and `<style>` bodies go through the CSS rules the same way. Only `<script>` without a `type`, or `module`, `text/javascript` and `application/javascript` types, and `lang` of `js`, `ts`, `jsx` or `tsx` are scanned; JSON, `text/template` and other types are not. More than 200,000 start tags make the file `too_complex`; a tag keeps 256 attributes. Unterminated quotes, tags and comments end at the end of the file, and the work is linear in the file size (tests include 20,000 repeats of each pathological shape).

| Rule | Files | Severity | What it reports, and what it leaves alone |
| --- | --- | --- | --- |
| `vue.xss.v_html` | `.vue` | high / medium | `v-html` with a value that is not a literal; **high** when the expression reads the route (`$route`, `route.query`, `searchParams`, `location.search`), **medium** otherwise. Not reported: a literal, a call to `sanitize*`, `purify*` or `escape*`, a bare `$t('key')`. |
| `svelte.xss.at_html` | `.svelte` | high / medium | `{@html expr}` with the same rules, in markup only (not in `<script>`). |
| `web.url.dynamic_scheme` | `.vue`, `.svelte` | medium / low | `:href`, `v-bind:href`, `href={...}` on `a`/`area`, and `src`, `action`, `formaction` and `data` on the elements where they run a `javascript:` URL (`iframe`, `frame`, `embed`, `form`, `button`, `input`, `object`), bound to a value that is not a literal. **Low** unless the expression reads the route or URL (**medium**). Not reported: values that start with a literal `/`, `#`, `https://`, `http://`, `mailto:` or `tel:`, and `:src` on `img`. |
| `html.inline.event_handler` | `.html`, `.htm` | low | `onclick`, `onload` and every other `on...` attribute with a value. |
| `html.url.javascript_scheme` | `.html`, `.htm` | low | `href`, `src`, `action`, `formaction`, `data` or `xlink:href` starting with `javascript:`; the no-op `javascript:void(0)`, `javascript:;` and `javascript:undefined` are left alone. |
| `html.link.target_blank` | `.html`, `.htm` | low | `target="_blank"` on `a`/`area` with an absolute `http(s)` or `//` link and no `noopener` or `noreferrer` in `rel`. Relative links, and a `rel` that holds template syntax, are left alone. All current browsers imply `noopener`, so this is about older ones. |
| `html.form.http_action` | `.html`, `.htm` | medium | `<form action="http://...">`; loopback hosts are left alone. |
| `html.mixed.http_resource` | `.html`, `.htm` | low | `script src`, `iframe src`, `img src` and `link href` (for `stylesheet`, `preload`, `modulepreload` and `icon`) over `http:`; loopback hosts are left alone. |
| `html.angular.inner_html` | `.html`, `.htm`, inline `template:` strings in `.ts` | low | `[innerHTML]` and `[outerHTML]` bound to a value that is not a literal. Angular sanitizes these values, so this marks a place to check where a `bypassSecurityTrustHtml` result flows, not a vulnerability. |
| `css.import.http` | `.css`, `.scss`, `<style>` | low | `@import` and `url()` over `http:` (comments are ignored; loopback hosts are left alone). |
| `css.expression.legacy` | `.css`, `.scss`, `<style>` | low | `expression(...)` in a declaration (Internet Explorer 7 and older). |
| `next.images.wildcard_host` | `next.config.js`, `.mjs`, `.cjs`, `.ts` | low | `hostname: '**'` in `images.remotePatterns`. |

**Not reported, on purpose.** A missing Content-Security-Policy, or missing security headers in `next.config` `headers()`, is not flagged: a header check without knowing the deployment (a CDN, a reverse proxy, middleware) fires on most projects. The `html.*` rules do not run on `.vue` and `.svelte` templates, where `target="_blank"` links and `@click` handlers are idiomatic. Template engines that generate HTML (Jinja, Django, ERB, Blade, Handlebars) are read as HTML, so a `{{ }}` or `<% %>` value is not analyzed. Vue `:href` values that pass through a script variable are not traced into the script. The Claude Code hook reports medium severity and above, so the low-severity web rules appear in scans and CI, not in the hook's context.

## Claude Code and MCP configuration

The `config.*` rules read `.claude/settings.json`, `.claude/settings.local.json`, a plugin's `hooks/hooks.json` and `.mcp.json` ([`agent_config.py`](../../packages/kestrix-scan/src/kestrix_scan/agent_config.py)), with the field names from the Claude Code [settings](https://code.claude.com/docs/en/settings), [hooks](https://code.claude.com/docs/en/hooks), [permissions](https://code.claude.com/docs/en/permissions) and [MCP](https://code.claude.com/docs/en/mcp) documentation. These files are untrusted input: they are parsed with `json` after a 256 KiB size check (`too_large`; invalid JSON is `syntax_error`, pathological nesting `too_complex`), only the fields below are read, and nothing is run or expanded.

- `config.claude.hook_remote_exec`: a `command` hook that pipes `curl`, `wget`, `iwr` or `irm` into a shell or interpreter, runs `sh -c "$(curl ...)"` or `sh <(curl ...)`, or downloads a file with `-o`/`-O` and then runs it. The Check Point research on CVE-2025-59536 used repository hooks to run code when a project was opened.
- `config.claude.permissions_bypass`: `permissions.defaultMode` `bypassPermissions` (Claude Code 2.1.257 and newer ignore it in project settings; older versions do not), an `allow` rule `Bash`, `Bash(*)`, `PowerShell` or `PowerShell(*)`, and `enableAllProjectMcpServers: true`.
- `config.mcp.unpinned_launcher`: a server `command`/`args` of `npx -y` or `npx --yes` with a package that has no `@<version>`, or `uvx` / `uv tool run` with no `==<version>` or `@<version>` (also after `--from`). `npx` without `-y` is not reported.
- `config.mcp.secret_inline`: a credential in a server's `env`, `args`, `headers` (after `Bearer `) or `url`; `config.claude.env_leak`: one in the settings `env` block. Both use the secret detectors, take the matching `secret.*` rule's severity, are redacted the same way, and replace the `secret.*` finding on that line (with `rules.disable` for the config rule, the `secret.*` finding comes back). `${VAR}` references are fine.

JSON has no comments, so these findings cannot be suppressed inline; use `rules.disable` or a baseline.

**How the secret rules decide.** Provider rules match the documented shape of each credential and need at least 3.0 bits of entropy per character, which drops runs such as `ghp_xxxx…`. Values that contain placeholder words (example, changeme, test, your, xxxx, a `${...}` or `<...>`) are ignored, which also drops the AWS documentation key. A private key needs its base64 body, not just the `BEGIN` line. `secret.generic` needs a credential-like name (password, secret, api_key, token, client_secret and similar, but not names ending in `_url`, `_path`, `_env`, `_hash`, `_id` and similar) assigned a quoted value, or an unquoted `NAME=value` line as in `.env` files, and the value must be at least 16 characters, have at least 3.5 bits of entropy per character, mix character classes and not look like a URL, path, dotted name or environment-variable name. A provider match wins over a generic match of the same value. Severities: critical for live provider credentials and private keys; high for AWS access key ids, Google API keys, JWTs and generic credentials.

## Dependencies

Pinned dependency versions in lockfiles are checked against a local copy of [OSV](https://osv.dev), which aggregates the GitHub Advisory Database, the PyPA advisory database, the OpenSSF malicious-packages feed and others. The check is offline: build the index once with `kestrix-scan db update`, refresh it now and then, and every scan, hook and install-guard decision reads it.

```text
$ kestrix-scan db update --ecosystem PyPI npm
Updated ~/Library/Caches/kestrix-scan/osv.sqlite3 in 10.3 s.
Index: ~/Library/Caches/kestrix-scan/osv.sqlite3 (built 2026-10-20T01:14:58+00:00)
Age: 0.0 days
  PyPI: 25,776 advisories (11,827 malicious-package reports); downloaded 2026-10-20T01:14:49+00:00, 36.5 MB, sha256 9afc5a76…
  npm: 229,740 advisories (222,340 malicious-package reports); downloaded 2026-10-20T01:14:51+00:00, 218.6 MB, sha256 796ba88c…
```

**`db update`** downloads `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip` for each ecosystem ([OSV data dumps](https://google.github.io/osv.dev/data/)). It uses HTTPS only and refuses a redirect to anything else, refuses a download over 2 GiB (by `Content-Length` and by bytes received), checks that the body is a zip, and writes it to a temporary file before renaming it into place. The zip is kept in the cache with its ETag and Last-Modified, so the next update sends `If-None-Match` and `If-Modified-Since` and an unchanged export costs one 304 response. When every export is unchanged and already indexed the index is not rebuilt: `checked.json` next to it records the time of the check, and the index's age is counted from the last download or confirmation. A cached zip that is reused for a rebuild is first checked against its recorded SHA-256, and downloaded again if it does not match. Otherwise the index (`osv.sqlite3`) is rebuilt from every cached zip into a temporary file and renamed over the old one, so a scan never reads a half-written index. It records each export's URL, SHA-256, size and download time. Advisory files over 16 MiB, or a zip that unpacks to more than 8 GiB, are refused. Withdrawn advisories are left out. Sizes on 2026-10-20: PyPI 36.5 MB, npm 218.6 MB, index 86 MB; the whole update took 10 s on a fast connection. Export sizes measured with a HEAD request on 2026-10-23: Packagist 11.0 MB, Go 12.6 MB, crates.io 3.6 MB, Maven 10.4 MB, RubyGems 5.2 MB, NuGet 2.7 MB, Pub 0.03 MB (PyPI and npm as above).

**Which ecosystems.** `db update` without `--ecosystem` downloads the ecosystems of the dependency files found under the current directory (or `--path`), those already in the index and those in `db-ecosystems` of `[tool.kestrix]`; with no dependency file and no setting it downloads PyPI and npm. `--ecosystem X Y` names them, `--all` takes all nine: PyPI, npm, Packagist, Go, crates.io, Maven, RubyGems, NuGet, Pub.

**Where:** `$KESTRIX_SCAN_DB` when set; otherwise `~/Library/Caches/kestrix-scan` on macOS, `$XDG_CACHE_HOME/kestrix-scan` (default `~/.cache/kestrix-scan`) on Linux and `%LOCALAPPDATA%\kestrix-scan` on Windows. **`db status`** prints the index path, its age, whether it is stale and the counts per ecosystem; `db status --json` prints the same as JSON (it exits 1 without an index).

**Freshness.** The index is stale after 7 days by default; set `db-max-age-days` in `[tool.kestrix]`, or `KESTRIX_SCAN_MAX_AGE_DAYS` (which wins). A stale or missing index gives one `dep.db_stale` note in text, JSON and SARIF output (a SARIF `toolExecutionNotification`, not a result), never a finding or a failing exit code. The Claude Code hook adds one line to its context when a dependency file was edited and the index is stale or missing, `/kestrix:status` shows the index's age, and the install guard says its answer may be stale. An ecosystem the index holds no data for gives a `dep.ecosystem_missing` note naming the `db update --ecosystem` command, so a missing download is never read as a clean result. To keep results current, run `db update` daily: `kestrix-scan init --ci github` writes a workflow that does so on a schedule (below), and with pre-commit, which never refreshes the index, run `kestrix-scan db update` from cron or a scheduled job.

**Files read** (matched by name, anywhere the walk reaches; `node_modules` is never entered):

| File | What is checked |
| --- | --- |
| `requirements*.txt`, `requirements/*.txt` | exact pins only (`name==1.2.3`, `name===1.2.3`, extras and markers allowed). Other requirement lines (`>=`, `!=`, `~=`, `==1.*`, no version) are listed in one `dep.not_checked` note per file. Options, `-r`, `-e`, URLs and paths are skipped. |
| `uv.lock`, `poetry.lock`, `pdm.lock` | every `[[package]]` from a registry; workspace, path, git, URL and editable packages are skipped |
| `Pipfile.lock` | `default` and `develop` entries pinned with `==` |
| `package-lock.json`, `npm-shrinkwrap.json` | `lockfileVersion` 2 and 3 (`packages`); linked packages are skipped. Version 1 gets a `dep.unsupported` note. |
| `yarn.lock` | v1, and Berry (v2+) entries resolved with the `npm:` protocol |
| `pnpm-lock.yaml` | versions 5 to 9: the package keys under `packages:` and `snapshots:`, read line by line (no YAML parser) |
| `bun.lock` | Bun 1.2+ text lockfile, `packages` entries with a numeric version; workspace, git and alias entries are skipped. The binary `bun.lockb` gets a `dep.unsupported` note. |
| `composer.lock` (Packagist) | `packages` and `packages-dev`; branch versions (`dev-main`, `1.x-dev`) are listed as not checked. This covers PHP applications and their libraries. |
| `go.mod`, `go.sum` (Go) | `go.mod`: `require` lines with `replace` applied (a local-path replacement is skipped). `go.sum`: the highest hashed version of each module, since go.sum keeps superseded versions; prefer `go.mod`. Pseudo-versions are compared as SemVer pre-releases. |
| `Cargo.lock` (crates.io) | `[[package]]` from a registry; git, path and workspace crates are skipped |
| `pom.xml`, `gradle.lockfile` (Maven) | `pom.xml`: `<dependency>` elements with an exact version or one defined in the file's `<properties>`; versions from a parent POM or BOM, ranges and unresolved `${...}` are listed as not checked. `gradle.lockfile`: `group:artifact:version=` lines. |
| `Gemfile.lock` (RubyGems) | `specs:` of the `GEM` section (platform suffix dropped); git and path gems are skipped |
| `packages.lock.json` (NuGet) | resolved versions of non-project dependencies |
| `pubspec.lock` (Pub) | hosted packages from pub.dev |

**Matching.** A version is affected when an advisory lists it in `versions`, or it falls inside an `ECOSYSTEM` or `SEMVER` range: `introduced` opens an interval (`0` means from the start), `fixed` closes it before that version and `last_affected` after it. PyPI versions are compared by PEP 440 (epochs, pre-, post- and dev releases, local versions, normalized spellings); npm, Go, crates.io and Pub versions by SemVer 2.0 precedence, so a pre-release sorts before its release (a Go `v` prefix and `+incompatible` are accepted, and pseudo-versions such as `v0.0.0-20210101000000-abcdef123456` order by their timestamp); Packagist by Composer's rules (`-dev` < alpha < beta < RC < stable < patch); RubyGems by `Gem::Version` (a letter segment makes a pre-release); NuGet by SemVer with four numeric parts; Maven by a port of `ComparableVersion` (`1.0` = `1.0-ga` = `1.0.Final`, `alpha` < `beta` < `milestone` < `rc` < `snapshot` < release < `sp`). Each ordering is implemented here from the package manager's specification, with tests of the documented orderings. Kestrix implements both orderings itself rather than vendoring `packaging`, to keep zero dependencies and one license; the tests use the orderings listed in PEP 440 and SemVer. PyPI names are normalized as in PEP 503. A version, or an advisory range event, that cannot be parsed in its ecosystem is never silently skipped: the dependency gets a `dep.vulnerable` finding worded "possibly affected" with low confidence (an explicit `versions` entry still matches exactly).

**Findings.** All the advisories that affect one dependency make one finding on its lockfile line. Advisories that name each other as aliases (a GHSA, its PYSEC and its CVE) count as one vulnerability.

- `dep.malicious` (critical, CWE-506) when any of them is an OpenSSF `MAL-` report. The fix is to remove the package and rotate every credential on machines where it was installed.
- `dep.vulnerable` otherwise. Severity is the highest of the advisories': the CVSS v3 base score (computed from the vector: 9.0+ critical, 7.0+ high, 4.0+ medium, else low), else GitHub's `database_specific.severity` label, else medium. The CWE is the first in `database_specific.cwe_ids`, else CWE-1395. The message names `package@version`, the advisory ids (GHSA first, with the CVE), the first summary and the fixed versions; the fix is "Upgrade X to V or later", where V is the lowest version that fixes every vulnerability, and it says so when one has no fix.
- `dep.db_stale`, a note, not a finding: once per scan that found a dependency file, when there is no index or it is older than `db-max-age-days` (default 7). It never changes the exit code. `dep.ecosystem_missing` is the same kind of note for an ecosystem whose data was not downloaded.

The fingerprint's snippet is `name@version` plus the matching advisory ids, so a baselined finding comes back when a new advisory affects the same version. Rules, `exclude`, baselines, `--diff` and `--fail-on` apply as to other findings, and SARIF results point at the lockfile line.

```text
requirements.txt
  1:1  HIGH  dep.vulnerable  CWE-522
      requests@2.19.0 (PyPI) has 5 known vulnerability(ies): GHSA-9hjg-9r4m-mvj7 (CVE-2024-47081), GHSA-9wx4-h78v-vm56 (CVE-2024-35195), GHSA-gc5v-m9x4-r6x2 (CVE-2026-25645), GHSA-j8r2-6x86-q33q (CVE-2023-32681) (+1 more). Requests vulnerable to .netrc credentials leak via malicious URLs; fixed in 2.20.0, 2.31.0, 2.32.0, 2.32.4, 2.33.0.
      fix: Upgrade requests to 2.33.0 or later and update the lockfile.
```

**Suppression.** In a requirements file, `# kestrix: ignore[<rule id or advisory id>] reason` on the line or the line above drops the finding or that one advisory. Lockfiles have no comments, so for them (and everywhere) use `ignore-advisories` in [configuration](#configuration), with a reason per advisory.

**Not covered.** Reachability is not analyzed: a finding means the version is affected, not that your code calls the vulnerable function. The nine ecosystems above are indexed; Maven versions managed by a parent POM or BOM, unresolved properties and GIT-only advisory ranges are not evaluated. The PHP interpreter, a web server or any other runtime is not a lockfile dependency, so this check cannot see it: the website check's exposure finding covers server and runtime versions seen from outside. Unpinned requirements, `package.json` ranges and `pyproject.toml` dependency lists are not resolved; check the lockfile instead. Advisory data is as good as OSV's.

## Suppression

Add `# kestrix: ignore[rule-id] reason` on the finding's line or the line above. Several ids may be given, separated by commas. `// kestrix: ignore[...] reason` works the same way, for files with `//` comments, and so does `/* kestrix: ignore[...] reason */`, which is the only form JSX accepts (`{/* kestrix: ignore[js.dom.xss_sink] reason */}`). HTML, Vue, Svelte and Angular templates take `<!-- kestrix: ignore[rule-id] reason -->`; a `<script>` block takes the JavaScript forms and a `<style>` block or a `.css` file `/* ... */` (`//` in `.scss`).

```python
subprocess.run(deploy.command, shell=True)  # kestrix: ignore[py.subprocess.shell_true] command from the reviewed deploy config
```

The reason is required. A suppression without one suppresses nothing and adds a note with id `kestrix.suppression.missing_reason` to the report (the text output prints it as `note:`). Notes never change the exit code. The report counts suppressed findings in `suppressed`.

## Baselines and fingerprints

A fingerprint is the SHA-256 of the rule id, the path and the snippet with all whitespace removed. It leaves out the line number, so a finding keeps its fingerprint when code above it moves or its indentation changes. Two findings of the same rule on identical lines of one file share a fingerprint. For secrets the snippet is the redacted form, so replacing one secret with another of the same kind and prefix on the same line keeps the fingerprint.

To adopt the scanner on existing code: `kestrix-scan --write-baseline .kestrix-baseline.json`, commit the file, then run `kestrix-scan --baseline .kestrix-baseline.json` in CI, or set `baseline` in `[tool.kestrix]`. The report's `baseline_filtered` says how many findings the baseline left out.

## Report

`--format json` prints a `ScanReport` ([`models.py`](../../packages/kestrix-scan/src/kestrix_scan/models.py), a frozen dataclass whose `to_json()` gives this text). The keys and their order are stable; renaming or removing one is a breaking change recorded in the changelog:

| Field | Meaning |
| --- | --- |
| `schema_version`, `generated_by`, `notice` | `1`, `"Kestrix by Ruthvik Bandari"`, and the pattern-analysis notice |
| `root` | absolute scan root; finding paths are relative to it |
| `diff_base`, `fail_on` | the `--diff` ref (or null) and the failure threshold |
| `files_scanned` | files read and checked |
| `files_skipped` | `{path, reason}` with reason `binary`, `too_large`, `unreadable`, `syntax_error`, `too_complex`, `symlink_outside_root` or `minified` |
| `truncated` | true when the 20,000-file limit stopped the scan |
| `findings` | most severe first, then by path, line and column |
| `counts` | findings per severity |
| `suppressed`, `baseline_filtered` | findings left out by suppressions with a reason and by the baseline |
| `notes` | scanner notes, such as suppressions without a reason |
| `duration_ms` | wall-clock time of the scan |

Each finding has `rule_id`, `cwe`, `severity` (`low`, `medium`, `high`, `critical`), `confidence` (`low`, `medium`, `high`), `path`, `line`, `column`, `end_line`, `message`, `why`, `fix`, `snippet` (at most 200 characters; redacted for secrets) and `fingerprint`. Taint findings also have `trace`, a list of `{line, note}` from source to sink; the key is left out when there is no trace, so `schema_version` stays 1 and reports without taint findings are byte-for-byte unchanged.

## SARIF

`--format sarif` writes SARIF 2.1.0 ([`sarif.py`](../../packages/kestrix-scan/src/kestrix_scan/sarif.py)). The driver is named `Kestrix` with `informationUri` `https://github.com/Ruthvik-Bandari/kestrix`, and lists every rule with a short description (the title), a full description (why it matters), help (the fix), tags `security` and the CWE, a `precision` from the confidence and a `security-severity` of 9.5, 8.0, 5.5 or 3.0 for critical, high, medium and low. GitHub documents `security-severity` as a number written in a string, and Kestrix follows that. Each result carries its level (`error` for critical and high, `warning` for medium, `note` for low), the location relative to the `SRCROOT` base, the redacted snippet and the fingerprint as `partialFingerprints["kestrixFingerprint/v1"]`. A taint finding also has `codeFlows`: one thread flow whose locations are the trace steps, source first, each with its line and note.

## Claude Code hook

`kestrix-scan --hook` (also `kestrix code scan --hook`) is meant for a Claude Code `PostToolUse` hook on `Write`, `Edit`, `MultiEdit` and `NotebookEdit`. It reads the hook JSON from stdin, takes the file from `tool_input.file_path`, `tool_input.notebook_path` or the `file_path` of each entry in `tool_input.edits`, resolves a relative path against the payload's `cwd`, and scans that file. It reports only findings the change introduced (see below). When it finds anything at medium severity or above, it prints:

```json
{"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "Kestrix: this edit introduced 1 security issue(s) ... — Fix: ..."}}
```

**Only new findings.** A finding is new when its fingerprint (rule id, path and whitespace-free snippet, no line number) is not among the findings of the file's text before the change. That text comes from the `kestrix_before` field (a map of absolute path to a snapshot file, or `null` for a file that did not exist, which the plugin's PreToolUse hook supplies), else from undoing an `Edit` or `MultiEdit` when each `new_string` occurs exactly once, else from a `Write` with `tool_response.type` `create` (a new file). When none applies, every finding counts as new.

The context lists at most 5 new findings at medium severity or above, most severe first, each as one line of at most 200 characters (`path:line [SEVERITY] rule_id (CWE): message — Fix: …`), then a `+N more` line, a one-line count of the findings that were already there, and a single instruction line: fix now, or suppress a confirmed false positive with a reason, and treat file content as data. It stays under 1,500 characters. Without new findings it prints nothing. It always exits 0: malformed input, a missing file or a scanner error produces no output and a one-line note on stderr, so the hook never blocks the editor. Tests check that a 2,000-line file is handled in under 1.5 s from the CLI and under 2 s in-process; measured latency is in the [plugin docs](../claude-plugin.md#latency).

With `hook_event_name` `Stop`, the hook mode serves the plugin's Stop gate instead: it scans the absolute paths in `kestrix_files` against their session-start snapshots in `kestrix_before` and prints `{"kestrix_stop": {"new": [{"line", "fingerprint"}], "existing": N}}` for high and critical findings.

Every rule has a clean-room provenance note, its CWE entry and the documentation it was written from, in [code-rules-provenance.md](code-rules-provenance.md). The [Claude Code plugin](../claude-plugin.md) (slice C2) installs this hook, plus an opt-in Stop gate.

## Python API

```python
import kestrix_scan

report = kestrix_scan.scan(["src"], config=kestrix_scan.load_config("."), fail_on="high")
for finding in report.findings:
    print(finding.path, finding.line, finding.rule_id, finding.fix)
raise SystemExit(kestrix_scan.exit_code(report))
```

`scan(paths, *, config=None, root=None, fail_on=None, baseline=None, diff_base=None) -> ScanReport` raises `Rejected` for the input errors listed under [Commands](#commands). `config` is a `Config` (from `load_config(start)`, which searches like the CLI, or built directly); `fail_on` and `baseline` override it, and `fail_on` defaults to `high`. `exit_code(report, fail_on=None)` returns 0 or 1 using the report's threshold unless one is given. `rules()` lists the rule registry. `Finding` and `ScanReport` are frozen dataclasses with `to_dict()`; the package ships `py.typed`. `from kestrix.code import scan` keeps working in the workbench.

## Limits

- Code rules cover Python, JavaScript and TypeScript, plus the Claude Code and MCP configuration rules. The JavaScript and TypeScript rules use a tokenizer, not a parser: they match fixed shapes, follow names only through simple bindings, and read Vue, Svelte and HTML files only for the fixed shapes of the [web rules](#web-files), with no HTML parser and no component or cross-file analysis.
- Dependency checks cover the lockfiles of nine ecosystems (PyPI, npm, Packagist, Go, crates.io, Maven, RubyGems, NuGet, Pub), need `kestrix-scan db update` first, and cannot see a language runtime such as PHP itself.
- Data flow is local: taint is followed within one function, class body or module top level, never across functions or files, and through only the calls listed under [Taint analysis](#taint-analysis); `json.loads(request.data)` and a helper that builds a command are not followed. Literal propagation for the pattern rules follows names a few hops deep in the same scope.
- The secret rules are high-precision on purpose and miss credentials with no recognizable shape or name.
- Column numbers come from the parser's offsets and can be off on lines with non-ASCII characters before the finding.
