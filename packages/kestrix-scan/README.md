# kestrix-scan

**Local security checks for Python, JavaScript and TypeScript code, HTML, Vue, Svelte and CSS files, hard-coded secrets and dependencies.**
`kestrix-scan` finds shell and SQL injection, XSS sinks, unsafe deserialization, disabled TLS checks, weak hashes and
randomness, leaked API keys, and lockfile dependencies with known vulnerabilities or reported as malware, with a CWE and a concrete fix for every finding. It runs in your terminal, in CI with SARIF for GitHub code scanning, in
pre-commit and pytest, and inside Claude Code, where it has Claude fix what it finds while it writes code.

- **No dependencies** on Python 3.11 and newer (only `tomli` on 3.10). Python 3.10 to 3.13.
- **Nothing leaves your machine.** Files are read as data: never imported, executed or uploaded. Scans open no
  network connections. The only command that uses the network is `kestrix-scan db update`, which you run to
  download the public OSV vulnerability data; dependency checks read that local copy.
- **Fast to start:** `kestrix-scan --version` takes about 40 to 55 ms, a few milliseconds more than Python itself.

Part of [Kestrix](https://github.com/Ruthvik-Bandari/kestrix) by Ruthvik Bandari. Apache-2.0.

## Quick start

```bash
pip install kestrix-scan          # or: uv tool install kestrix-scan / pipx install kestrix-scan
kestrix-scan src                  # text report; exit 1 on high or critical findings
```

Before the first PyPI release, install it from GitHub:
`pip install "git+https://github.com/Ruthvik-Bandari/kestrix#subdirectory=packages/kestrix-scan"`.

```text
$ kestrix-scan app.py
app.py
  4:5  HIGH  py.subprocess.shell_true  CWE-78
      subprocess.run runs a built command through the shell (shell=True).
      fix: Pass the command as a list of arguments without shell=True, for example subprocess.run(['git', 'log', ref], check=True). Use shlex.quote only when a shell is unavoidable.

1 finding(s): 0 critical, 1 high, 0 medium, 0 low in 1 file(s); 0 suppressed, 0 in baseline, 0 skipped; fail-on high.
Rule-based pattern analysis on this machine. Rules miss things and can be wrong; no detection rate is claimed. No findings means no rule fired, not that the code is secure.
```

| Option | Meaning |
| --- | --- |
| `PATH ...` | Files or directories to scan (default `.`). Directories skip `.gitignore`d, vendored and build paths. |
| `--format text\|json\|sarif` | Output format. JSON has a `schema_version`; SARIF 2.1.0 is for GitHub code scanning. |
| `--output FILE` | Write the report to a file instead of stdout. |
| `--fail-on low\|medium\|high\|critical\|none` | Lowest severity that makes the command exit 1 (default `high`, or `[tool.kestrix]` `fail-on`). |
| `--diff REF` | Only report findings on lines changed since a git ref (untracked files count as new). |
| `--baseline FILE` / `--write-baseline FILE` | Leave out known findings / record the current ones, to adopt the scanner gradually. |
| `--config FILE` / `--no-config` | Use one settings file / ignore settings files. |
| `--hook` | Claude Code hook mode: read the hook JSON on stdin; always exit 0. |

**Exit codes:** 0 nothing at or above `--fail-on`, 1 findings at or above it, 2 usage or input error.
`kestrix-scan rules` lists every rule; `kestrix-scan --help` lists the commands. `python -m kestrix_scan` works too.

Silence a confirmed false positive on its line, or the line above, with a reason (required):

```python
subprocess.run(
    deploy.command, shell=True
)  # kestrix: ignore[py.subprocess.shell_true] command from the reviewed deploy config
```

## Dependency scanning

```bash
kestrix-scan db update                    # downloads the OSV data for the ecosystems your lockfiles use (the only network step)
kestrix-scan .                            # lockfiles are now checked too, offline
kestrix-scan db status                    # where the index is, how old, how many advisories
```

`db update` downloads the [OSV](https://osv.dev) export of each ecosystem
(`https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip`) over HTTPS, with a 2 GiB cap,
keeps it in your cache directory (`$KESTRIX_SCAN_DB`, or `~/Library/Caches/kestrix-scan`,
`$XDG_CACHE_HOME/kestrix-scan`, `%LOCALAPPDATA%\kestrix-scan`) and builds a SQLite index from it, recording
each download's SHA-256 and time. The exports include the OpenSSF malicious-packages feed. On 2026-10-20
PyPI was 36.5 MB and npm 218.6 MB, and the index 86 MB; on 2026-10-23 Packagist was 11.0 MB, Go 12.6 MB, Maven 10.4 MB,
RubyGems 5.2 MB, crates.io 3.6 MB, NuGet 2.7 MB and Pub 0.03 MB. Without `--ecosystem`, `db update` downloads only the
ecosystems of the dependency files it finds (plus those already indexed and `db-ecosystems` from `[tool.kestrix]`;
PyPI and npm when there are none); `--ecosystem Go Packagist` names them and `--all` takes all nine. A repeat
update sends `If-None-Match` and `If-Modified-Since`: an unchanged export is a 304 and the index is not rebuilt.

Scans then read `requirements*.txt` (exact `==` pins; other lines are noted as not checked), `uv.lock`,
`poetry.lock`, `pdm.lock`, `Pipfile.lock`, `package-lock.json` (v2 and v3), `yarn.lock` (v1 and Berry),
`pnpm-lock.yaml`, `bun.lock`, `composer.lock` (PHP), `go.mod`/`go.sum`, `Cargo.lock`, `pom.xml`/`gradle.lockfile`,
`Gemfile.lock`, `packages.lock.json` (NuGet) and `pubspec.lock`, and match each version against the advisories with
the ecosystem's own ordering (PEP 440, SemVer, Composer, RubyGems, NuGet, Maven). A version that cannot be compared is
reported as "possibly affected" at low confidence, never skipped:

```text
package-lock.json
  12:1  CRITICAL  dep.vulnerable  CWE-1321
      minimist@1.2.0 (npm) has 2 known vulnerability(ies): GHSA-vh95-rmgr-6w4m (CVE-2020-7598), GHSA-xvch-5gv4-984h (CVE-2021-44906). Prototype Pollution in minimist; fixed in 1.2.3, 1.2.6.
      fix: Upgrade minimist to 1.2.6 or later and update the lockfile.
  15:1  CRITICAL  dep.malicious  CWE-506
      react-0b1@1.0.0 (npm) is reported as a malicious package: GHSA-8ghv-p6hq-5px9 (MAL-2023-722). Malicious code in react-0b1 (npm)
      fix: Remove react-0b1 from the project and its lockfile, then rotate every credential, token and key on machines where it was installed.
```

- `dep.vulnerable`: the advisories' highest CVSS severity, their CWE, ids and summary, and "Upgrade X to V or
  later" with the lowest version that fixes all of them. `dep.malicious`: critical; remove it and rotate
  credentials.
- A `dep.db_stale` note (never a failure) in text, JSON and SARIF output when the index is missing or older than
  `db-max-age-days` (default 7; `KESTRIX_SCAN_MAX_AGE_DAYS` overrides). The Claude hook, `/kestrix:status` and the install
  guard say so too. `dep.ecosystem_missing` notes an ecosystem the index has no data for.
- Suppress with `# kestrix: ignore[GHSA-...] reason` on a requirements line, or for any file with
  `ignore-advisories = {"GHSA-..." = "reason"}` in `[tool.kestrix]`. Baselines, `--diff` and `fail-on` apply.
- Reachability is not analyzed. A language runtime (for example the PHP interpreter) is not a lockfile dependency and is
  not checked; the website check's exposure finding covers server and runtime versions. Details:
  [docs/modules/code.md](https://github.com/Ruthvik-Bandari/kestrix/blob/main/docs/modules/code.md#dependencies).

## Configuration

`[tool.kestrix]` in `pyproject.toml`, or the same keys at the top level of `.kestrix.toml`:

```toml
[tool.kestrix]
fail-on = "medium"                              # low, medium, high, critical or none
exclude = ["tests/fixtures/", "*.min.js"]       # globs, as in .gitignore
baseline = ".kestrix-baseline.json"             # relative to this file
rules.enable = ["py.", "secret."]               # rule ids or prefixes; default: every rule
rules.disable = ["py.crypto.weak_hash"]
ignore-advisories = {"GHSA-xxxx-xxxx-xxxx" = "not reachable: we never parse untrusted XML"}
claude.install-guard = false                    # turn off the Claude Code install guard here
db-max-age-days = 7                             # warn when the OSV index is older than this
db-ecosystems = ["PyPI", "npm", "Go"]           # extra ecosystems for `db update`
```

- The nearest file wins, searching upwards from the scan root and stopping at the git root. In each directory
  `.kestrix.toml` is read before `pyproject.toml`; a `pyproject.toml` without `[tool.kestrix]` is skipped.
- Command-line flags override the file.
- An unknown key is a warning. An unknown rule id or prefix is an error (exit 2) with a suggestion, so a
  typo never silently disables nothing.
- Excludes apply to files named on the command line too, which is how pre-commit passes them.

## Set up a project: `kestrix-scan init`

```bash
kestrix-scan init                        # append a minimal [tool.kestrix] to pyproject.toml
kestrix-scan init --pre-commit           # add the pre-commit hook
kestrix-scan init --ci github            # write .github/workflows/kestrix.yml
kestrix-scan init --claude-plugin        # install the Claude Code plugin
```

`init` appends to `pyproject.toml` as text and never rewrites it; it leaves an existing `[tool.kestrix]`
alone unless you pass `--force`. Without a `pyproject.toml` it writes `.kestrix.toml`. It writes
`.pre-commit-config.yaml` only when it is missing or empty, and otherwise prints the entry to add. Running
it again is safe: each step reports what is already in place.

## pre-commit

```yaml
repos:
  - repo: https://github.com/Ruthvik-Bandari/kestrix
    rev: v0.1.0
    hooks:
      - id: kestrix-scan
```

The hook scans the staged Python and text files, lockfiles included, and honours `[tool.kestrix]`. Dependency results
use the local index and pre-commit never refreshes it, so run `kestrix-scan db update` daily (cron, a scheduled job or
the CI workflow below); a stale index is reported as a note.

## GitHub code scanning

`kestrix-scan init --ci github` writes a workflow that runs on every push and pull request and daily at 05:17 UTC, so a
vulnerability published tomorrow in a locked dependency appears without a commit. It caches the OSV download directory
(`actions/cache`), so the daily refresh is a conditional request per ecosystem. Its actions are pinned to commit SHAs and
its job has only `contents: read` and `security-events: write`. The steps that matter:

```yaml
- run: pip install kestrix-scan==0.1.0
- run: kestrix-scan db update        # downloads the OSV data of your lockfiles' ecosystems; needs network access
- run: kestrix-scan --format sarif --output kestrix.sarif || true
- uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
  with:
    sarif_file: kestrix.sarif
```

Findings then appear under **Security → Code scanning**. To fail the build instead, drop `|| true`.

## pytest

```bash
pytest --kestrix                          # adds one "kestrix-scan" item that scans the rootdir
pytest --kestrix --kestrix-fail-on=medium
```

The item fails when findings meet the threshold (default: `[tool.kestrix]` `fail-on`, else `high`), and its
failure report is the scanner's text report. Without `--kestrix` the plugin only registers its options; the
scanner is not even imported.

## Claude Code plugin

```bash
kestrix-scan install-claude-plugin        # copies the plugin to ~/.claude/kestrix-plugin
claude plugin marketplace add ~/.claude/kestrix-plugin
claude plugin install kestrix@kestrix-local
```

Or from the repository's marketplace: `/plugin marketplace add Ruthvik-Bandari/kestrix`, then
`/plugin install kestrix@kestrix`. Nothing in your Claude Code settings changes until you run those commands.

- **After every Write or Edit** the plugin runs `kestrix-scan --hook` on the changed file and hands Claude the
  findings the edit introduced, with the rule, CWE and fix, so Claude fixes them in the same turn.
- **Skills and commands:** `secure-code-review`, a per-rule `fixing-security-findings` playbook,
  `/kestrix:scan`, `/kestrix:fix` and `/kestrix:review` (a review of the current git diff).
- **Install guard:** before a `pip`, `uv`, `npm`, `pnpm`, `yarn`, `bun`, `composer require`, `go get`, `cargo add`, `gem install` or `dotnet add package` install runs, the plugin checks the packages
  against the local OSV index. A known malicious package is denied; a known-vulnerable pinned version gets a
  warning naming the fixed version. No index means no check; an old index adds a line saying the result may be stale. Turn it off with `KESTRIX_INSTALL_GUARD=0` or
  `claude.install-guard = false`.
- **Opt-in Stop gate:** with `KESTRIX_BLOCK_ON_STOP=1`, Claude cannot finish while new high or critical
  findings remain in files it changed (at most three times per session).
- **Fails open:** a missing scanner, a timeout or an error never blocks an edit. Findings never contain secret
  values, only their kind and first four characters.

`kestrix-scan install-claude-skill` installs only the `kestrix-security` skill;
`package-claude-plugin` and `package-claude-skill` write zips. Full details:
[docs/claude-plugin.md](https://github.com/Ruthvik-Bandari/kestrix/blob/main/docs/claude-plugin.md).

## Python API

```python
import kestrix_scan

config = kestrix_scan.load_config("src")  # [tool.kestrix] or .kestrix.toml, if any
report = kestrix_scan.scan(["src"], config=config, fail_on="high")
for finding in report.findings:  # kestrix_scan.Finding: frozen dataclass
    print(finding.path, finding.line, finding.rule_id, finding.cwe, finding.fix)
print(report.to_json())  # the same JSON as --format json
raise SystemExit(kestrix_scan.exit_code(report))

for rule in kestrix_scan.rules():  # the registry, in its stable order
    print(rule.id, rule.severity, rule.cwe, rule.title)
```

`scan` raises `kestrix_scan.Rejected` for a missing path, a bad baseline, an unknown git ref or bad
settings. The package is typed (`py.typed`).

## Privacy

`kestrix-scan` reads files as bytes, decodes them as text, parses Python with the standard-library `ast` and
splits JavaScript and TypeScript with its own bounded tokenizer.
It never imports or runs the code it scans, never follows symbolic links out of the scan root, and caps
file size and count. Scans, the plugin hooks and the install guard make no network requests; the test suite
proves they work with every socket call refused. The one exception is `kestrix-scan db update`, which you run
explicitly: it downloads the public OSV exports over HTTPS and sends nothing about your project. `--diff` and directory walks run the local `git` binary.

## Rules

There are 76 rules. They cover Python (30 `py.*` rules: `eval`/`exec`, `shell=True` and `os.system`, pickle and
unsafe YAML, tar extraction without a filter, SQL built from strings, disabled TLS checks, MD5/SHA-1, `random` for secrets, `tempfile.mktemp`,
Flask debug, unverified JWTs, stdlib XML parsers, Jinja2 environments without autoescape, `assert` for access checks, and, through intraprocedural taint
analysis from Flask (including route parameters), Django, FastAPI, Starlette, aiohttp, Tornado and LLM-client sources, path traversal, SSRF, open redirects, XSS/SSTI and
LLM output reaching code, a shell, SQL or a path; plus unsafe model loading), JavaScript and TypeScript (16 `js.*`
rules for `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.mts` and `.cts`: `eval` and `new Function`,
`child_process` shells, DOM and React HTML sinks, SQL built from strings, `rejectUnauthorized: false`, MD5/SHA-1,
`Math.random()` for secrets, JWT `none` and `ignoreExpiration`, Express, Koa and hapi request data (including the request URL) reaching files, URLs and
redirects, prototype pollution, wildcard CORS with credentials, Angular `bypassSecurityTrust*`, and LLM output reaching `eval`, a shell or HTML; request
sources also include Next.js route handlers, `params` and server-action `FormData`, Fastify, Koa and NestJS decorators),
web files (12 rules in `vue.*`, `svelte.*`, `web.*`, `html.*`, `css.*` and `next.*` for `.vue`, `.svelte`, `.html`, `.htm`,
`.css`, `.scss` and `next.config.*`: `v-html` and `{@html}` with a non-literal value, `javascript:` links, inline event
handlers, `target="_blank"` without `noopener`, forms and subresources over `http:`, Angular `[innerHTML]`, remote CSS over
`http:` and `expression()`, and a `**` image host in `next.config`; mostly low severity, with `<script>` blocks run through the
`js.*` rules), Claude Code and MCP configuration
(5 `config.*` rules: hooks that run downloaded scripts, permission bypasses, unpinned `npx -y`/`uvx` servers and
literal credentials), secrets in any text file (11 `secret.*` rules: AWS, GitHub, Slack, Stripe, Google, Anthropic
and OpenAI-style keys, private keys, JWTs and high-entropy credentials), and dependencies in lockfiles (2 `dep.*`
rules: `dep.vulnerable`, `dep.malicious`). The full table with CWEs and severities is in
[docs/modules/code.md](https://github.com/Ruthvik-Bandari/kestrix/blob/main/docs/modules/code.md#rules), and
each rule's sources are in
[docs/modules/code-rules-provenance.md](https://github.com/Ruthvik-Bandari/kestrix/blob/main/docs/modules/code-rules-provenance.md).

**JavaScript and TypeScript: precision first, no full parser.** The scanner stays dependency-free, so it does not
ship a JavaScript parser. A bounded tokenizer (strings, nested templates, comments, regex versus division, JSX and
TypeScript annotations) feeds a structural matcher that knows calls, member chains, assignments, object keys, JSX
attributes, function scopes and `import`/`require` aliases, plus a light same-function taint for Express request
data, the URL and LLM output. Every rule matches a precise shape and stays quiet when the code is ambiguous, so it
misses more than a parser-based tool would, by design. Minified files (a `.min.` name or an average line over 500
characters) are skipped as `minified`. Vue, Svelte and HTML files are read with a bounded tag scanner (no HTML parser): the
template rules look at directives and attributes, `<script>` bodies go through the JavaScript rules with the file's line
numbers, and a missing Content-Security-Policy is deliberately not reported.

Rules are pattern analysis: they miss things and can be wrong in context. No real-world detection rate is
claimed, and no findings means no rule fired, not that the code is secure. A
[benchmark scorecard](https://github.com/Ruthvik-Bandari/kestrix/blob/main/docs/benchmarks/benchmarkpython.md)
measures category coverage on synthetic code (OWASP BenchmarkPython v0.1 and the project's own labelled cases)
against Bandit and the security-guidance regex layer, including the categories where Kestrix loses. Rule ids are stable; renaming one is a breaking
change recorded in the [CHANGELOG](CHANGELOG.md).
