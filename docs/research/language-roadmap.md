# Language and framework roadmap for kestrix-scan

Status: Phase 1 (web stack) implemented 2026-10-23 and measured on tuning data only (see [the Phase 1 section of the CVE-fix benchmark](../benchmarks/cvefixes.md#phase-1-the-web-stack-tuning-numbers-2026-10-23)); its held-out `test3` is not yet run. Phase 3 (infrastructure as code and CI) implemented 2026-10-23 and measured on real files (see the Phase 3 section). Phase 2 (PHP and SQL) implemented 2026-10-24 and measured on a PHP benchmark with a one-time held-out run next to Psalm (see the Phase 2 section). Phases 4 and 5 are plans. Nothing is shipped as "measured" until its phase passes the measurement gate below.

## Why

Today `kestrix-scan` reads Python, JavaScript and TypeScript (including JSX/TSX), secrets in any text file,
Claude Code agent configuration, and dependency lockfiles. Most people who would install it also write PHP, SQL,
HTML, Vue or Next.js, ship Dockerfiles and CI workflows, and work in Go, Java, C# or Ruby. A scanner that covers
the stack a team actually uses gets used; one that covers a third of it gets uninstalled.

The order below weighs four things: how widely each language or framework is used (public surveys such as the
Stack Overflow Developer Survey and GitHub Octoverse), how many reviewed advisories its ecosystem has in the GitHub
Advisory Database, how often Claude Code users write it, and how much a lexical, zero-dependency scanner can say
about it truthfully.

## Ground rules for every phase

- **Zero runtime dependencies stays.** Each language gets a bounded, stdlib-only tokenizer like the JavaScript one,
  never a bundled compiler or a network call. Where a construct cannot be judged from tokens, the rule says less
  rather than guessing.
- **Every rule is explainable:** a CWE, a concrete fix, a positive and a negative test, and in-function taint where
  a source and a sink are involved.
- **Measured before it ships.** Each phase builds a project-disjoint benchmark from CVEfixes / GitHub Advisory
  Database fix commits in that language (as in [`docs/benchmarks/cvefixes.md`](../benchmarks/cvefixes.md)), tunes on
  a development split, and reports a one-time held-out result next to an established open-source tool for that
  language, where one is licensed for the use. A rule that raises false alarms without measurable detection is not
  shipped.
- **Dependency coverage first.** For a new language, lockfile checks against OSV usually deliver value before code
  rules do, and they are already being added (Composer, Go, Cargo, Maven/Gradle, RubyGems, NuGet, Pub).
- **Docs and the Claude plugin move with the scanner:** the rules reference, the plugin's hook coverage and the
  skill text list exactly what is supported.

## Phases

### Phase 1: the web stack (highest reach)

**Status: shipped in `kestrix-scan` (unreleased) with tuning numbers.** 13 rules and the Next.js, Fastify, Koa and NestJS sources are in; HTML, Vue, Svelte, CSS and `next.config` files are read; the Claude plugin hooks scan the new extensions. On the tuning data JavaScript and TypeScript detection moved 6.72% to 6.80% (+4 pairs, +0.2% alerts) and the web rules detect 27.4% [7.4, 50.9] of 73 in-scope web-file pairs (13 pairs by `vue.xss.v_html`; none before). Not done: the one-time held-out measurement (`research/hpc/codebench/codebench_heldout_future.sh` builds `test3` from advisories published after 2026-10-22), a comparison tool for web files (none is licensed for the use), and rule evidence for the CSS, mixed-content, form and `target="_blank"` checks (no detection data; they raise 0.47 findings per KLOC on 123 KLOC of other web files). A missing Content-Security-Policy in `headers()` is not flagged: too noisy. Table below is the original plan.

| Target | What the rules look for (examples) | Notes |
| --- | --- | --- |
| **Next.js** (App and Pages router) | Route handlers and API routes as request sources (`NextRequest`, `searchParams`, `params`, `req.query`), server actions receiving form data, `dangerouslySetInnerHTML`, `redirect()` with request input, `next.config` `images.remotePatterns` wildcards, missing security headers in `headers()` | Builds on the existing JS/TS taint engine |
| **Vue** (SFC) | `v-html` with non-constant values, `:href`/`:src` bound to user input (`javascript:` URLs), `<script setup>` analysed with the JS rules | Template parsing limited to directives |
| **Svelte, Angular** | `{@html …}`; `bypassSecurityTrust*`, `innerHTML` bindings | Same approach as Vue |
| **HTML** | Inline event handlers and `javascript:` URLs (CSP-hostile), `target="_blank"` without `rel="noopener"`, forms posting over `http:`, inline scripts using `eval`/`document.write`, mixed-content `http:` resources on `https` pages | Mostly low severity; useful for static sites |
| **CSS** | Remote `@import`/`url()` over `http:`, legacy `expression()` | CSS carries little risk on its own; this stays small and honest |
| **Node.js servers** (Express, Fastify, Koa, NestJS) | Already partly covered; widen sources/sinks per framework | Continues the round-2 work |

### Phase 2: PHP and SQL

**Status: shipped in `kestrix-scan` (unreleased), measured with a held-out run.** 9 `php.*` rules (command, include, SQL incl. Laravel and WordPress, echo/XSS, SSRF, file path, `extract`, `md5`/`sha1` of passwords, Blade `{!! !!}`), 3 `sql.*` rules (`GRANT ALL`, plaintext passwords, `SECURITY DEFINER` without `search_path`), a bounded PHP tokenizer, `.php`, `.phtml`, `.blade.php` and `.sql` read by the scanner and the Claude plugin hooks. On the held-out split of a PHP benchmark built from CVEfixes (1,121 in-scope pairs, 210 projects) the PHP rules detect **5.4% [2.8, 10.2]** next to Psalm 6.20.1's taint analysis at 3.3% [1.5, 6.7] (Kestrix minus Psalm +2.1 points [+0.8, +4.5]), at 0.80 alerts per KLOC on fixed files; dev numbers 5.3% and 0.97. No slowdown on the Python/JS/TS files. Written but **not shipped** for lack of dev detection: `unserialize`, `eval`/`assert`/`create_function` and `preg_replace` `/e`. Not done: advisory-database PHP pairs (the miner fetches Python/JS/TS only), the SQL and Blade rules have no detection data (no such files in the CVE data), `display_errors` and the WordPress nonce/capability checks, and the Python and JavaScript/TypeScript SQL-concatenation rules were left as they are (no extension was measured). Details: [PHP and SQL](../benchmarks/cvefixes.md#phase-2-php-and-sql-2026-10-24). Table below is the original plan.

| Target | What the rules look for (examples) |
| --- | --- |
| **PHP** | `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`php://input` flowing into `system`/`exec`/`shell_exec`/`passthru`/backticks (command injection), `include`/`require` (file inclusion), `mysqli_query`/`PDO::query` with concatenation (SQL injection), `echo`/`print` (XSS), `unserialize` (object injection), `file_get_contents`/`curl_exec` with a request URL (SSRF), `eval`, `assert` with strings, `extract($_REQUEST)`, `preg_replace` `/e`, `md5`/`sha1` for passwords, `display_errors` on |
| **Frameworks** | Laravel (`DB::raw`, `whereRaw` with input, `{!! !!}` in Blade), Symfony, WordPress plugins (`$wpdb->query` without `prepare`, missing nonce/capability checks where detectable lexically) |
| **SQL** | Queries built by string concatenation or interpolation in every supported language; in `.sql` files: `GRANT ALL`, plaintext credentials, `SECURITY DEFINER` functions without a fixed `search_path` |

Baselines for the measurement: PHP has strong OSS analyzers (for example Psalm's taint analysis); the benchmark will
use one whose licence allows it.

### Phase 3: infrastructure as code and CI (high value, easy to judge)

**Status: shipped in `kestrix-scan` (unreleased), measured as false alarms and tool agreement on real files (development numbers; there is no CVE-fix data for these formats and no held-out run).** 24 rules (`gha.*`, `docker.*`, `sh.*`, `tf.*`, `k8s.*`), a bounded YAML subset reader (no PyYAML), and the Claude plugin hook scans the new names. On 16,157 files of 1,090 public repositories plus 61 Terraform and Kubernetes projects the rules fire at, for example, 4.5 (`gha.action.unpinned`), 0.05 (`gha.pr_target.checkout_head`) and 0.03 (`gha.injection.untrusted_context`) findings per KLOC, and agree with zizmor, hadolint and checkov on 94% to 100% of the tool's files where the checks mean the same thing. Terraform is thin in the sample (no `0.0.0.0/0` in 309 files) so its three rules are checked mostly by tests and fixtures. Details: [Infrastructure and CI](../modules/code.md#infrastructure-and-ci). Not done: AWS-only Terraform (no Azure or Google), Helm templates, Docker Compose, CloudFormation.

| Target | What the rules look for (examples) |
| --- | --- |
| **GitHub Actions** | `pull_request_target` with a checkout of the PR head, `${{ github.event.* }}` interpolated into `run:` (script injection), unpinned third-party actions, over-broad `permissions` |
| **Dockerfile** | Running as root, `ADD` from URLs, `curl … \| sh`, `latest` tags, secrets in `ENV`/`ARG` |
| **Shell scripts** | `curl … \| sh`, `eval` of variables, unquoted variables in `rm -rf`, world-writable `chmod` |
| **Terraform / Kubernetes YAML** | Public storage buckets, `0.0.0.0/0` admin ports, privileged pods, `hostPath` mounts, missing encryption flags |

### Phase 4: other popular server languages

Go (`os/exec` with input, `template.HTML` of input, `InsecureSkipVerify`), Java and Kotlin (JDBC concatenation,
`Runtime.exec`, unsafe deserialization, XXE-prone parsers), C# (`SqlCommand` concatenation, `Process.Start`,
`BinaryFormatter`), Ruby on Rails (`find_by_sql`, `html_safe`, `constantize`, `send` with params). Each gets
dependency checks first (already in progress), then the highest-volume CWE families for that ecosystem from the
advisory data.

### Phase 5: systems languages (narrow, honest scope)

C and C++ (`gets`, `strcpy`, `sprintf`, `system`, format strings), Rust (`unsafe` blocks touching input, `Command`
with input), Swift (insecure TLS settings). Memory-safety bugs need real analysers; Kestrix will only flag the
lexically obvious patterns and say so.

## What "done" means for a phase

1. Tokenizer and rules with unit tests (positive and negative per rule), fuzz/pathological-input tests and a speed
   check (no more than 10% slower on mixed repositories).
2. A development and a one-time held-out measurement in [`docs/benchmarks/`](../benchmarks/), with the comparison
   tool and honest reading.
3. Rules reference, docs site pages, Claude plugin coverage (hooks scan the new file types) and skill text updated.
4. Released in `kestrix-scan`'s changelog with the measured numbers.

## Not planned

- Bundling a compiler front-end, a language server or a network service: it would break the zero-dependency,
  offline promise.
- Claiming coverage of a language before its benchmark exists.
