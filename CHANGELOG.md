# Changelog

All notable changes to Kestrix are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may change commands, report fields or API routes; each such change is listed here.

## [Unreleased]

### Changed

- **`kestrix-scan` Python rules, informed by the benchmark's gap analysis.** Five new rules (reflected XSS, LDAP and
  XPath injection, insecure cookies, session trust boundary), shells started through an argument list, a `weak_random`
  taint kind, more propagators, sanitizers and guards, constant-aware pattern rules, and an XXE rule that follows the
  Python documentation. On BenchmarkPython v0.1 the score went from 15.8 to 39.5, a number that is no longer blind. A
  held-out set of 44 owned pairs went from 16.7 to 100.0, and it was written by the same author. Details and
  disclosure in [docs/benchmarks/benchmarkpython.md](docs/benchmarks/benchmarkpython.md) and
  [packages/kestrix-scan/CHANGELOG.md](packages/kestrix-scan/CHANGELOG.md).

### Added

- **Code scanner benchmark and scorecard (roadmap item 3 of
  [docs/research/competitive-landscape-2026-10.md](docs/research/competitive-landscape-2026-10.md)).**
  `uv run python -m bench.run` downloads OWASP BenchmarkPython at a pinned commit into the git-ignored
  `bench/.cache/` (never committed), installs Bandit and Semgrep CE into an isolated environment there, and scores
  them, `kestrix-scan` and the security-guidance regex layer per category (TP/FP/TN/FN, TPR, FPR, Youden index,
  plus a strict-CWE mode as in BenchmarkUtils). `bench/cases/` adds 87 owned, labelled cases (AI-written-style Python
  pairs with taint and LLM-output cases, and Claude Code / MCP configuration). The scorecard is
  [docs/benchmarks/benchmarkpython.md](docs/benchmarks/benchmarkpython.md); on BenchmarkPython v0.1, Bandit scores
  higher overall than `kestrix-scan` (17.5 against 15.8). Semgrep's numbers are not published (Semgrep Rules
  License). A weekly and manual workflow, `bench.yml`, uploads the results as an artifact.
- **JavaScript and TypeScript rules in `kestrix-scan` (ADR 0005 slice C3, roadmap item 9).** 14 `js.*` rules
  (eval, `child_process` shells, DOM and React HTML sinks, SQL built from strings, disabled TLS checks, weak hashes,
  `Math.random()` secrets, JWT `none`/`ignoreExpiration`, Express path traversal, SSRF and open redirects,
  prototype pollution, wildcard CORS with credentials, and LLM output reaching code, a shell or HTML) on a
  dependency-free tokenizer and structural matcher, precision first. Minified files are skipped as `minified`.
  Details in [packages/kestrix-scan/CHANGELOG.md](packages/kestrix-scan/CHANGELOG.md) and
  [docs/modules/code.md](docs/modules/code.md#javascript-and-typescript).
- **`kestrix-scan` taint analysis and AI-era rules.** Intraprocedural taint tracking for the Python injection
  rules with traces in JSON (`trace`), SARIF (`codeFlows`), text and hook output; new rules for SSRF, open
  redirects, XSS/SSTI, LLM output reaching code, shell, SQL or paths, unsafe model loading, and risky Claude Code
  and MCP configuration (`config.*`). Details in
  [packages/kestrix-scan/CHANGELOG.md](packages/kestrix-scan/CHANGELOG.md) and
  [docs/modules/code.md](docs/modules/code.md#taint-analysis).
- **Offline dependency scanning in `kestrix-scan` (roadmap item 5 of
  [docs/research/competitive-landscape-2026-10.md](docs/research/competitive-landscape-2026-10.md)).**
  `kestrix-scan db update` downloads the OSV PyPI and npm exports, including the OpenSSF malicious-packages
  feed, into a local index; scans then report `dep.vulnerable` and `dep.malicious` findings in Python and npm
  lockfiles without network access, and the Claude Code plugin gains an install guard that denies a known
  malicious `pip`/`uv`/`npm`/`pnpm`/`yarn` install. See
  [docs/modules/code.md](docs/modules/code.md#dependencies) and
  [docs/claude-plugin.md](docs/claude-plugin.md#pretooluse-on-bash-the-install-guard).
- **`kestrix-scan`, the code scanner as its own package (ADR 0006,
  [packages/kestrix-scan](packages/kestrix-scan/README.md)).** `pip install kestrix-scan` installs the scanner
  and the Claude Code plugin with no dependencies on Python 3.11+ (`tomli` on 3.10). Its own changelog is
  [packages/kestrix-scan/CHANGELOG.md](packages/kestrix-scan/CHANGELOG.md). New with it:
  - `[tool.kestrix]` / `.kestrix.toml` configuration (`fail-on`, `exclude`, `rules.enable`, `rules.disable`,
    `baseline`); unknown rule ids are an error with a suggestion;
  - `kestrix-scan init [--ci github] [--pre-commit] [--claude-plugin] [--force]`;
  - a pre-commit hook (`.pre-commit-hooks.yaml`), a pytest plugin (`pytest --kestrix`) and the typed API
    `kestrix_scan.scan`, `Finding`, `rules()`, `load_config`;
  - `kestrix-scan rules`, `kestrix-scan version` and `python -m kestrix_scan`.
- **Release workflow** (`.github/workflows/release.yml`): on a `v*` tag it builds both packages, attests their
  build provenance and publishes them with PyPI trusted publishing. One-time setup: [docs/release.md](docs/release.md).
- **Code security scanning (`kestrix code scan`, ADR 0005 slice C1).** A local, rule-based scanner for source code.
  - **Python rules** over the standard-library AST, with import and alias resolution and literal propagation within a function: `eval`/`exec`/`compile` of non-literals, `shell=True` and `os.system`/`os.popen` with built commands, pickle-style and unsafe YAML deserialization, SQL built from strings, disabled TLS verification, MD5/SHA-1, `random` for secrets, `tempfile.mktemp`, Flask debug mode, unverified JWTs, stdlib XML parsers, `assert` for access checks and request-derived file paths.
  - **Secret rules** for any text file: AWS, GitHub, Slack, Stripe, Google, Anthropic and OpenAI-style keys, private keys, JWTs, and entropy-gated generic assignments. Secret values never appear in any output; only the kind and the first four characters do.
  - Text, JSON and SARIF 2.1.0 output; exit codes 0/1/2 with `--fail-on`; inline suppressions that require a reason; fingerprint baselines (`--baseline`, `--write-baseline`); `--diff BASE` for changed lines only; `--hook` for Claude Code `PostToolUse` hooks (always exits 0).
  - The walker honors `.gitignore` (through git when available), skips dependency and build directories, binary files, files over 1 MiB and links out of the scan root, and stops at 20,000 files.
  - Python API `kestrix.code.scan`. Rules table in `docs/modules/code.md`, generated by `scripts/build_code_rules_doc.py`. No detection rates are claimed.
- **Claude Code plugin `kestrix` (ADR 0005 slice C2, [docs/claude-plugin.md](docs/claude-plugin.md)).** It ships in the wheel under `kestrix/integrations/claude_plugin/kestrix/`, and the repository root has a marketplace (`.claude-plugin/marketplace.json`) for `/plugin marketplace add Ruthvik-Bandari/kestrix`.
  - **PostToolUse hook** on `Write|Edit|MultiEdit|NotebookEdit`. It runs `kestrix code scan --hook` on the changed file and returns medium-or-worse findings as `additionalContext`, so Claude fixes them in the same turn or suppresses a confirmed false positive with a reason. It fails open, and when `kestrix` is not on PATH it shows a single hint per session.
  - **Opt-in Stop gate** (`KESTRIX_BLOCK_ON_STOP=1`, or `{"claude": {"block_on_stop": true}}` in `.kestrix.json`). It blocks finishing while files changed this session have high or critical findings. It respects `stop_hook_active` and blocks at most 3 times per session.
  - **SessionStart hook** that adds one line of context when `kestrix` is available.
  - **Hook script:** a stdlib-only Python script (3.9+) that stores session state under `CLAUDE_PLUGIN_DATA`.
  - **Skills:** `secure-code-review`; `fixing-security-findings`, generated from the rule registry by `scripts/build_claude_fix_playbook.py`, with before and after code that tests scan; and `kestrix-security`.
  - **Commands:** `/kestrix:scan`, `/kestrix:fix` and `/kestrix:review`.
- `kestrix integrations install-claude-plugin [--dest DIR] [--force]` copies the plugin, together with a `kestrix-local` marketplace, to a directory (default `~/.claude/kestrix-plugin`) and prints the `claude plugin marketplace add` and `claude plugin install` commands. It never edits Claude Code settings. `package-claude-plugin --out FILE.zip [--force]` writes a reproducible zip for `claude --plugin-dir`. Both apply the same symlink and overwrite safety as the skill installer.
- `kestrix code scan --hook` also reads `tool_input.notebook_path`, so `NotebookEdit` changes are scanned.

### Changed

- **Python 3.10 and newer** (was 3.12). `enum.StrEnum` became `kestrix.core.enums.TextEnum`, whose members
  still print and serialize as their value; `datetime.UTC` became `timezone.utc`. On 3.10, uv resolves
  Starlette 1.7 (1.8 needs 3.11); no advisory affects 1.7.
- **The scanner and the Claude Code plugin moved to `kestrix-scan`.** `kestrix` depends on `kestrix-scan==0.1.0`.
  `kestrix code scan` and `kestrix integrations ...` run the `kestrix-scan` commands with the same options,
  output and exit codes; `kestrix.code` re-exports the API, and `kestrix.code.models`, `.rules` and the other
  old submodules still import. The report models are now frozen dataclasses (`to_dict()`, `to_json()`)
  instead of pydantic models; the JSON report is byte-identical. The plugin's hooks run `kestrix-scan`
  first and fall back to `kestrix code scan`.
- **Faster CLI start:** module command groups load on first use, so `kestrix --help` takes about 90 ms instead
  of 340 ms and `kestrix code scan` no longer imports FastAPI, pySigma or pydantic.
- **Security review fixes (hosted mode).** An independent review found no authentication, session, CSRF or SSRF bypass. The following were fixed.
  - **Resource abuse:**
    - email header-parameter bombs are rejected before parsing, in both modes;
    - hosted analyses run in isolated worker processes with CPU, memory and time limits;
    - website checks have a true 10-second deadline;
    - one request at a time per user, at most 2 analyses and 8 website checks at once;
    - 10 MiB hosted uploads.
  - **Website check:** ports 80 and 443 only, and generic connection errors.
  - **Sign-in limits:** cross-site sign-in starts are refused, IPv6 is limited per /64, and the limiter evicts fairly.
  - **Errors:** a JSON 500 with security headers.
  - **Deletion:** secure delete, ids that are never reused, and the user's limiter counters cleared.
  - **Operators:** `kestrix hosted disable-user` / `enable-user` / `hash-host` for abuse handling.
  - **Responses:** `Cache-Control: no-store` on hosted API responses, and no public OpenAPI schema.
  - **Parser robustness:** three parser crashes found by fuzzing.
  - **Docs:** corrected wording.
- **Hosted-mode interface:** when the server runs in hosted mode, the landing page is at `/` and the dashboard at `/app`. Visitors sign in with Google or GitHub on `/signin`; an account menu offers sign-out and account deletion (type DELETE to confirm). Every write sends the CSRF token, a 401 leads to sign-in, rate-limit replies show when to retry, and only the website check, forensics and email check appear. The website check asks for an "I own this website or am authorized to test it" confirmation. Draft privacy notice and terms of use pages (`/privacy`, `/terms`, and `docs/legal/`) are marked for the owner's review before launch. Local mode is unchanged.
- **Deployment:** a hardened container image (`Dockerfile`: pinned base images by digest, hash-checked dependencies, non-root uid 10001, read-only root filesystem, no pip) and a Fly.io configuration (`fly.toml`, one machine, SQLite on a volume) with a step-by-step guide in `docs/deploy.md`. CI builds the image and smoke-tests it read-only.
- `KESTRIX_CLIENT_IP_HEADER` names a header the platform proxy overwrites with the client address (Fly: `Fly-Client-IP`), so sign-in rate limits are per visitor behind a proxy. It cannot be combined with `KESTRIX_TRUST_PROXY_HEADERS`; `docs/deploy.md` has a post-deploy spoofing check.
- **Landing page as "without vs with Kestrix" stories:** six interactive chapters (a fake invoice email, a detection rule silenced by a field rename, a program disguised as a PDF, a deceptive link, a weak website, exposed Bitcoin keys) with a draggable comparison beam and a keyboard toggle. Every verdict, finding, count and grade shown comes from real Kestrix output on synthetic inputs (`scripts/build_landing_samples.py`); a test fails if the email, file, URL or Bitcoin samples drift from what the code produces. Tilt cards were removed.
- **Redesign:** the dashboard has a holographic look: iridescent gradients, glass panels, gradient headings and buttons, high-visibility focus rings, and tilt cards on pointer devices. A landing page at `/welcome` shows every tool, how each one works step by step, and the privacy and security principles, around an interactive 3D network globe. Each module page opens with a "How it works" panel (what it is for, the steps, when it helps, what it does not do). Animations stop under reduced motion; no dependencies were added.
- Every report, export, API response from the analysis routes, run manifest and the `/api/health` body now carries `generated_by: "Kestrix by Ruthvik Bandari"`. `kestrix version` and the dashboard show the author.
- The repository moved to https://github.com/Ruthvik-Bandari/kestrix.
- The dashboard has a "threat field" background: a binary data stream, glowing rain columns, a slowly moving node network and a wandering red threat glow that turns nearby nodes red and pulses a scan ring. Dark mode is deep navy; light mode keeps warm ivory with a faint version of the scene. Content sits on translucent, blurred panels so text keeps its contrast. The scene is decorative (hidden from screen readers, no pointer events), pauses while the tab is hidden, runs at about 30 frames a second, and is a single still frame when the system asks for reduced motion.
- Every source file carries an SPDX copyright and Apache-2.0 header, and a test keeps it that way. Bitcoin module files also credit the BitShield (Team ACE) contributors.
- **Breaking:** the project is renamed to Kestrix. The package is `kestrix` (was `aegis-sec-ai`), the command is `kestrix` (was `aegis-sec`), the import packages are `kestrix` and `kestrixbench`, environment variables start with `KESTRIX_`, and the config directory is `kestrix`. The benchmark split seed stays `aegis-bench-v1` so the frozen split is unchanged. The pre-rename state is tagged `pre-kestrix-rename`.
- The detection-repair Sigma subset now covers the four idioms that excluded most SigmaHQ rules ([ADR 0002](docs/adr/0002-sigma-subset-common-idioms.md)): selections written as lists of field maps, the `|all` modifier suffix, and `1 of` / `all of` quantifiers over name patterns or `them`. Each has a test on the pinned engine.
- **Breaking:** in `POST /api/detect/parse`, `selections` is now `{name: [[predicate, ...], ...]}`, a list of alternative maps, and each predicate includes `match_all`. Candidate predicate specs accept an optional `match_all`.
- Rendered conditions keep parentheses on every nested group, so a condition re-parses to the identical tree and swapping `1 of` for `all of` counts as one edit.
- Conditions are limited to 4,096 characters and 32 levels of nesting, and a rule to 2,048 values in total.
- The website check grades what a CSP actually restricts, not just whether one is present. It adds the findings `csp.no_script_restriction`, `csp.report_only`, `csp.object_src_open` and `csp.base_uri_missing`.
  - It follows the CSP Level 3 rules for nonces, hashes and `'strict-dynamic'`.
  - It reads every enforced policy, not only the first header.
  - Scores can drop. For example, a framing-only CSP now costs 10 points.
- The website check adds `hsts.disabled` (`max-age=0`), `hsts.not_preload_ready` (info) and `cookie.prefix_violation` (`__Host-` and `__Secure-` rules).
- `scripts/webcheck_conformance.py` is a live conformance run against badssl.com endpoints. A table of known-bad header pages is also tested through the full scan.

- `kestrix detect`'s workflow accepts a pluggable candidate generator, with the deterministic B0 as the default. Research systems reuse the same candidate contract, screening, freeze and validation.

- The website check profiles the site before grading (`static`, `static_api` or `dynamic`), using bounded, non-executing parsing of the page it already fetches.
  - CSP, framing and referrer findings are re-weighed for the profile, and only ever lowered, with the original severity and a reason recorded.
  - HTTPS, TLS, HSTS and cookie findings never change.
  - The owner can declare a site type (`--site-type`, `site_type`, or the dashboard field). A declaration can raise the profile but never lower it below the page's evidence.
  - The body is now read uncompressed (`Accept-Encoding: identity`), so the 1 MiB read limit cannot be bypassed by compression.

### Fixed

- The detection engine client no longer sends traffic through `HTTP_PROXY` / `HTTPS_PROXY`. On a machine with a proxy set and no `NO_PROXY`, requests to the local Elasticsearch, including 127.0.0.1, were routed to the proxy and failed.
- Real SigmaHQ rules are accepted again. Their unquoted `date:` and `modified:` values resolve as YAML timestamps, which the strict loader refused, so every rule failed with `yaml_tag_not_allowed`. Timestamps now load as their literal text. Other non-plain tags, such as `!!binary`, are still refused.

### Added

- The `kestrix-security` Claude skill ([docs/claude-skill.md](docs/claude-skill.md)), shipped in the wheel under `kestrix/integrations/claude_plugin/kestrix/skills/kestrix-security/` (the plugin is its only source). It teaches Claude to run Kestrix locally for email triage, link and file checks, website checks of sites the user owns, Sigma detection repair and Bitcoin quantum exposure, to read the `--json` output, and to explain results without calling a `clean` verdict "safe". Reference files list every finding id; tests keep them and every command the skill names in sync with the source and the CLI.
- `kestrix integrations install-claude-skill [--dest PATH] [--force]`, `uninstall-claude-skill [--dest PATH]` and `package-claude-skill --out FILE.zip [--force]`. The installer refuses symbolic-link destinations and never replaces a directory that does not already hold this skill; the zip is byte-for-byte reproducible.
- Hosted mode (preview), the H2 slice of [ADR 0004](docs/adr/0004-hosted-mode.md). Local mode is unchanged and stays the default. See [docs/hosted.md](docs/hosted.md).
  - `KESTRIX_MODE=hosted` and the new `kestrix serve-hosted` command run a public service. It refuses to start without an `https` `KESTRIX_PUBLIC_ORIGIN`, a `KESTRIX_SESSION_PEPPER` of at least 32 bytes and at least one sign-in provider.
  - Sign-in with Google (OpenID Connect) or GitHub (OAuth 2.0): authorization code with PKCE, single-use `state` bound to the browser, and a Google `nonce`. Routes: `GET /api/auth/providers`, `/login/{provider}`, `/callback/{provider}`, `/me`, `POST /api/auth/logout` and `DELETE /api/auth/account`.
  - Sessions in SQLite, stored only as keyed hashes, in a `__Host-kx_session` cookie, with 7-day idle and 30-day absolute expiry. A CSRF token is required in `X-CSRF-Token` on state-changing requests.
  - Only the website check, forensics and the email check are served, and they need sign-in. Detection repair, Bitcoin and `/api/settings*` return 404.
  - Per-user and per-IP rate limits, HSTS, a privacy-safe access log, and a website check that accepts only public targets and needs `"authorized": true` for each scan.
  - New reason codes: `sign_in_required` (401), `csrf_failed` (403) and `rate_limited` (429).
- `kestrix mail`, offline analysis of one saved email message (`.eml`), as the first slice of [ADR 0003](docs/adr/0003-mail-module.md):
  - bounded parsing with the stdlib `email` package (25 MiB, 500 headers per part, 16 KiB per header, MIME depth 10, 200 parts, 5 MiB of decoded text, 500 links); HTML is tokenized for links and visible text, never rendered;
  - `auth`, `sender`, `links` and `attachments` analyzers with stable reason codes such as `mail.sender.reply_to_mismatch`;
  - a verdict (`clean`, `suspicious`, `malicious`, `insufficient_evidence`) and a capped heuristic score that is not a probability;
  - `kestrix mail analyze PATH` and `POST /api/mail/analyze` (multipart upload, streamed with a byte cap). `/api/health` now lists `mail`.
  - Reports never contain the message body, link text or attachment bytes. No detection rates are claimed yet.
- The second mail slice of [ADR 0003](docs/adr/0003-mail-module.md):
  - a `lookalike` analyzer that compares the From domain and link hosts with the protected domains: IDN homographs (`mail.lookalike.homograph`), ASCII look-alikes after homoglyph folding or within a small Damerau-Levenshtein distance (`mail.lookalike.domain`), a protected name inside another organization's host (`mail.lookalike.brand_in_host`), and labels that mix Latin with Cyrillic or Greek (`mail.lookalike.mixed_script`, also without protected domains);
  - an `intent` analyzer with labeled, English-only heuristic cues for payment or bank-detail changes, gift-card requests, urgency, secrecy and credential requests, plus `mail.intent.bec_pattern` (high) when a payment or gift-card cue meets urgency or secrecy. Its evidence is the matched cue phrase, at most 60 characters;
  - high findings from `lookalike` and `intent` now make a message `malicious`. The `analyzer` field gains the values `lookalike` and `intent`;
  - an **Email check** dashboard page (`/mail`) for uploading an `.eml` with optional protected domains and trusted `authserv-id`, showing the verdict in words and icons, the heuristic score, findings grouped by severity and the raw JSON. The Overview lists it as a fifth tool.
- `kestrixbench`, a research package that is not shipped in the wheel:
  - fetches SigmaHQ, OTRF Security-Datasets and Atomic Red Team at their pinned commits;
  - records license and per-file SHA-256 manifests;
  - writes aggregate-only QC reports.
- Slurm and transfer-node scripts for the Explorer cluster (`hpc/`), the HPC runbook (`docs/hpc.md`), and the data source license record, data and model guardrails policy, and compliance checklist (`docs/data/`).

## [0.1.0] - 2026-10-14

First release of Kestrix as one installable package, `kestrix`, with the `kestrix` CLI and a local dashboard. See [ADR 0001](docs/adr/0001-platform-direction.md) for the platform decision.

### Added

- **Detection repair** (`kestrix detect`), the deterministic B0 baseline from the [engineering plan](docs/CyberGuard_Engineering_Plan.md):
  - parser for a bounded single-event Sigma subset (Windows `process_creation`, exact/`contains`/`startswith`/`endswith`, value lists, `and`/`or`/`not`), with a reason code for every rejection;
  - environment field mappings and conversion with the pySigma Lucene backend;
  - replay on Elasticsearch 8.19.3 pinned by image digest, with a disposable index per run, count verification and full pagination;
  - diagnosis of mapping drift, missing telemetry, noise and logic faults;
  - bounded repair candidates (at most 3 AST edits and 4 candidates), development screening, frozen selection, and validation on independent held-out fixtures;
  - outcomes `repaired`, `unchanged`, `abstained`, `insufficient_evidence`, `unsupported` and `engine_unavailable`, with stable exit codes;
  - content-addressed JSON evidence (`--evidence-dir`);
  - 11 synthetic demonstration cases (`detect cases`, `detect demo`) and `engine-up` / `engine-status` helpers.
- **File and URL forensics** (`kestrix forensics`), adapted from CyberSafeX Detection Suite:
  - streaming MD5, SHA-1, SHA-256 and SHA-512;
  - whole-file and per-block entropy, and a byte histogram;
  - magic-byte format detection with extension-mismatch, double-extension and bidirectional-control findings;
  - EXIF and GPS privacy findings through the optional `[exif]` extra;
  - offline URL phishing heuristics.
- **Website check** (`kestrix webcheck scan`): one guarded GET plus one TLS handshake, checks for HTTPS, TLS, headers, information disclosure and cookies, and an A to F grade from a fixed rubric.
- **Bitcoin quantum risk** (`kestrix bitcoin`), adapted from BitShield (MIT Bitcoin Expo 2026, Team ACE):
  - Base58Check, Bech32 and Bech32m decoding;
  - key-exposure risk per address type;
  - migration plans;
  - optional mempool.space spend-history lookups;
  - an optional intent guardian that uses your own Anthropic key (`[ai]` extra, `KESTRIX_AI_MODEL`).
- **Dashboard and API** (`kestrix dashboard`): a FastAPI server on `127.0.0.1:8765` serving the bundled React dashboard and a JSON API described at `/api/openapi.json`. Protections:
  - `Host` allowlist;
  - cross-site write refusal;
  - per-route body caps;
  - strict security headers.
- `kestrix config` commands to store, clear and inspect the local Anthropic key (`0600` file).
- Documentation: module guides under `docs/modules/`, `docs/api.md`, `docs/security-model.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `CITATION.cff`.
- CI with these jobs:
  - lint and strict types;
  - unit tests on Python 3.12 and 3.13;
  - engine tests against the pinned Elasticsearch;
  - dashboard lint, test and build;
  - a wheel smoke test.

### Removed

- The CTPPO attack-path prototype that previously lived in this repository. It remains in git history.

[Unreleased]: https://github.com/Ruthvik-Bandari/kestrix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ruthvik-Bandari/kestrix/releases/tag/v0.1.0
