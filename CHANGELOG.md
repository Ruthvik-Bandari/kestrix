# Changelog

All notable changes to Kestrix are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may change commands, report fields or API routes; each such change is listed here.

## [Unreleased]

### Changed

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

- The `kestrix-security` Claude skill ([docs/claude-skill.md](docs/claude-skill.md)), shipped in the wheel under `kestrix/integrations/claude_skill/`. It teaches Claude to run Kestrix locally for email triage, link and file checks, website checks of sites the user owns, Sigma detection repair and Bitcoin quantum exposure, to read the `--json` output, and to explain results without calling a `clean` verdict "safe". Reference files list every finding id; tests keep them and every command the skill names in sync with the source and the CLI.
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
