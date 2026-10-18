# Changelog

All notable changes to Kestrix are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may change commands, report fields or API routes; each such change is listed here.

## [Unreleased]

### Changed

- Every report, export, API response from the analysis routes, run manifest and the `/api/health` body now carries `generated_by: "Kestrix by Ruthvik Bandari"`. `kestrix version` and the dashboard show the author.
- The repository moved to https://github.com/Ruthvik-Bandari/kestrix.
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

- `kestrix mail`, offline analysis of one saved email message (`.eml`), as the first slice of [ADR 0003](docs/adr/0003-mail-module.md):
  - bounded parsing with the stdlib `email` package (25 MiB, 500 headers per part, 16 KiB per header, MIME depth 10, 200 parts, 5 MiB of decoded text, 500 links); HTML is tokenized for links and visible text, never rendered;
  - `auth`, `sender`, `links` and `attachments` analyzers with stable reason codes such as `mail.sender.reply_to_mismatch`;
  - a verdict (`clean`, `suspicious`, `malicious`, `insufficient_evidence`) and a capped heuristic score that is not a probability;
  - `kestrix mail analyze PATH` and `POST /api/mail/analyze` (multipart upload, streamed with a byte cap). `/api/health` now lists `mail`.
  - Reports never contain the message body, link text or attachment bytes. No detection rates are claimed yet.
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
