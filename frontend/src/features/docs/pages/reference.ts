// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { code, diagram, list, note, p, section, see, table } from "../blocks";
import { architectureDiagram } from "../diagrams";
import type { DocPage } from "../model";
import { HOSTED_DOC_PATH } from "../model";

/* Follows `kestrix --help`, docs/api.md, docs/security-model.md, docs/hosted.md, NOTICE and docs/research/dataset-licenses.md. */

export const referencePages: DocPage[] = [
  {
    path: "reference/architecture",
    title: "Architecture",
    nav: "Architecture",
    summary: "How the ways in, the server, the shared core and kestrix-scan fit together, and what crosses each trust boundary.",
    sections: [
      section(
        "Overview",
        p("Every way of using Kestrix reaches the same core functions, so a result is the same from the command line, the dashboard, the hosted service or Claude Code. Dashed arrows leave your machine, and only when you ask for it."),
        diagram(architectureDiagram),
      ),
      section(
        "What crosses each boundary",
        table(
          ["Boundary", "What crosses it"],
          [
            ["Your machine to the internet", "Nothing by default. Website checks, the Bitcoin chain lookup, the AI guardian and `db update` connect only when you start them."],
            ["Browser to the hosted server", "Your upload or URL, over HTTPS with sign-in, CSRF and rate limits. Uploads are processed in a worker and never stored; the report is kept 30 days, encrypted."],
            ["Claude Code to kestrix-scan", "The files Claude edits, scanned locally; only new findings go back to Claude as context."],
          ],
        ),
        see("The threat model", "security/threat-model"),
        see("The hosted service", HOSTED_DOC_PATH),
      ),
    ],
  },
  {
    path: "reference/cli",
    title: "CLI commands",
    nav: "CLI commands",
    summary: "Every `kestrix` and `kestrix-scan` command, with where its options are documented.",
    sections: [
      section(
        "kestrix",
        p("`kestrix --help` lists the groups below, and `kestrix <group> --help` lists their commands. Add `--json` to a module command for machine-readable output. Exit codes are stable."),
        table(
          ["Command", "What it does", "Details"],
          [
            ["`kestrix version`", "Prints the installed version and the author.", "Installation"],
            ["`kestrix dashboard`", "Starts the local dashboard and API. Options: `--host` (default `127.0.0.1`), `--port` (default 8765), `--open` or `--no-open`.", "Run locally"],
            ["`kestrix mail analyze PATH`", "Checks one saved email.", "Email check"],
            ["`kestrix webcheck scan URL`", "Grades a website's HTTPS, TLS, headers and cookies.", "Web check"],
            ["`kestrix forensics file PATH`, `kestrix forensics url URL`", "Analyzes a file, or scores a link without opening it.", "File & link forensics"],
            ["`kestrix detect cases`, `demo`, `run`, `engine-up`, `engine-status`", "Diagnoses and repairs a Sigma detection by replay.", "Detection repair"],
            ["`kestrix bitcoin scan`, `migration`, `ask`", "Rates Bitcoin addresses for quantum exposure, gives migration steps, and answers plain-language questions with your own key.", "Bitcoin quantum risk"],
            ["`kestrix code scan [PATH ...]`", "Runs the code scanner with the same options, output and exit codes as `kestrix-scan`.", "kestrix-scan"],
            ["`kestrix config set-anthropic-key`, `clear-anthropic-key`, `show`", "Stores or removes your optional Anthropic API key, or shows where settings live and which keys are configured (never the key itself).", "Threat model"],
            ["`kestrix integrations`", "Installs the Kestrix skill and the Claude Code plugin.", "Claude Code plugin"],
            ["`kestrix serve-hosted`, `kestrix hosted`", "Operator commands for running the hosted service: run it, disable accounts, hash hosts. Configured by `KESTRIX_*` variables.", "The hosted service"],
          ],
        ),
      ),
      section(
        "kestrix-scan",
        table(
          ["Command", "What it does"],
          [
            ["`kestrix-scan [scan] [PATH ...]`", "Scans files and directories. Exit 0 when nothing is at or above `--fail-on`, 1 when something is, 2 on a usage or input error."],
            ["`kestrix-scan init`", "Adds `[tool.kestrix]` settings, a GitHub code scanning workflow (`--ci github`), the pre-commit hook (`--pre-commit`) or the Claude Code plugin (`--claude-plugin`)."],
            ["`kestrix-scan rules`", "Lists every rule."],
            ["`kestrix-scan db update`, `db status`", "Downloads the public OSV data (the only network command), or shows the local index."],
            ["`kestrix-scan install-claude-plugin`", "Copies the Claude Code plugin to `~/.claude/kestrix-plugin`."],
            ["`kestrix-scan version`", "Prints the installed version and the author."],
          ],
        ),
        see("The scanner's options", "code-security/kestrix-scan/install-and-cli"),
      ),
    ],
  },
  {
    path: "reference/http-api",
    title: "HTTP API",
    nav: "HTTP API",
    summary: "The local JSON API the dashboard uses, its protections, error envelope and routes.",
    sections: [
      section(
        "Overview",
        p("`kestrix dashboard` starts a local HTTP server that serves the dashboard and a JSON API on `http://localhost:8765`. Use the API to script Kestrix from another program on the same machine, or to see exactly what the dashboard sends. It calls the same functions as the CLI, so results match."),
        code("curl -s http://127.0.0.1:8765/api/health"),
        p("The machine-readable schema is served at `GET /api/openapi.json` by the local server only; the hosted service does not publish it. Clients outside a browser, such as `curl`, send no `Origin` or `Sec-Fetch-Site` header, so the cross-site rule does not affect them."),
      ),
      section(
        "Local-only protections",
        list(
          "The `Host` header must be `127.0.0.1`, `localhost` or `[::1]`, otherwise HTTP 421. A page that uses DNS rebinding still sends its own name in `Host`, so it is refused.",
          "A write is refused with 403 when `Sec-Fetch-Site` is cross-site or `Origin` is not an allowed host. The server sends no CORS headers, so other origins cannot read responses.",
          "The declared body size is capped per route (413 beyond it).",
        ),
        table(
          ["Route", "Body limit"],
          [
            ["`POST /api/detect/run`", "60 MiB"],
            ["`POST /api/forensics/file`", "51 MiB (the file itself 50 MiB)"],
            ["`POST /api/mail/analyze`", "26 MiB (the message itself 25 MiB)"],
          ],
        ),
      ),
      section(
        "Errors",
        p("Errors use one envelope, with a stable machine-readable `reason` and a human-readable `detail`."),
        code('{"reason": "invalid_url", "detail": "the URL is empty"}'),
        table(
          ["Status", "reason"],
          [
            ["400", "Any rejected input, for example `invalid_input`, `invalid_url`, `invalid_rule`, `unsupported_modifier`, `invalid_mapping`, `invalid_fixture`, `malformed_yaml`, `engine_error`"],
            ["401", "`sign_in_required`, `token_expired` (hosted mode only)"],
            ["403", "`target_not_allowed`, `cross_site_request`, and `csrf_failed` (hosted mode only)"],
            ["404", "`not_found`, for an unknown path under `/api/`"],
            ["413", "`input_too_large`"],
            ["421", "`host_not_allowed`"],
            ["422", "`analysis_timeout` (hosted mode only); a request body that does not fit the route's schema"],
            ["429", "`rate_limited` and `busy` (hosted mode only), with a `Retry-After` header"],
            ["500", "`internal_error`; `detail` is always `unexpected error`"],
            ["502", "`upstream_error`, `target_unreachable`"],
            ["503", "`engine_unavailable`, `ai_key_missing`, `busy` (hosted mode only), and `dashboard_not_built`"],
          ],
        ),
        p("Detection repair outcomes such as `abstained`, `unsupported` or `engine_unavailable` come back as HTTP 200 with the outcome in the report body."),
      ),
      section(
        "Routes",
        table(
          ["Route", "Request", "Response"],
          [
            ["`GET /api/health`", "none", "`status`, `version` and the modules served"],
            ["`GET /api/settings`, `PUT /api/settings/anthropic-key`", "`{\"key\": string | null}`", "Whether a key is configured (never the key); `204` on write"],
            ["`GET /api/detect/engine`, `GET /api/detect/cases`", "none", "Engine state; bundled case manifests"],
            ["`POST /api/detect/cases/{case_id}/run`, `POST /api/detect/parse`, `POST /api/detect/run`", "A case id, or rule, mapping and event files", "The workflow report"],
            ["`POST /api/forensics/file`", "`multipart/form-data` with one file field named `file`", "`FileReport`"],
            ["`POST /api/forensics/url`", "`{\"url\": string}`", "`UrlReport`; the URL is never visited"],
            ["`POST /api/webcheck`", "`{\"url\", \"allow_private\", \"site_type\", \"scope\"}`", "The web check report"],
            ["`POST /api/bitcoin/scan`, `GET /api/bitcoin/migration/{address_type}`, `POST /api/bitcoin/guardian`", "Up to 100 addresses; an address type; a message of 1 to 2,000 characters", "`ScanResult`; `MigrationPlan`; `GuardianResult`"],
            ["`POST /api/mail/analyze`", "`multipart/form-data` with one file field named `file`; optional `protected_domain` and `trusted_authserv_id` query parameters", "`MailReport`"],
            ["`GET /api/history`, `GET /api/history/{id}`, `DELETE /api/history/{id}`, `DELETE /api/history`, `PUT /api/settings/history`", "Page and per-page numbers, an id, or `{\"enabled\": bool}`", "Saved reports (kept 30 days), one report, or `204`"],
          ],
        ),
      ),
      section(
        "On the hosted service",
        list(
          "`Host` must be the public host, and on writes `Origin` must equal the public origin.",
          "`/api/detect/*`, `/api/bitcoin/*` and `/api/settings*` return 404, except `PUT /api/settings/history`. The OpenAPI schema is not served.",
          "Every `/api/` route except `GET /api/health` and the public sign-in routes needs a valid access token (401 without one), and a signed-in write needs an `X-CSRF-Token` header (403 without it).",
          "Rate limits are 20 website checks and 120 analyses per user per hour, with a request refused while another is still running (429 `busy`).",
          "Uploads are capped at 10 MiB. Every `/api/` response is `Cache-Control: no-store`.",
        ),
        see("The hosted service", HOSTED_DOC_PATH),
      ),
    ],
  },
  {
    path: "security/threat-model",
    title: "Threat model: what Kestrix protects against",
    nav: "Threat model",
    summary: "What Kestrix protects, what it assumes, and where its protections stop.",
    sections: [
      section(
        "What Kestrix is",
        p("Kestrix is a single-user tool that runs on your own computer, with two front ends over one set of module functions: the `kestrix` CLI, and a FastAPI server that serves the dashboard and a JSON API on `127.0.0.1:8765`. There are no accounts, no database and no background jobs in the default local mode. Two features reach the internet, and only when you ask: the website check contacts the site you name, and the Bitcoin module contacts mempool.space and the Anthropic API."),
      ),
      section(
        "What it defends against",
        table(
          ["Adversary", "Example threats"],
          [
            ["A web page open in your browser", "DNS rebinding against the local server; cross-site form posts (CSRF); framing the dashboard"],
            ["A hostile file, rule, mapping or fixture", "YAML alias bombs and tag-based object construction, deeply nested JSON, oversized input, path traversal in case ids or upload names, decoder bugs in image parsing"],
            ["A website you check, or its DNS", "Redirects to internal addresses (SSRF), DNS answers that change between check and connect, oversized responses"],
            ["An upstream service (mempool.space, Anthropic)", "Malformed or oversized responses; a model that returns invented addresses or follows instructions hidden in your message"],
            ["Another local user or process", "Reading stored secrets; calling the unauthenticated local API"],
          ],
        ),
      ),
      section(
        "Controls",
        table(
          ["Area", "Control"],
          [
            ["Local server", "Binds to `127.0.0.1`; `Host` allowlist (HTTP 421); cross-site writes refused (HTTP 403); no CORS headers; body size caps; errors are `{reason, detail}`, never stack traces."],
            ["Browser", "A strict content security policy with `script-src 'self'` and `style-src 'self'` and no `unsafe-inline` or `unsafe-eval`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer` and same-origin isolation headers on every response."],
            ["Untrusted input", "YAML loaded with a safe loader that refuses aliases, tags and duplicate keys (one document, 100 KiB, depth 16); JSONL bounded; Sigma rules parsed against an allowlist; repair candidates validated as a strict envelope; emails parsed with caps and never rendered; code parsed with `ast`, never imported or run."],
            ["Outbound requests", "Only `http` and `https` with a host and no credentials; every resolved address must be public (private, loopback, link-local including cloud metadata, multicast and reserved ranges are refused); the website check connects to the validated IP; each redirect is re-validated; no environment proxies; no cookie is ever sent back."],
            ["Model output", "The guardian only classifies a message into a fixed schema and cannot run commands or move funds. Addresses from the model are kept only if they appear verbatim in your message and pass the local parser."],
            ["Result integrity", "The pinned engine is the only matching oracle and its version is checked every run; engine errors are errors, never zero matches; the candidate is selected on development fixtures and frozen before validation; abstentions are explicit outcomes."],
          ],
        ),
      ),
      section(
        "How secrets are stored",
        p("The only secret is the optional Anthropic API key. `ANTHROPIC_API_KEY` from the environment is used first, then the `anthropic_api_key` entry in `secrets.json` in the config directory (`$KESTRIX_HOME`, else `%APPDATA%\\kestrix` on Windows, else `$XDG_CONFIG_HOME/kestrix`, which defaults to `~/.config/kestrix`)."),
        list(
          "The directory is created or tightened to `0700`, and the file is written to a new `0600` temporary file and atomically renamed. On Windows these modes have limited effect.",
          "The format is plain JSON. The key is not encrypted and is not stored in the OS keychain. Anyone who can read files as your user can read it.",
          "`GET /api/settings` and `kestrix config show` report only whether a key is configured. Kestrix does not write the key to logs or evidence, and it is sent only to the Anthropic API.",
        ),
      ),
      section(
        "Known limitations",
        list(
          "Single local user, no authentication: any process or user on the machine that can reach `127.0.0.1:8765` can call every route, including replacing or clearing the stored key. Do not run the dashboard on a machine you share with people you do not trust.",
          "`kestrix dashboard --host <interface>` serves the same unauthenticated API to the network over plain HTTP. Keep the default unless you have a separate access control in front of it.",
          "Guardian output is unverified model text and can be wrong; prompt injection in your own message can change it. Your message is sent to Anthropic.",
          "`--lookup-chain` sends addresses and your IP to mempool.space.",
          "The local engine is unauthenticated: `detect engine-up` runs Elasticsearch with security disabled on `127.0.0.1:9200`.",
          "Evidence files written with `--evidence-dir` use your default file permissions.",
          "EXIF reading parses untrusted image headers with Pillow; a Pillow vulnerability in header parsing remains a residual risk. Without the `exif` extra, Pillow is not used.",
          "Heuristics are not verdicts: the URL score, entropy findings and website grade are signals, and a clean result does not mean a file, link or site is safe.",
          "A `repaired` outcome shows behavior on the labeled scenarios you supplied, and the bundled cases are synthetic.",
        ),
        note("To report a vulnerability in Kestrix, see SECURITY.md in the repository.", "info"),
      ),
      section(
        "Hosted mode additions",
        p("The hosted service adds accounts, so its threat model adds stolen sessions, scan abuse, upload floods and a shared server that parses strangers' files."),
        list(
          "Sign-in uses an authorization-code flow with PKCE; there are no passwords. Access tokens are 15-minute JWTs; refresh tokens are 256-bit random values stored only as keyed hashes, rotated on every refresh, and a reused one revokes its whole family. State-changing requests need a per-session CSRF token.",
          "Each analysis runs in a fresh worker process with a scrubbed environment and CPU, memory and wall-clock limits; uploads are capped at 10 MiB; one module request runs at a time per user.",
          "The website check reaches public targets on ports 80 and 443 only, needs a confirmation per scan, and reports every connection failure with the same message.",
          "Saved reports are encrypted with AES-256-GCM, kept 30 days, and deleted with the account. Access logs never hold bodies, file names, emails, query strings, cookies or tokens.",
          "Uploads are parsed by the same code as locally, so a parser bug affects a shared server rather than one machine, and the worker limits contain exhaustion, not memory-safety bugs in a C extension.",
        ),
        see("The hosted service", HOSTED_DOC_PATH),
      ),
    ],
  },
  {
    path: "reference/licenses",
    title: "Licenses and attribution",
    nav: "Licenses and attribution",
    summary: "Kestrix is Apache-2.0. These are the projects and datasets it builds on or was measured with, and their licenses.",
    sections: [
      section(
        "Kestrix",
        p("Kestrix by Ruthvik Bandari. Copyright 2026 Ruthvik Bandari. It is open source under the Apache-2.0 license."),
        p("Licensed under the Apache License, Version 2.0. You may use, modify and redistribute Kestrix under its terms, which are published at apache.org/licenses/LICENSE-2.0. The software is provided \"as is\", without warranties or conditions of any kind. Every source file carries an SPDX header naming the copyright holder and the license."),
      ),
      section(
        "Code the modules are adapted from",
        list(
          "The forensics module is adapted from CyberSafeX Detection Suite (MIT License, Ruthvik Bandari).",
          "The Bitcoin quantum-risk module is adapted from BitShield, built by Team ACE at the MIT Bitcoin Expo 2026 hackathon (MIT).",
          "The code scanner's rules were written for Kestrix from their CWE entries and the language, library and standard documentation cited per rule. No rule text, pattern or code from other scanners is included.",
          "The dashboard's icons are Lucide icons (ISC License), bundled into the dashboard build.",
        ),
      ),
      section(
        "Dependency advisory data",
        p("No advisory data ships with Kestrix. `kestrix-scan db update` downloads it from OSV to your own cache, and OSV redistributes each source under that source's license, including the GitHub Advisory Database (CC BY 4.0), the PyPI Advisory Database (CC BY 4.0), OpenSSF Malicious Packages (Apache-2.0), OSS-Fuzz (CC BY 4.0), the Erlang Ecosystem Foundation CNA (CC BY 4.0) and the Global Security Database (CC0 1.0)."),
      ),
      section(
        "Datasets used to measure accuracy",
        p("These datasets are not redistributed; only aggregate counts, rates and rule ids are published, and the data stays on the research cluster."),
        table(
          ["Dataset", "License", "Used for", "Attribution"],
          [
            ["Nazario phishing corpus", "CC BY 4.0", "Email check measurement", "Nazario, J., Phishing corpus (monkey.org/~jose/phishing)"],
            ["PhiUSIIL Phishing URL dataset", "CC BY 4.0", "Link check measurement", "Prasad, A. & Chandra, S. (2024), doi:10.1016/j.cose.2023.103545"],
            ["Majestic Million", "CC BY 3.0", "Link check measurement (benign domains)", "Majestic, majestic.com/reports/majestic-million"],
            ["CVEfixes v1.0.8", "CC BY 4.0", "Code scanner measurement", "Bhandari, G., Naseer, A. and Moonen, L. (2021), CVEfixes, PROMISE '21"],
            ["GitHub Advisory Database", "CC BY 4.0", "Code scanner measurement", "GitHub Advisory Database, github.com/github/advisory-database"],
            ["Govdocs1 (Digital Corpora)", "\"Freely redistributable\", no formal license", "File check measurement (false alarms)", "Garfinkel, S., Farrell, P., Roussev, V. & Dinolt, G. (2009), Digital Investigation 6, S2-S11 (DFRWS 2009)"],
            ["SpamAssassin public corpus, Enron email dataset", "No license stated", "Email check measurement (normal mail and spam)", "Used for research only; not redistributed"],
          ],
        ),
        p("Bandit (Apache-2.0) and ESLint with eslint-plugin-security (MIT and Apache-2.0) were the baseline scanners. Semgrep was not used, because its registry rules are not licensed for this use."),
      ),
      section(
        "Used on your own responsibility",
        note("Use Kestrix only on systems, files and websites you own or are authorized to assess.", "caution"),
        p("The repository's NOTICE file records each third-party notice with its source, copyright holder and license, in the same change that adds it. The notices that apply to what you install are summarized above. Third-party code, rules or data are added only under a license that permits redistribution with Apache-2.0, and the research datasets are not redistributed."),
        p("The OSV schema is Apache-2.0. The PEP 440 and SemVer version orderings were implemented from their specifications (PEP 440 is public domain, SemVer is CC BY 3.0), with no code from `packaging` or any other version library. The CVSS v3.1 base-score formula follows the FIRST specification. Lucide icons are ISC licensed."),
      ),
    ],
  },
];
