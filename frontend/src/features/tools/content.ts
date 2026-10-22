// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ToolPage } from "../../app/tools";
import { REPO_URL } from "../../lib/site";
import { list, p, steps, type DocSection } from "../docs/blocks";

/*
 * Everything the dashboard says about each tool beyond its name and one-line summary
 * (app/tools.ts), written once:
 * - `reference`: what it is, how it works, how it helps, typical uses and limits, shown on its
 *   docs page;
 * - `local`: how to install and run it yourself, shown as the tool's guide page (the "Run locally"
 *   tools) and again, from the same data, at the end of its docs page.
 * The tool pages themselves show only the summary and a link to the docs.
 *
 * The content follows docs/modules/*.md, packages/kestrix-scan/README.md and
 * docs/claude-plugin.md and must never contradict them; every command and option exists in the
 * CLIs (src/kestrix/*\/cli.py, packages/kestrix-scan/src/kestrix_scan/cli.py). Change the docs
 * first, then this file. Example outputs are real and live in ./examples.ts.
 */

export interface GuideStep {
  title: string;
  detail?: string;
  command?: string;
}

/*
 * Install commands. Neither package is on PyPI yet (docs/release.md), so every command here installs
 * from the repository; the guides say so and mention pip only as what works after the release.
 */
const SOURCE = `git+${REPO_URL}`;
export const INSTALL_KESTRIX = `uv tool install "${SOURCE}"`;
export const INSTALL_SCAN = `uv tool install "${SOURCE}#subdirectory=packages/kestrix-scan"`;
export const INSTALL_EXIF = `uv tool install "kestrix[exif] @ ${SOURCE}"`;
export const INSTALL_AI = `uv tool install "kestrix[ai] @ ${SOURCE}"`;

/**
 * The repository does not commit the built dashboard, so a git install gives every CLI command but an
 * empty dashboard. Until the PyPI wheel ships the bundle, the dashboard needs this from-source build.
 */
export const INSTALL_DASHBOARD = [
  `git clone ${REPO_URL} && cd kestrix`,
  "npm --prefix frontend ci && npm --prefix frontend run build",
  "uv tool install .",
  "kestrix dashboard",
].join("\n");

/** Shown above every install command until the first PyPI release. */
export const PYPI_PENDING = "PyPI release pending, so install from the repository with uv. pip install works only after that release.";

export interface LocalGuide {
  requirements: string[];
  install: { command: string; note?: string }[];
  /** One command that proves the install worked, and what to expect. */
  verify: { command: string; detail: string };
  steps: GuideStep[];
  troubleshooting: { problem: string; fix: string }[];
}

export interface ToolContent {
  reference: DocSection[];
  local: LocalGuide;
}

/** The reference sections every tool page uses, in order. */
function reference(doc: { what: string[]; how: string[]; helps: string[]; uses: string[]; limits: string[] }): DocSection[] {
  return [
    { heading: "What it is", blocks: doc.what.map(p) },
    { heading: "How it works", blocks: [steps(...doc.how)] },
    { heading: "How it helps", blocks: [list(...doc.helps)] },
    { heading: "Typical uses", blocks: [list(...doc.uses)] },
    { heading: "Limits", blocks: [list(...doc.limits)] },
  ];
}

const PYTHON = "Python 3.10 or newer.";

export const toolContent: Record<ToolPage, ToolContent> = {
  mail: {
    reference: reference({
      what: [
        "The mail module checks one saved email message (an `.eml` file) for common phishing and malware-delivery signs and explains each one. It is available from the CLI, the API and the dashboard's Email check page.",
        "It is a set of heuristics, not a classifier.",
      ],
      how: [
        "Parse the message within fixed limits: 25 MiB, 200 MIME parts, nesting depth 10. HTML is never rendered.",
        "Trust one `Authentication-Results` header: the topmost, or the first from your provider's `authserv-id`.",
        "Run six analyzers: `auth`, `sender`, `lookalike`, `links`, `attachments` and `intent`.",
        "Combine the findings into a verdict (`malicious`, `suspicious`, `insufficient_evidence` or `clean`) and a heuristic score from 0 to 100.",
      ],
      helps: [
        "Each finding has a stable reason code, a plain-language explanation and the evidence behind it.",
        "Nothing is sent anywhere: links are never visited and attachments are never opened, executed or extracted.",
        "The report never holds the message body, link text or attachment bytes, except the short scam phrase that matched (at most 60 characters).",
      ],
      uses: [
        "A message you are unsure about, before you click, reply or open anything.",
        "An invoice email that says the bank details have changed.",
        "A help desk triaging messages that users report.",
      ],
      limits: [
        "A `clean` verdict means none of the checks fired, not that the message is safe.",
        "On a one-time locked test of public spam, phishing and normal mail (1999–2025), it flagged 61% of phishing and 50% of spam and wrongly flagged 1.2% of normal mail. That normal mail is old, so false alarms on modern mail are not measured.",
        "The scam phrase lists are small and curated: English, plus Russian for gambling and prize offers. Paraphrases and other languages are missed.",
        "The look-alike table is a curated subset of the Unicode confusables list, and organizations are grouped without the full Public Suffix List.",
        "The heuristic score orders messages for attention. It is not a probability.",
      ],
    }),
    local: {
      requirements: [
        PYTHON,
        "A saved message: in Gmail, ⋮ (More) → Download message; in Outlook, File → Save as.",
      ],
      install: [{ command: INSTALL_KESTRIX }],
      verify: { command: "kestrix version", detail: "Prints the installed version and the author." },
      steps: [
        { title: "Save the message as an .eml file", detail: "Use your mail client's download or save option." },
        { title: "Analyze it", command: "kestrix mail analyze message.eml" },
        {
          title: "Name the domains you care about",
          detail: "A display name or look-alike domain imitating one of them is flagged. Repeat the option, up to 20 times.",
          command: "kestrix mail analyze message.eml --protected-domain example-bank.com",
        },
        {
          title: "Trust your provider's authentication results",
          detail: "Pass the authserv-id, the first word of the Authentication-Results header your provider adds.",
          command: "kestrix mail analyze message.eml --trusted-authserv-id mx.google.com",
        },
        { title: "Get the full report as JSON", command: "kestrix mail analyze message.eml --json" },
      ],
      troubleshooting: [
        {
          problem: "Rejected (invalid_input)",
          fix: "The file has none of the usual message headers. Save the message itself as .eml rather than copying its text.",
        },
        { problem: "Rejected (input_too_large)", fix: "Messages are limited to 25 MiB." },
        {
          problem: "The verdict is insufficient_evidence",
          fix: "No trusted Authentication-Results header was found. Pass --trusted-authserv-id with your provider's authserv-id.",
        },
      ],
    },
  },
  webcheck: {
    reference: reference({
      what: [
        "The website check grades how well a site protects its visitors at the connection and browser level: HTTPS, the TLS certificate, security headers and cookie flags.",
        "By default it checks the whole site: up to 50 read-only GET requests to the page you name, the pages it links to, the pages in its sitemap and six common login addresses, plus one TLS handshake. \"Just this page\" sends one GET request (following up to five redirects) instead. It never submits a form, logs in, follows a link to another site, fuzzes or scans ports.",
      ],
      how: [
        "Validate the target: only public addresses, on every redirect, unless you pass `--allow-private` for a host you own.",
        "Connect to the validated IP address, with the real host name in the `Host` header and TLS SNI. Each page, with its redirects, has 10 seconds.",
        "For a whole-site check, collect the pages to fetch: links on the start page, the sitemap's addresses, then `/login`, `/signin`, `/admin`, `/admin/login`, `/account` and `/wp-login.php`. Only the same scheme, host and port; files such as images and PDFs are skipped. Fetch them one at a time with a short pause, at most 50 pages and 60 seconds.",
        "Make one verified TLS handshake and record the protocol, issuer and expiry.",
        "Profile the site from the pages it fetched: `static`, `static_api` or `dynamic`. The most sensitive page sets the kind and is named in the reason.",
        "Check headers and cookies on each page, merge findings by id (the most severe instance wins and lists its pages), then grade: start at 100, subtract 25 per high, 10 per medium and 4 per low finding; F whenever the site is not HTTPS or TLS is not ok.",
      ],
      helps: [
        "Every finding comes with a recommendation you can apply.",
        "The profile weighs a missing CSP or framing protection by what the site does, and only ever lowers a severity.",
        "Cookie findings name the cookie but never echo its value.",
      ],
      uses: [
        "After a deploy or a hosting change.",
        "Getting a concrete fix list for a small site.",
        "Catching a certificate that expires within 14 days.",
      ],
      limits: [
        "It cannot find application bugs such as SQL injection.",
        "Only pages reachable without logging in are seen: headers set only for logged-in users are not. Pages found only through JavaScript, forms or beyond the 50-page limit are not checked.",
        "It tries six common login addresses; a login at any other address is found only if a page links to it. Declare the site type if you know better.",
        "Only the first resolved address is contacted, and certificate revocation is not checked.",
        "The grade is a summary for prioritizing fixes, not a compliance rating. A good grade is not proof of security.",
        "On the hosted service only ports 80 and 443 can be checked.",
      ],
    }),
    local: {
      requirements: [PYTHON, "Network access to the site.", "Only check websites you own or are authorized to assess."],
      install: [{ command: INSTALL_KESTRIX }],
      verify: { command: "kestrix version", detail: "Prints the installed version and the author." },
      steps: [
        { title: "Check a whole site (up to 50 pages)", command: "kestrix webcheck scan https://your-site.example" },
        { title: "Check only the page you name", command: "kestrix webcheck scan https://your-site.example --page-only" },
        {
          title: "Say what the site is, if the page doesn't show it",
          detail: "For example a login the scan cannot find. A declaration can raise the profile, never lower it.",
          command: "kestrix webcheck scan https://your-site.example --site-type dynamic",
        },
        {
          title: "Check a lab host you own on a private address",
          command: "kestrix webcheck scan http://192.168.1.20:8080 --allow-private",
        },
        { title: "Get the full report as JSON", command: "kestrix webcheck scan https://your-site.example --json" },
      ],
      troubleshooting: [
        {
          problem: "Exit code 2 with target_not_allowed",
          fix: "The address resolves to a private, loopback or other non-public range. Use --allow-private only for hosts you control.",
        },
        {
          problem: "Exit code 3 with target_unreachable or upstream_error",
          fix: "The site did not answer within 10 seconds, or redirected more than 5 times.",
        },
        {
          problem: "Grade F with only a few findings",
          fix: "The grade is forced to F when the final URL is not HTTPS or the TLS status is not ok.",
        },
      ],
    },
  },
  forensics: {
    reference: reference({
      what: [
        "File analysis gives four hashes you can look up in malware databases, the real format detected from the content, entropy measurements that reveal packed or encrypted data, and photo metadata such as GPS location.",
        "URL analysis scores the link's text against a set of offline checks. The module is adapted from CyberSafeX Detection Suite (MIT).",
      ],
      how: [
        "Read the file once, in 1 MiB chunks. Nothing is executed, decompressed or rendered.",
        "Compute MD5, SHA-1, SHA-256 and SHA-512.",
        "Detect the format from the first bytes, never from the name, and compare it with the extension.",
        "Measure entropy per 4 KiB block and mark random-looking regions (7.2 bits per byte or more).",
        "With the `exif` extra, read JPEG, PNG, TIFF and WebP metadata without decoding pixels.",
        "For a link, score the URL text against the offline checks. It is never fetched, resolved or followed.",
      ],
      helps: [
        "Flags names that disguise a program, such as `invoice.pdf.exe`, and extensions that do not fit the content.",
        "Shows GPS tags and identifying camera details before you share a photo.",
        "Spots brand imitation, look-alike scripts, IP hosts and other link tricks.",
      ],
      uses: ["A download or attachment you are unsure about.", "A photo before you share it.", "A link from an email or message."],
      limits: [
        "Neither check is a malware or phishing verdict. A clean result means none of the checks fired, not that the file or site is safe.",
        "File analysis looks at structure, not behavior: it does not detect malware or unpack archives.",
        "High entropy has innocent causes such as compression, media, keys and certificates.",
        "The brand, keyword, shortener and TLD lists are fixed; a brand outside the list is not recognised.",
        "Files over 50 MiB are refused (10 MiB on the hosted service).",
      ],
    }),
    local: {
      requirements: [PYTHON, "Optional: the exif extra (Pillow) to read photo metadata."],
      install: [
        { command: INSTALL_KESTRIX },
        { command: INSTALL_EXIF, note: "Instead of the line above: adds photo metadata (Pillow)." },
      ],
      verify: { command: "kestrix version", detail: "Prints the installed version and the author." },
      steps: [
        { title: "Analyze a file", command: "kestrix forensics file ~/Downloads/invoice.pdf" },
        { title: "Check a photo before you share it", detail: "Needs the exif extra.", command: "kestrix forensics file photo.jpg" },
        { title: "Check a link without opening it", command: 'kestrix forensics url "http://paypa1-login.example.top/verify"' },
        { title: "Get the full report as JSON", command: "kestrix forensics file ~/Downloads/invoice.pdf --json" },
      ],
      troubleshooting: [
        { problem: "exif_status is pillow_not_installed", fix: "Install kestrix with the exif extra: the second command under Install." },
        { problem: "Rejected (input_too_large)", fix: "Files over 50 MiB and URLs over 8,192 characters are refused." },
        { problem: "Rejected (invalid_url)", fix: "Only http and https links (or a link without a scheme) are accepted." },
      ],
    },
  },
  detect: {
    reference: reference({
      what: [
        "Detection repair takes three inputs, a Sigma rule, an environment field mapping and labeled JSONL events, and answers with one outcome: `repaired`, `unchanged`, `abstained`, `insufficient_evidence`, `unsupported` or `engine_unavailable`, with a JSON report that holds the evidence.",
        "It needs Docker for the replay engine. Every other module works without it.",
      ],
      how: [
        "Parse the rule within the supported Sigma subset: single-event Windows `process_creation` rules. Anything else is `unsupported`.",
        "Check which mapped fields the events actually contain.",
        "Replay the rule on the pinned Elasticsearch 8.19.3 against the labeled development events.",
        "Diagnose the fault family: mapping, missing telemetry, noise or logic.",
        "Propose at most 4 candidates, each with at most 3 edits and never dropping a selection.",
        "Select on the development events, freeze the choice, then validate it on independent validation events.",
      ],
      helps: [
        "A repair is proved by replay on a real search engine, never by a Python stand-in or by conversion succeeding.",
        "Mapping faults are fixed in the mapping, so the portable rule logic stays untouched.",
        "When a field the rule needs is not collected, it says so and gives telemetry guidance instead of guessing.",
      ],
      uses: [
        "A rule that went quiet after a log pipeline change.",
        "A noisy rule that buries the team in false alarms.",
        "Checking whether the telemetry a rule needs is collected at all.",
      ],
      limits: [
        "Only the supported Sigma subset is repaired; other rules are reported as `unsupported`.",
        "Without validation events, a repair is reported as provisional.",
        "It abstains rather than guess when no candidate survives screening or validation.",
        "A repair is proved on your labeled events only. It is not proof that the rule catches every attack.",
      ],
    }),
    local: {
      requirements: [
        PYTHON,
        "Docker, for the pinned Elasticsearch replay engine.",
        "For your own rule: a Sigma rule, an environment field mapping and labeled JSONL events.",
      ],
      install: [{ command: INSTALL_KESTRIX }],
      verify: { command: "kestrix version", detail: "Prints the installed version and the author." },
      steps: [
        { title: "Start the pinned engine", detail: "Binds to 127.0.0.1:9200.", command: "kestrix detect engine-up" },
        { title: "Wait until it is ready", command: "kestrix detect engine-status" },
        { title: "List the bundled demonstrations", command: "kestrix detect cases" },
        { title: "Run one end to end", command: "kestrix detect demo c01-mapping-drift-commandline" },
        {
          title: "Repair your own rule",
          detail: "Without --validation, a repair is reported as provisional.",
          command:
            "kestrix detect run --rule rule.yml --mapping mapping.yml --dev development.jsonl --validation validation.jsonl",
        },
        {
          title: "Keep a hashed copy of the evidence",
          command: "kestrix detect demo c01-mapping-drift-commandline --evidence-dir ./evidence",
        },
      ],
      troubleshooting: [
        {
          problem: "Outcome engine_unavailable (exit 3)",
          fix: "Start the engine with kestrix detect engine-up (it needs Docker), then check kestrix detect engine-status.",
        },
        {
          problem: "Outcome unsupported (exit 11)",
          fix: "The rule uses semantics outside the supported Sigma subset: single-event Windows process_creation rules.",
        },
        {
          problem: "Exit code 2",
          fix: "The run could not produce an outcome, for example a rejected rule or fixture, a missing file or an engine that is not the pinned version. The error is printed to stderr.",
        },
        {
          problem: "Outcome abstained (exit 10)",
          fix: "No candidate survived screening or validation. Kestrix does not guess; the report explains why.",
        },
      ],
    },
  },
  code: {
    reference: reference({
      what: [
        "`kestrix-scan` finds shell and SQL injection, XSS sinks, unsafe deserialization, disabled TLS checks, weak hashes and randomness, leaked API keys, and lockfile dependencies with known vulnerabilities or reported as malware, with a CWE and a concrete fix for every finding.",
        "It is its own package with no dependencies on Python 3.11 and newer, and part of the `kestrix` workbench as `kestrix code scan`.",
      ],
      how: [
        "Walk the paths you give, skipping `.gitignore`d, vendored and build paths.",
        "Parse Python with the standard-library `ast`, split JavaScript and TypeScript with a bounded tokenizer, and read text files for secrets. Nothing is imported or executed.",
        "Apply 59 rules, with taint analysis within one function from Flask, Django, FastAPI, Express and LLM-client sources.",
        "After `kestrix-scan db update`, match lockfile versions against the local OSV index.",
        "Report each finding with its rule id, CWE and fix, and exit 1 when one meets `--fail-on` (default `high`).",
      ],
      helps: [
        "Runs in your terminal, pre-commit, pytest and CI, with SARIF for GitHub code scanning.",
        "Baselines and `--diff` let you adopt it gradually.",
        "Secret values never leave the scanner: findings show only the kind and the first four characters.",
      ],
      uses: [
        "Before a commit, through the pre-commit hook.",
        "In CI, uploading SARIF to GitHub code scanning.",
        "Reviewing code an AI assistant wrote, through the Claude Code plugin.",
        "Auditing lockfiles for vulnerable or malicious packages.",
      ],
      limits: [
        "No findings means no rule fired, not that the code is secure. No findings is not proof of security.",
        "Rules are pattern analysis: they miss things and can be wrong in context. No real-world detection rate is claimed.",
        "Taint is followed within one function, never across functions or files.",
        "JavaScript and TypeScript are matched by shape without a full parser; Vue and Svelte files are not analyzed.",
        "Dependency checks cover PyPI and npm lockfiles only, and reachability is not analyzed.",
      ],
    }),
    local: {
      requirements: [
        "Python 3.10 to 3.13. No dependencies on 3.11 and newer (only tomli on 3.10).",
        "git, for --diff and directory walks.",
        "Network only for kestrix-scan db update, which downloads the public OSV data.",
      ],
      install: [{ command: INSTALL_SCAN }],
      verify: { command: "kestrix-scan version", detail: "Prints the installed version and the author." },
      steps: [
        { title: "Scan a directory", detail: "Exit 1 on high or critical findings.", command: "kestrix-scan src" },
        { title: "Download the vulnerability data once", detail: "The only network step.", command: "kestrix-scan db update" },
        { title: "Scan again: lockfiles are now checked too, offline", command: "kestrix-scan ." },
        {
          title: "Set up the project",
          detail: "Adds [tool.kestrix] settings, a GitHub code scanning workflow and the pre-commit hook.",
          command: "kestrix-scan init --ci github --pre-commit",
        },
        { title: "Only report lines changed since a git ref", command: "kestrix-scan . --diff main" },
        { title: "Write SARIF for GitHub code scanning", command: "kestrix-scan --format sarif --output kestrix.sarif" },
        { title: "Run it inside your test suite", command: "pytest --kestrix" },
      ],
      troubleshooting: [
        {
          problem: "A confirmed false positive",
          fix: "Add # kestrix: ignore[<rule-id>] <reason> on that line or the line above. The reason is required.",
        },
        {
          problem: "Exit code 2",
          fix: "A usage or input error, such as a missing path, a bad baseline, an unknown git ref or an unknown rule id in the settings.",
        },
        { problem: "A dep.db_stale note", fix: "The OSV index is missing or more than 7 days old. Run kestrix-scan db update." },
      ],
    },
  },
  "claude-plugin": {
    reference: [
      {
        heading: "What it does",
        blocks: [
          p(
            "After every `Write`, `Edit`, `MultiEdit` or `NotebookEdit`, and after a Bash command that changes source files in a git repository, a hook runs the local Kestrix scanner on the changed files. Findings at medium severity or above that the edit introduced come back to Claude with the rule, the CWE and the fix. The plugin ships inside the `kestrix-scan` wheel.",
          ),
        ],
      },
      {
        heading: "How the hooks work",
        blocks: [
          steps(
            "Before an edit, a `PreToolUse` hook snapshots the file, so new findings can be told from old ones. It never blocks a tool.",
            "Claude edits the file.",
            "A `PostToolUse` hook scans the changed file with `kestrix-scan --hook`.",
            "The medium-or-worse findings this edit introduced go back to Claude as context, with the rule, CWE and fix.",
            "Claude fixes them in the same turn. A confirmed false positive gets an inline suppression with a written reason.",
          ),
          p("A `SessionStart` hook tells Claude the hooks are active and shows you one line that scanning is on."),
        ],
      },
      {
        heading: "The Stop gate (opt-in)",
        blocks: [
          p(
            "With the gate on, Claude cannot finish while files changed this session have high or critical findings that this session introduced. It blocks at most three times per session, and lets Claude stop when the findings are unchanged after two blocks. `KESTRIX_BLOCK_ON_STOP=0` turns it off even when `.kestrix.json` turns it on.",
          ),
        ],
      },
      {
        heading: "Commands and skills",
        blocks: [
          list(
            "`/kestrix:status` shows this session's record: files scanned, findings reported, and files that were not security-checked, with the reason. It scans nothing.",
            "`/kestrix:scan [path]` scans and summarizes; it changes no code.",
            "`/kestrix:fix [path]` fixes every finding at medium or above and re-scans, for at most 5 rounds.",
            "`/kestrix:review [base-ref]` reviews the current diff.",
            "Skills: `secure-code-review`, `fixing-security-findings` and `kestrix-security`.",
          ),
        ],
      },
      {
        heading: "Install guard",
        blocks: [
          p(
            "Before a `pip`, `uv`, `npm`, `pnpm` or `yarn` install runs, the plugin checks the packages against the local OSV index. A known malicious package is denied; a known-vulnerable pinned version gets a warning naming the fixed version. Without an index there is no check. Turn it off with `KESTRIX_INSTALL_GUARD=0`.",
          ),
        ],
      },
      {
        heading: "Privacy and limits",
        blocks: [
          list(
            "Neither the scanner nor the hooks open a network connection. The scanner reads files as data and never imports, executes or uploads them.",
            "The hook output is part of your conversation, so findings go to Anthropic like any other conversation content. They hold rule ids, paths, line numbers, messages and fixes, never secret values.",
            "It fails open: a missing scanner, a timeout or an error never blocks an edit.",
            "Edits made outside Claude Code, files over 1 MiB and anything before the plugin loaded are not scanned.",
            "No findings is not proof of security.",
          ),
        ],
      },
    ],
    local: {
      requirements: [
        "Claude Code.",
        "kestrix-scan on PATH (the full kestrix package includes it).",
        "python3 on PATH: any Python 3.9 or later, including the macOS system Python.",
      ],
      install: [{ command: INSTALL_SCAN }],
      verify: { command: "kestrix-scan version", detail: "Prints the installed version and the author." },
      steps: [
        {
          title: "Copy the plugin",
          detail: "Copies it to ~/.claude/kestrix-plugin and prints the next commands. It never edits your Claude Code settings.",
          command: "kestrix-scan install-claude-plugin",
        },
        { title: "Add it as a local marketplace", command: "claude plugin marketplace add ~/.claude/kestrix-plugin" },
        { title: "Install it", command: "claude plugin install kestrix@kestrix-local" },
        { title: "Load it", detail: "Start a new Claude Code session, or run this in the current one.", command: "/reload-plugins" },
        {
          title: "Optional: turn on the Stop gate",
          detail: 'Set it in the environment Claude Code runs in, or commit {"claude": {"block_on_stop": true}} as .kestrix.json.',
          command: "export KESTRIX_BLOCK_ON_STOP=1",
        },
        { title: "See what was scanned this session", command: "/kestrix:status" },
      ],
      troubleshooting: [
        {
          problem: "No findings or messages appear",
          fix: "The hooks fail open: a missing scanner, a timeout or an error never blocks an edit. Check that kestrix-scan and python3 are on PATH; /kestrix:status lists files that were not checked and why.",
        },
        {
          problem: "The plugin is not loaded",
          fix: "Start a new session or run /reload-plugins. To try it for one session: claude --plugin-dir ~/.claude/kestrix-plugin.",
        },
        {
          problem: "Claude finishes with findings left",
          fix: "The Stop gate is off by default. Turn it on with KESTRIX_BLOCK_ON_STOP=1. It blocks at most three times per session.",
        },
        {
          problem: "Remove the plugin",
          fix: "Run claude plugin uninstall kestrix@kestrix-local and claude plugin marketplace remove kestrix-local, then delete the directory.",
        },
      ],
    },
  },
  bitcoin: {
    reference: reference({
      what: [
        "You paste public addresses or public keys. Kestrix never asks for private keys or seed phrases, and it cannot sign, send or move coins.",
        "A large enough quantum computer running Shor's algorithm could derive a private key from its public key. No such computer is publicly known to exist, so the module reports exposure, not attack timelines. It is adapted from BitShield (MIT Bitcoin Expo 2026, Team ACE).",
      ],
      how: [
        "Decode each address or public key locally, verifying checksums.",
        "Rate it by type: a raw public key (P2PK) is critical and Taproot (P2TR) is high, because the key is visible; hash-based types are unknown.",
        "Optionally (`--lookup-chain`), ask mempool.space whether a hash-based address has been spent from: high if it has, low if not.",
        "Recommend what to do, and give step-by-step migration plans for each address type.",
      ],
      helps: [
        "Shows which coins a future quantum computer could target first.",
        "Without a lookup, a scan makes no network requests.",
        "Migration plans describe what you do in your own wallet.",
      ],
      uses: [
        "Checking which of your addresses are exposed.",
        "Deciding whether to move coins, and to which address type.",
        "Learning why an address type shows or hides its key.",
      ],
      limits: [
        "It reports exposure, not when an attack could happen.",
        "A lookup sends each looked-up address, with your IP address, to mempool.space.",
        "`low` assumes the same key is not also used by another address that has been spent from.",
        "The steps hide your public key; they do not make coins quantum-proof. BIP-360 and other post-quantum output types are draft proposals, not active on the network.",
      ],
    }),
    local: {
      requirements: [
        PYTHON,
        "Public addresses or public keys only. Kestrix never asks for private keys or seed phrases, and cannot move coins.",
        "Optional: network access for --lookup-chain (sends each looked-up address to mempool.space).",
        "Optional: the ai extra and your own Anthropic API key for the guardian.",
      ],
      install: [
        { command: INSTALL_KESTRIX },
        { command: INSTALL_AI, note: "Instead of the line above, only for the optional guardian." },
      ],
      verify: { command: "kestrix version", detail: "Prints the installed version and the author." },
      steps: [
        {
          title: "Scan addresses offline",
          detail: "Up to 100 addresses or hex public keys. No network requests.",
          command: "kestrix bitcoin scan bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        },
        {
          title: "Check whether a hash-based address has been spent from",
          detail: "Sends the address and your IP address to mempool.space.",
          command: "kestrix bitcoin scan bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq --lookup-chain",
        },
        { title: "Get the migration steps for an address type", command: "kestrix bitcoin migration P2TR" },
        { title: "Optional: store your Anthropic key for the guardian", command: "kestrix config set-anthropic-key" },
        { title: "Optional: ask in plain language", command: 'kestrix bitcoin ask "is my taproot address safe?"' },
      ],
      troubleshooting: [
        {
          problem: "Rejected invalid_input naming an address #N",
          fix: "That input is not a valid address or public key. The scan stops at the first invalid input.",
        },
        {
          problem: "upstream_error during a lookup (exit 3)",
          fix: "mempool.space rate-limited the request or did not answer. The scan never falls back to a partial result; try again later.",
        },
        {
          problem: "ai_key_missing",
          fix: "Install kestrix with the ai extra (the second command under Install), then set ANTHROPIC_API_KEY or run kestrix config set-anthropic-key.",
        },
        {
          problem: "Risk unknown",
          fix: "Only a hash is visible. Without --lookup-chain the tool cannot tell whether the address has been spent from.",
        },
      ],
    },
  },
};
