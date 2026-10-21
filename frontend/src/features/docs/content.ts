// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { IconName } from "../../components/Icon";
import type { ExampleId } from "../guides/examples";

/*
 * The in-app documentation. It summarizes README.md, docs/modules/*.md,
 * packages/kestrix-scan/README.md, docs/claude-plugin.md and ADR 0006, and must never contradict
 * them: when those change, change this file in the same commit. Text in `backticks` is shown as
 * code; nothing here is parsed as HTML.
 */

export type Block =
  | { kind: "p"; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "steps"; items: string[] }
  | { kind: "code"; code: string; label?: string }
  | { kind: "example"; example: ExampleId };

export interface DocSection {
  heading: string;
  blocks: Block[];
}

export type DocGroup = "Start" | "Tools" | "Packages and integrations";

export interface DocPage {
  /** "" for the overview, at /docs. */
  slug: string;
  title: string;
  nav: string;
  group: DocGroup;
  icon: IconName;
  lede: string;
  sections: DocSection[];
}

const p = (text: string): Block => ({ kind: "p", text });
const list = (...items: string[]): Block => ({ kind: "list", items });
const steps = (...items: string[]): Block => ({ kind: "steps", items });
const code = (source: string, label?: string): Block =>
  label === undefined ? { kind: "code", code: source } : { kind: "code", code: source, label };

interface ToolDoc {
  slug: ExampleId;
  title: string;
  nav: string;
  icon: IconName;
  lede: string;
  what: string[];
  how: string[];
  helps: string[];
  uses: string[];
  limits: string[];
  tryIt: string[];
}

function toolPage(doc: ToolDoc): DocPage {
  return {
    slug: doc.slug,
    title: doc.title,
    nav: doc.nav,
    group: "Tools",
    icon: doc.icon,
    lede: doc.lede,
    sections: [
      { heading: "What it is", blocks: doc.what.map(p) },
      { heading: "How it works", blocks: [steps(...doc.how)] },
      { heading: "How it helps", blocks: [list(...doc.helps)] },
      { heading: "Typical uses", blocks: [list(...doc.uses)] },
      { heading: "Limits", blocks: [list(...doc.limits)] },
      { heading: "Try it", blocks: doc.tryIt.map((command) => code(command)) },
      { heading: "A real example result", blocks: [{ kind: "example", example: doc.slug }] },
    ],
  };
}

const overview: DocPage = {
  slug: "",
  title: "Kestrix documentation",
  nav: "Overview",
  group: "Start",
  icon: "bookOpen",
  lede: "Security checks for your code, and a local-first security workbench. Everything runs on your own machine.",
  sections: [
    {
      heading: "What Kestrix is",
      blocks: [
        p(
          "Kestrix is an open-source security toolkit by Ruthvik Bandari. It fixes broken threat detections, inspects suspicious files and links, checks your website's defences, reads suspicious emails, tells you whether your Bitcoin addresses are exposed to future quantum attacks, and finds security mistakes in code, including the code an AI assistant writes.",
        ),
        p(
          "Every result starts with a plain answer and keeps the evidence that produced it. Heuristic scores are labeled as heuristics, never as probabilities, and a clean result always means that no check fired, not that something is safe.",
        ),
      ],
    },
    {
      heading: "Two packages",
      blocks: [
        list(
          "`kestrix-scan` is the code scanner and the Claude Code plugin. It has no dependencies on Python 3.11 and newer (only `tomli` on 3.10) and works in the terminal, CI, pre-commit, pytest and Claude Code.",
          "`kestrix` is the full workbench: every module, the `kestrix` CLI and the dashboard. It depends on `kestrix-scan`, so one install gives you both; `kestrix code scan` runs the same scanner.",
        ),
        code("pip install kestrix-scan"),
        code("pip install kestrix"),
        p("Both need Python 3.10 or newer. The workbench has two optional extras: `kestrix[exif]` for photo metadata and `kestrix[ai]` for the Bitcoin guardian."),
      ],
    },
    {
      heading: "Seven tools",
      blocks: [
        list(
          "Email check: explains the phishing, impersonation and malware-delivery signs in a saved `.eml` message.",
          "Web check: grades the HTTPS, TLS, security headers and cookie settings of a site you own.",
          "File & link forensics: hashes, real file type, entropy and photo metadata of a file; phishing signs in a link, without opening it.",
          "Detection repair: finds why a Sigma rule misses attacks or is noisy, and proves the smallest fix by replaying labeled events.",
          "Code scanner: insecure Python, JavaScript and TypeScript, hard-coded secrets and vulnerable dependencies.",
          "Claude Code plugin: scans every file Claude writes so Claude fixes what it introduced, in the same turn.",
          "Bitcoin quantum risk: which addresses show a public key on chain, and how to move coins to hide it.",
        ),
      ],
    },
    {
      heading: "How it fits together",
      blocks: [
        steps(
          "One core: each module is a set of Python functions. The `kestrix` CLI and the dashboard's API call the same functions, so a result is the same wherever you run it.",
          "`kestrix dashboard` starts a FastAPI server on `127.0.0.1:8765` that serves the API and the bundled dashboard. It answers only local requests.",
          "Outbound requests are opt-in and say so first: the website check, the Bitcoin chain lookup and the AI guardian. Everything else works offline.",
          "Detection repair replays rules on a pinned Elasticsearch 8.19.3 that you start with Docker; it is the only matching oracle.",
          "`kestrix-scan` stands alone, and the workbench and the Claude Code plugin both call it.",
        ),
      ],
    },
    {
      heading: "On your computer, or on the hosted service",
      blocks: [
        p(
          "By default Kestrix runs on your own machine, with no accounts. The hosted service adds Google or GitHub sign-in and runs the email check, the web check and forensics on Kestrix's server; uploaded files and emails are never stored.",
        ),
        p(
          "Detection repair, the Bitcoin check, the code scanner and the Claude Code plugin run on your computer only. Their pages on the hosted service are guides to installing and using them.",
        ),
        p("Use Kestrix only on systems, files and websites you own or are authorized to assess."),
      ],
    },
  ],
};

const tools: DocPage[] = [
  toolPage({
    slug: "mail",
    title: "Email check",
    nav: "Email check",
    icon: "mailWarning",
    lede: "Offline analysis of one saved email message, with a reason for every finding.",
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
      "Detection and false-positive rates have not been measured, so none are claimed.",
      "The scam phrase lists are small, curated and English only; paraphrases and other languages are missed.",
      "The look-alike table is a curated subset of the Unicode confusables list, and organizations are grouped without the full Public Suffix List.",
      "The heuristic score orders messages for attention. It is not a probability.",
    ],
    tryIt: ["kestrix mail analyze message.eml --protected-domain example-bank.com"],
  }),
  toolPage({
    slug: "webcheck",
    title: "Web check",
    nav: "Web check",
    icon: "globeLock",
    lede: "A passive A to F grade of a website's HTTPS, TLS, security headers and cookies, with a fix for each problem.",
    what: [
      "The website check grades how well a site protects its visitors at the connection and browser level: HTTPS, the TLS certificate, security headers and cookie flags.",
      "It sends one GET request (following up to five redirects) and makes one TLS handshake. It does not crawl, fuzz, log in or scan ports.",
    ],
    how: [
      "Validate the target: only public addresses, on every redirect, unless you pass `--allow-private` for a host you own.",
      "Connect to the validated IP address, with the real host name in the `Host` header and TLS SNI. The whole chain has 10 seconds.",
      "Make one verified TLS handshake and record the protocol, issuer and expiry.",
      "Profile the site from the page it fetched: `static`, `static_api` or `dynamic`.",
      "Check headers and cookies, then grade: start at 100, subtract 25 per high, 10 per medium and 4 per low finding; F whenever the site is not HTTPS or TLS is not ok.",
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
      "One response is checked: headers set only on other pages, or only for logged-in users, are not seen.",
      "Only the first resolved address is contacted, and certificate revocation is not checked.",
      "The grade is a summary for prioritizing fixes, not a compliance rating. A good grade is not proof of security.",
      "On the hosted service only ports 80 and 443 can be checked.",
    ],
    tryIt: ["kestrix webcheck scan https://your-site.example"],
  }),
  toolPage({
    slug: "forensics",
    title: "File & link forensics",
    nav: "File & link forensics",
    icon: "fileSearch",
    lede: "What a file really is, and whether a link shows common phishing signs, without running the file or opening the link.",
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
    uses: [
      "A download or attachment you are unsure about.",
      "A photo before you share it.",
      "A link from an email or message.",
    ],
    limits: [
      "Neither check is a malware or phishing verdict. A clean result means none of the checks fired, not that the file or site is safe.",
      "File analysis looks at structure, not behavior: it does not detect malware or unpack archives.",
      "High entropy has innocent causes such as compression, media, keys and certificates.",
      "The brand, keyword, shortener and TLD lists are fixed; a brand outside the list is not recognised.",
      "Files over 50 MiB are refused (10 MiB on the hosted service).",
    ],
    tryIt: ["kestrix forensics file ~/Downloads/invoice.pdf", 'kestrix forensics url "http://paypa1-login.example.top/verify"'],
  }),
  toolPage({
    slug: "detect",
    title: "Detection repair",
    nav: "Detection repair",
    icon: "shieldCheck",
    lede: "Why a Sigma rule misses attacks or fires on benign activity, the smallest fix it can justify, and proof from replayed events.",
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
    tryIt: ["kestrix detect engine-up", "kestrix detect demo c01-mapping-drift-commandline"],
  }),
  toolPage({
    slug: "code",
    title: "Code scanner",
    nav: "Code scanner",
    icon: "scanSearch",
    lede: "kestrix-scan: local security checks for Python, JavaScript and TypeScript code, hard-coded secrets and dependencies.",
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
    tryIt: ["kestrix-scan src"],
  }),
  toolPage({
    slug: "bitcoin",
    title: "Bitcoin quantum risk",
    nav: "Bitcoin quantum risk",
    icon: "bitcoin",
    lede: "Which of your addresses have a public key visible on the blockchain, and how to move coins to an address that hides it.",
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
    tryIt: ["kestrix bitcoin scan bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "kestrix bitcoin migration P2TR"],
  }),
];

const packages: DocPage = {
  slug: "packages",
  title: "The pip packages",
  nav: "pip packages",
  group: "Packages and integrations",
  icon: "package",
  lede: "Install, run and configure kestrix-scan and kestrix, in the terminal, pre-commit, GitHub and pytest.",
  sections: [
    {
      heading: "Install",
      blocks: [
        code("pip install kestrix-scan"),
        p("Only the code scanner and the Claude Code plugin. Or use `uv tool install kestrix-scan` or `pipx install kestrix-scan`."),
        code("pip install kestrix"),
        p("The full workbench and dashboard, including `kestrix-scan`. Add `kestrix[exif]` for photo metadata or `kestrix[ai]` for the Bitcoin guardian."),
        p(
          "Before the first PyPI release, install the scanner from GitHub: `pip install \"git+https://github.com/Ruthvik-Bandari/kestrix#subdirectory=packages/kestrix-scan\"`.",
        ),
      ],
    },
    {
      heading: "The kestrix-scan command",
      blocks: [
        code("kestrix-scan src"),
        list(
          "`--format text|json|sarif`: the output format. SARIF 2.1.0 is for GitHub code scanning.",
          "`--output FILE`: write the report to a file instead of stdout.",
          "`--fail-on low|medium|high|critical|none`: the lowest severity that makes the command exit 1 (default `high`).",
          "`--diff REF`: only report findings on lines changed since a git ref.",
          "`--baseline FILE` and `--write-baseline FILE`: leave out known findings, or record the current ones.",
          "`--config FILE` and `--no-config`: use one settings file, or ignore settings files.",
        ),
        p("Exit codes: 0 nothing at or above `--fail-on`, 1 findings at or above it, 2 usage or input error. `kestrix-scan rules` lists every rule."),
        p("Silence a confirmed false positive on its line, or the line above, with a required reason: `# kestrix: ignore[py.subprocess.shell_true] command from the reviewed deploy config`."),
      ],
    },
    {
      heading: "Dependencies",
      blocks: [
        code("kestrix-scan db update"),
        p(
          "Downloads the public OSV data for PyPI and npm: the only command that uses the network. Scans then check `requirements*.txt` pins and `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock` and `pnpm-lock.yaml` offline. `kestrix-scan db status` shows the index.",
        ),
      ],
    },
    {
      heading: "Configuration",
      blocks: [
        p("`[tool.kestrix]` in `pyproject.toml`, or the same keys at the top level of `.kestrix.toml`. The nearest file wins, and command-line flags override it."),
        code(
          `[tool.kestrix]
fail-on = "medium"                              # low, medium, high, critical or none
exclude = ["tests/fixtures/", "*.min.js"]       # globs, as in .gitignore
baseline = ".kestrix-baseline.json"             # relative to this file
rules.enable = ["py.", "secret."]               # rule ids or prefixes; default: every rule
rules.disable = ["py.crypto.weak_hash"]`,
          "pyproject.toml",
        ),
        p("`kestrix-scan init` appends a minimal `[tool.kestrix]` without rewriting the file; `--pre-commit`, `--ci github` and `--claude-plugin` set up the rest."),
        code("kestrix-scan init --ci github --pre-commit"),
      ],
    },
    {
      heading: "pre-commit",
      blocks: [
        code(
          `repos:
  - repo: https://github.com/Ruthvik-Bandari/kestrix
    rev: v0.1.0
    hooks:
      - id: kestrix-scan`,
          ".pre-commit-config.yaml",
        ),
        p("The hook scans the staged Python and text files and honours `[tool.kestrix]`."),
      ],
    },
    {
      heading: "GitHub Action",
      blocks: [
        p(
          "`kestrix-scan init --ci github` writes `.github/workflows/kestrix.yml`. Its actions are pinned to commit SHAs and its job has only `contents: read` and `security-events: write`. The key steps:",
        ),
        code(
          `- run: pip install kestrix-scan==0.1.0
- run: kestrix-scan db update        # downloads the OSV data, so this job needs network access
- run: kestrix-scan --format sarif --output kestrix.sarif || true
- uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
  with:
    sarif_file: kestrix.sarif`,
          ".github/workflows/kestrix.yml (excerpt)",
        ),
        p("Findings appear under Security → Code scanning. To fail the build instead, drop `|| true`."),
      ],
    },
    {
      heading: "pytest",
      blocks: [
        code("pytest --kestrix"),
        code("pytest --kestrix --kestrix-fail-on=medium"),
        p("Adds one `kestrix-scan` item that scans the rootdir and fails when findings meet the threshold. Without `--kestrix` the scanner is not even imported."),
      ],
    },
    {
      heading: "The kestrix workbench CLI",
      blocks: [
        code("kestrix dashboard"),
        p("Opens the dashboard at `http://localhost:8765`. Every module also has commands, for example:"),
        code("kestrix forensics file ~/Downloads/invoice.pdf"),
        code("kestrix webcheck scan https://your-site.example"),
        p("Add `--json` to any command for machine-readable output. Exit codes are stable, so the commands work in scripts and CI."),
      ],
    },
  ],
};

const plugin: DocPage = {
  slug: "claude-plugin",
  title: "Claude Code plugin",
  nav: "Claude Code plugin",
  group: "Packages and integrations",
  icon: "bot",
  lede: "Claude Code checks the code it writes: every edit is scanned, and Claude fixes what the edit introduced in the same turn.",
  sections: [
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
          "With the gate on, Claude cannot finish while files changed this session have high or critical findings that this session introduced. It blocks at most three times per session, and lets Claude stop when the findings are unchanged after two blocks.",
        ),
        code("export KESTRIX_BLOCK_ON_STOP=1"),
        p("Or commit `{\"claude\": {\"block_on_stop\": true}}` as `.kestrix.json` at the project root. `KESTRIX_BLOCK_ON_STOP=0` turns it off even then."),
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
      heading: "Install",
      blocks: [
        p("The hooks need `kestrix-scan` and `python3` (3.9 or later) on PATH."),
        code("pip install kestrix-scan"),
        code("kestrix-scan install-claude-plugin"),
        code("claude plugin marketplace add ~/.claude/kestrix-plugin"),
        code("claude plugin install kestrix@kestrix-local"),
        p("Start a new session, or run `/reload-plugins`. The installer never edits your Claude Code settings."),
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
    { heading: "A real example result", blocks: [{ kind: "example", example: "claude-plugin" }] },
  ],
};

export const docPages: DocPage[] = [overview, ...tools, packages, plugin];

export const DOC_GROUPS: DocGroup[] = ["Start", "Tools", "Packages and integrations"];

export function findDoc(slug: string | undefined): DocPage | undefined {
  const key = slug === undefined || slug === "overview" ? "" : slug;
  return docPages.find((page) => page.slug === key);
}
