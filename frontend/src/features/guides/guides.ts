// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { IconName } from "../../components/Icon";
import { examples, type Example } from "./examples";

/*
 * Command-line guides, one per tool. The content follows docs/modules/*.md,
 * packages/kestrix-scan/README.md and docs/claude-plugin.md; every command and option exists in
 * the CLIs (src/kestrix/*\/cli.py, packages/kestrix-scan/src/kestrix_scan/cli.py). Change the
 * docs first, then this file.
 */

export type GuideTool = "mail" | "webcheck" | "forensics" | "detect" | "code" | "claude-plugin" | "bitcoin";

export interface GuideStep {
  title: string;
  detail?: string;
  command?: string;
}

export interface Guide {
  tool: GuideTool;
  name: string;
  icon: IconName;
  /** One sentence: what the tool is. */
  summary: string;
  /** What it protects you from. */
  protects: string;
  /** How it helps, in a few short points. */
  helps: string[];
  requirements: string[];
  install: { command: string; note?: string }[];
  steps: GuideStep[];
  example: Example;
  troubleshooting: { problem: string; fix: string }[];
  /** The docs page: dashboardPath(`docs/${docsSlug}`). */
  docsSlug: string;
}

export const GUIDE_TOOLS: GuideTool[] = ["mail", "webcheck", "forensics", "detect", "code", "claude-plugin", "bitcoin"];

const PYTHON = "Python 3.10 or newer.";

export const guides: Record<GuideTool, Guide> = {
  mail: {
    tool: "mail",
    name: "Email check",
    icon: "mailWarning",
    summary:
      "Checks one saved email message (.eml) for common phishing and malware-delivery signs and explains each one.",
    protects:
      "Protects you from phishing, impersonation and fake-invoice emails by explaining exactly what is wrong with a saved message.",
    helps: [
      "Reads the sender authentication results your mail provider stamped on the message.",
      "Compares the sender's addresses and looks for domains that imitate the ones you protect.",
      "Checks links and attachments as text, and looks for the wording of payment and credential scams.",
    ],
    requirements: [
      PYTHON,
      "A saved message: in Gmail, ⋮ (More) → Download message; in Outlook, File → Save as.",
      "No network: links are never visited and attachments are never opened.",
    ],
    install: [{ command: "pip install kestrix" }],
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
    example: examples.mail,
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
      {
        problem: "The verdict is clean",
        fix: "Clean means none of the checks fired, not that the message is safe. The checks are heuristics.",
      },
    ],
    docsSlug: "mail",
  },
  webcheck: {
    tool: "webcheck",
    name: "Web check",
    icon: "globeLock",
    summary:
      "Grades how well a website protects its visitors: HTTPS, the TLS certificate, security headers and cookie flags.",
    protects:
      "Protects you from running a website with missing HTTPS protections, an expiring certificate or unsafe browser security headers.",
    helps: [
      "Sends one GET request (following up to five redirects) and makes one TLS handshake. It does not crawl, fuzz, log in or scan ports.",
      "Gives each problem a recommendation, and the result an A to F grade from a fixed rubric.",
    ],
    requirements: [
      PYTHON,
      "Network access to the site.",
      "Only check websites you own or are authorized to assess.",
    ],
    install: [{ command: "pip install kestrix" }],
    steps: [
      { title: "Check a site", command: "kestrix webcheck scan https://your-site.example" },
      {
        title: "Say what the site is, if the page doesn't show it",
        detail: "For example a login behind a link. A declaration can raise the profile, never lower it.",
        command: "kestrix webcheck scan https://your-site.example --site-type dynamic",
      },
      {
        title: "Check a lab host you own on a private address",
        command: "kestrix webcheck scan http://192.168.1.20:8080 --allow-private",
      },
      { title: "Get the full report as JSON", command: "kestrix webcheck scan https://your-site.example --json" },
    ],
    example: examples.webcheck,
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
    docsSlug: "webcheck",
  },
  forensics: {
    tool: "forensics",
    name: "File & link forensics",
    icon: "fileSearch",
    summary:
      "Tells you what a file really is and whether a link shows common phishing signs, without running the file or opening the link.",
    protects:
      "Protects you from files that are not what their name claims, hidden encrypted payloads, photos that reveal where they were taken, and look-alike phishing links.",
    helps: [
      "Four hashes you can look up in malware databases, and the real format detected from the content.",
      "Entropy measurements that reveal packed or encrypted data, and photo metadata such as GPS location.",
      "Offline checks that score a link's text. The URL is never fetched.",
    ],
    requirements: [PYTHON, "Optional: the exif extra (Pillow) to read photo metadata."],
    install: [
      { command: "pip install kestrix" },
      { command: 'pip install "kestrix[exif]"', note: "Adds photo metadata (Pillow)." },
    ],
    steps: [
      { title: "Analyze a file", command: "kestrix forensics file ~/Downloads/invoice.pdf" },
      { title: "Check a photo before you share it", detail: "Needs the exif extra.", command: "kestrix forensics file photo.jpg" },
      { title: "Check a link without opening it", command: 'kestrix forensics url "http://paypa1-login.example.top/verify"' },
      { title: "Get the full report as JSON", command: "kestrix forensics file ~/Downloads/invoice.pdf --json" },
    ],
    example: examples.forensics,
    troubleshooting: [
      {
        problem: "exif_status is pillow_not_installed",
        fix: 'Install the extra with pip install "kestrix[exif]".',
      },
      { problem: "Rejected (input_too_large)", fix: "Files over 50 MiB and URLs over 8,192 characters are refused." },
      { problem: "Rejected (invalid_url)", fix: "Only http and https links (or a link without a scheme) are accepted." },
      {
        problem: "No findings",
        fix: "A clean result means none of the checks fired, not that the file or site is safe.",
      },
    ],
    docsSlug: "forensics",
  },
  detect: {
    tool: "detect",
    name: "Detection repair",
    icon: "shieldCheck",
    summary:
      "Finds out why a Sigma rule misses attacks or fires on benign activity, proposes the smallest fix it can justify, and checks it by replaying labeled events.",
    protects:
      "Protects you from detection rules that silently stop catching attacks, or bury your team in false alarms. It finds the cause and proposes a fix that has been tested on labeled events.",
    helps: [
      "Answers with one outcome: repaired, unchanged, abstained, insufficient_evidence, unsupported or engine_unavailable.",
      "Replays every candidate on a pinned Elasticsearch 8.19.3, the only matching oracle.",
      "Writes a JSON report that holds the evidence, with an optional hashed copy.",
    ],
    requirements: [
      PYTHON,
      "Docker, for the pinned Elasticsearch replay engine.",
      "For your own rule: a Sigma rule, an environment field mapping and labeled JSONL events.",
    ],
    install: [{ command: "pip install kestrix" }],
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
    example: examples.detect,
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
    docsSlug: "detect",
  },
  code: {
    tool: "code",
    name: "Code scanner",
    icon: "scanSearch",
    summary:
      "kestrix-scan finds security mistakes in Python, JavaScript and TypeScript code, hard-coded secrets and vulnerable or malicious dependencies.",
    protects:
      "Protects you from shipping shell and SQL injection, XSS sinks, unsafe deserialization, disabled TLS checks, weak hashes and randomness, leaked API keys and dependencies with known vulnerabilities.",
    helps: [
      "Every finding names a rule, a CWE, why it matters and a concrete fix.",
      "Runs in your terminal, in CI with SARIF for GitHub code scanning, in pre-commit and in pytest.",
      "Nothing leaves your machine: files are read as data, never imported, executed or uploaded.",
    ],
    requirements: [
      "Python 3.10 to 3.13. No dependencies on 3.11 and newer (only tomli on 3.10).",
      "git, for --diff and directory walks.",
      "Network only for kestrix-scan db update, which downloads the public OSV data.",
    ],
    install: [
      { command: "pip install kestrix-scan", note: "Or: uv tool install kestrix-scan / pipx install kestrix-scan." },
    ],
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
    example: examples.code,
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
      {
        problem: "No findings",
        fix: "No findings means no rule fired, not that the code is secure. Rules are pattern analysis and miss things.",
      },
    ],
    docsSlug: "code",
  },
  "claude-plugin": {
    tool: "claude-plugin",
    name: "Claude Code plugin",
    icon: "bot",
    summary:
      "Makes Claude Code check the code it writes: after every edit, a hook scans the changed file and Claude fixes what the edit introduced.",
    protects:
      "Protects you from insecure code written by an AI assistant: findings come back to Claude with the rule, the CWE and the fix, in the same turn.",
    helps: [
      "Scans after every Write, Edit, MultiEdit and NotebookEdit, and after Bash commands that change source files in a git repository.",
      "An optional Stop gate keeps Claude from finishing while new high or critical findings remain.",
      "An install guard checks pip, uv, npm, pnpm and yarn installs against the local OSV index.",
    ],
    requirements: [
      "Claude Code.",
      "kestrix-scan on PATH (the full kestrix package includes it).",
      "python3 on PATH: any Python 3.9 or later, including the macOS system Python.",
    ],
    install: [{ command: "pip install kestrix-scan" }],
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
        detail: "Set it in the environment Claude Code runs in, or commit {\"claude\": {\"block_on_stop\": true}} as .kestrix.json.",
        command: "export KESTRIX_BLOCK_ON_STOP=1",
      },
      { title: "See what was scanned this session", command: "/kestrix:status" },
    ],
    example: examples["claude-plugin"],
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
    docsSlug: "claude-plugin",
  },
  bitcoin: {
    tool: "bitcoin",
    name: "Bitcoin quantum risk",
    icon: "bitcoin",
    summary:
      "Tells you which of your Bitcoin addresses have a public key visible on the blockchain, and how to move coins to an address that hides it.",
    protects:
      "Protects your coins from future quantum computers by flagging addresses whose public key is already visible on the blockchain, with a step-by-step plan to move them.",
    helps: [
      "Decodes addresses and public keys locally and rates each one critical, high, low or unknown.",
      "Gives migration steps for every address type, to follow in your own wallet.",
      "Reports exposure, not attack timelines: no quantum computer that can do this is publicly known to exist.",
    ],
    requirements: [
      PYTHON,
      "Public addresses or public keys only. Kestrix never asks for private keys or seed phrases, and cannot move coins.",
      "Optional: network access for --lookup-chain (sends each looked-up address to mempool.space).",
      "Optional: the ai extra and your own Anthropic API key for the guardian.",
    ],
    install: [
      { command: "pip install kestrix" },
      { command: 'pip install "kestrix[ai]"', note: "Only for the optional guardian." },
    ],
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
    example: examples.bitcoin,
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
        fix: 'Install the extra with pip install "kestrix[ai]" and set ANTHROPIC_API_KEY or run kestrix config set-anthropic-key.',
      },
      {
        problem: "Risk unknown",
        fix: "Only a hash is visible. Without --lookup-chain the tool cannot tell whether the address has been spent from.",
      },
    ],
    docsSlug: "bitcoin",
  },
};
