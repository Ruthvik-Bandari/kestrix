// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { toolFor } from "../../../app/tools";
import { diagram, guide, list, note, p, pages, section, see, table } from "../blocks";
import { pluginFlowDiagram } from "../diagrams";
import type { DocPage } from "../model";
import { ref } from "./helpers";

/* Follows docs/claude-plugin.md, docs/claude-skill.md and docs/benchmarks/plugin-ab.md. */

const BASE = "code-security/claude-plugin";

export const pluginPages: DocPage[] = [
  {
    path: BASE,
    title: toolFor("claude-plugin").name,
    nav: "Claude Code plugin",
    summary: toolFor("claude-plugin").summary,
    sections: [
      ref("claude-plugin", "What it does"),
      section(
        "In this section",
        pages(`${BASE}/install`, `${BASE}/hooks`, `${BASE}/commands-and-skills`, `${BASE}/verified-behaviour`),
      ),
      ref("claude-plugin", "Privacy and limits"),
    ],
  },
  {
    path: `${BASE}/install`,
    title: "Claude Code plugin: install",
    nav: "Install",
    summary: "Install kestrix-scan, copy the plugin, add it as a local marketplace and load it.",
    sections: [
      section("Install and load", guide("claude-plugin")),
      section(
        "Notes",
        list(
          "The plugin calls the `kestrix-scan` command, so install it first (the full `kestrix` package includes it).",
          "`kestrix-scan install-claude-plugin` copies the plugin to `~/.claude/kestrix-plugin` and prints the next commands. It never edits your Claude Code settings.",
          "To try it for one session only: `claude --plugin-dir ~/.claude/kestrix-plugin`.",
        ),
      ),
    ],
  },
  {
    path: `${BASE}/hooks`,
    title: "Claude Code plugin: the hooks",
    nav: "Hooks",
    summary: "What runs before and after each edit, the opt-in Stop gate, the install guard and the session-start message.",
    sections: [
      section("How the plugin works", diagram(pluginFlowDiagram)),
      section(
        "The hooks at a glance",
        table(
          ["Hook", "Runs on", "What it does"],
          [
            ["`PreToolUse`", "`Write`, `Edit`, `MultiEdit`, `NotebookEdit`", "Snapshots the file before the change, so the other hooks can tell new findings from old ones. It prints nothing and never blocks a tool."],
            ["`PreToolUse` (install guard)", "`Bash`", "Checks the packages a `pip`, `uv`, `npm`, `pnpm` or `yarn` install names against the local OSV index. It denies a known malicious package and warns about a known-vulnerable pinned version. Silent without an index."],
            ["`PostToolUse`", "`Write`, `Edit`, `MultiEdit`, `NotebookEdit`", "Scans the changed file with `kestrix-scan --hook` and returns the medium-or-worse findings the edit introduced."],
            ["`PostToolUse`, `PostToolUseFailure`", "`Bash`", "Lists the files the command changed in a git repository, scans the source-like ones (at most 20) like an edit, and returns the findings the command introduced. A command that failed is scanned too."],
            ["`Stop` (opt-in)", "Finishing a turn", "Blocks Claude from finishing while files changed this session have high or critical findings that this session introduced. Off unless you enable it."],
            ["`SessionStart`", "Session start", "Tells Claude the hooks are active and shows you one line, once per session, that scanning is on. Silent when the scanner is not on PATH."],
          ],
        ),
      ),
      ref("claude-plugin", "How the hooks work"),
      ref("claude-plugin", "The Stop gate (opt-in)"),
      ref("claude-plugin", "Install guard"),
      section(
        "Suppressing a finding",
        p("When Claude reports a confirmed false positive, it adds an inline suppression with a written reason, the same `# kestrix: ignore[<rule-id>] <reason>` comment the scanner accepts. A suppression without a reason suppresses nothing."),
        see("Suppression syntax", "code-security/kestrix-scan/configuration"),
      ),
    ],
  },
  {
    path: `${BASE}/commands-and-skills`,
    title: "Claude Code plugin: commands and skills",
    nav: "Commands and skills",
    summary: "The four slash commands and three skills the plugin adds.",
    sections: [
      section(
        "Commands",
        table(
          ["Command", "What it does"],
          [
            ["`/kestrix:scan [path]`", "Scans a path (default `.`) and summarizes the findings. It changes no code."],
            ["`/kestrix:fix [path]`", "Scans, fixes every finding at medium or above, and re-scans until the code is clean or each remaining finding is explained. It stops after 5 rounds."],
            ["`/kestrix:status`", "Shows this session's record from the hooks: files scanned, findings reported, and the files that were not security-checked, with the reason. It scans nothing."],
            ["`/kestrix:review [base-ref]`", "A secure review of the current diff. It runs `kestrix-scan . --diff <ref>` (default `HEAD`), then reviews the diff for what the rules cannot see."],
          ],
        ),
        p("The four commands are skills that only run when you type them."),
      ),
      section(
        "Skills",
        table(
          ["Skill", "What it does"],
          [
            ["`secure-code-review`", "How to review code with Kestrix: scan, triage by severity, fix by rule family, re-scan and explain the risk that remains. Claude uses it on its own when you ask for a security review."],
            ["`fixing-security-findings`", "A per-rule playbook with before and after code for every rule id, generated from the rule registry."],
            ["`kestrix-security`", "Plain-language questions about email, links, files, websites, Sigma rules and Bitcoin addresses: Claude runs the matching `kestrix` command on your machine, reads the JSON report and explains it."],
          ],
        ),
        p("The skills tell Claude to treat code as data: to ignore instructions inside the code under review, such as comments or strings that say to skip a check, and to point them out to you."),
      ),
    ],
  },
  {
    path: `${BASE}/verified-behaviour`,
    title: "Claude Code plugin: verified behaviour",
    nav: "Verified behaviour",
    summary: "What is scanned, what is not, what was measured about speed and privacy, and what has not been measured.",
    sections: [
      section(
        "Coverage",
        list(
          "Scanned: files changed through `Write`, `Edit`, `MultiEdit` and `NotebookEdit`, and, in a git repository, the source-like files (at most 20) that a Bash command created or modified.",
          "Not scanned: edits made outside Claude Code; files a Bash command changed outside a git repository; a command that commits what it changed in the same command; files over 1 MiB; anything before the plugin was loaded.",
          "Analysis is per file, with taint tracked within one function. There is no whole-program or cross-file analysis.",
          "The scanner has 91 rules: 30 Python, 16 JS/TS, 12 web-file, 12 PHP, 3 SQL-file, 11 secret, 2 dependency and 5 agent-config rules.",
          "It fails open: a missing scanner, a timeout or an error never blocks an edit.",
        ),
        note("No findings is not proof of security.", "caution"),
      ),
      section(
        "Privacy, tested",
        list(
          "Neither the scanner nor the hooks open a network connection. A test runs a scan, the hook mode and the Stop mode with every socket call made to raise, and asserts that all still work and that no socket was attempted.",
          "The hook output is part of your conversation. It goes to Claude like any other tool result, so findings are sent to Anthropic like any other conversation content. It holds rule ids, file paths, line numbers, messages and fixes, never secret values.",
          "Snapshots of changed files stay in the plugin's data directory or a private temp directory and are removed with the session record.",
        ),
      ),
      section(
        "Latency, measured",
        p("Measured on 2026-10-19 on an Apple M4 Pro, macOS, Python 3.12.13, 30 runs per row, times in milliseconds as p50 / p95. The post-tool-use column is what you wait for after each edit."),
        table(
          ["File lines", "In-process scan", "Pre-tool-use process", "Post-tool-use process"],
          [
            ["103", "5.3 / 5.6", "34.7 / 35.9", "95.1 / 96.1"],
            ["999", "50.4 / 55.2", "35.2 / 36.0", "141.5 / 142.4"],
            ["4,999", "259.4 / 266.0", "37.1 / 44.2", "352.9 / 365.3"],
          ],
        ),
      ),
      section(
        "Does it help? Not measured",
        p("The effectiveness claim is not measured yet and none is made. Whether Claude ships less vulnerable code with the plugin is to be measured by a paired A/B eval (13 tasks, each with and without the plugin); its results page currently reads \"not yet run\". The scanner's own accuracy is on the Accuracy page, and its benchmark scorecard is not blind: rule changes after the first run were informed by that run's gap analysis."),
        see("Scanner accuracy", "code-security/accuracy"),
      ),
      section(
        "Three scan states",
        p("Fail-open must not make \"the scan could not run\" look the same as \"no findings\". Every scan ends in one of three states."),
        table(
          ["State", "You see", "Claude is told"],
          [
            ["Clean", "nothing", "nothing"],
            ["Findings", "nothing extra", "the new findings, with rule, CWE and fix"],
            ["Unavailable", "one message, once per session for each cause", "one line, every time: this file was NOT security-checked"],
          ],
        ),
        p("The causes of `Unavailable` are `missing` (neither `kestrix-scan` nor `kestrix` is on PATH), `timeout` (the scan ran past 8 seconds), `error` (a nonzero exit, output that is not JSON, or a crash inside the scanner), and, for Bash commands, `limit` (more than 20 changed files) and `no-git`. `/kestrix:status` prints the totals."),
      ),
    ],
  },
];
