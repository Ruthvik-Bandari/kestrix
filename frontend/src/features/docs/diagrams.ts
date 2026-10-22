// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { DiagramData } from "./blocks";

/*
 * The documentation's diagrams, as data. The architecture overview is the same drawing as the Mermaid
 * flowchart in README.md ("Architecture"); keep the two in step. Everything here must match the code:
 * packages/kestrix-scan (the scanner and the Claude Code plugin), src/kestrix/server (local and hosted
 * mode, isolated workers, history), src/kestrix/mail (the six analyzers) and src/kestrix/core (netguard,
 * safe parsing).
 */

const OUTSIDE = "Outside";

export const architectureDiagram: DiagramData = {
  title: "Architecture overview",
  summary:
    "Four ways in (the kestrix command, the dashboard, Claude Code with the Kestrix plugin, and CI, pre-commit or pytest) reach one shared core, either through the Kestrix server in local or hosted mode or directly. Code checks go to kestrix-scan. Dashed arrows leave Kestrix and happen only when you start them.",
  legend:
    "Solid arrows stay on your machine or on the Kestrix server. Dashed arrows reach something outside Kestrix, and only when you start the action; the Elasticsearch link stays on loopback.",
  rows: [
    [{ group: "ways", span: 12 }],
    [
      { group: null, span: 8 },
      { group: "server", span: 4 },
    ],
    [
      { group: "scanner", span: 5 },
      { group: "core", span: 7 },
    ],
    [{ group: "outside", span: 12 }],
  ],
  groups: [
    { id: "ways", title: "Ways in" },
    { id: "server", title: "Server", columns: 2 },
    { id: "scanner", title: "kestrix-scan (no dependencies)", columns: 1 },
    { id: "core", title: "One shared core", columns: 3 },
    { id: "outside", title: OUTSIDE, outside: true },
  ],
  nodes: [
    { id: "cc", group: "ways", label: "Claude Code", sublabel: "with the Kestrix plugin" },
    { id: "ci", group: "ways", label: "CI, pre-commit, pytest", sublabel: "the same scanner in your pipeline" },
    { id: "cli", group: "ways", label: "kestrix command", sublabel: "every tool, and kestrix code scan" },
    { id: "ui", group: "ways", label: "Dashboard", sublabel: "React, bundled with the server" },

    { id: "local", group: "server", label: "Local mode", sublabel: "loopback only, no accounts" },
    { id: "hosted", group: "server", label: "Hosted mode", sublabel: "sign-in, CSRF, rate limits" },
    { id: "hist", group: "server", kind: "store", label: "Recent results", sublabel: "30 days, encrypted when hosted" },
    { id: "iso", group: "server", label: "Isolated workers", sublabel: "one limited process per upload" },

    { id: "rules", group: "scanner", label: "60 rules", sublabel: "Python, JS/TS, secrets, dependencies, agent config" },
    { id: "taint", group: "scanner", label: "Source to sink traces", sublabel: "tracked within one function" },
    { id: "osv", group: "scanner", kind: "store", label: "Local OSV index", sublabel: "vulnerability data, read offline" },

    { id: "mail", group: "core", label: "Email check", sublabel: "parse, 6 analyzers, verdict" },
    { id: "forensics", group: "core", label: "File and link check", sublabel: "bytes and text only" },
    { id: "guards", group: "core", label: "Guards", sublabel: "safe parsing, netguard, size limits" },
    { id: "web", group: "core", label: "Website check", sublabel: "whole site or one page" },
    { id: "detect", group: "core", label: "Detection repair", sublabel: "diagnose, bounded repair, replay" },
    { id: "btc", group: "core", label: "Bitcoin quantum risk", sublabel: "address exposure" },

    { id: "osvnet", group: "outside", kind: "external", label: "OSV.dev", sublabel: "vulnerability data" },
    { id: "site", group: "outside", kind: "external", label: "Target website", sublabel: "one you own or may test" },
    { id: "es", group: "outside", kind: "external", label: "Pinned Elasticsearch", sublabel: "8.19.3, on loopback" },
    { id: "mempool", group: "outside", kind: "external", label: "mempool.space", sublabel: "Bitcoin chain data" },
    { id: "anthropic", group: "outside", kind: "external", label: "Anthropic API", sublabel: "optional, with your key" },
  ],
  edges: [
    { from: "ui", to: "local" },
    { from: "ui", to: "hosted" },
    { from: "local", to: "hist" },
    { from: "hosted", to: "hist" },
    { from: "hosted", to: "iso" },
    { from: "server", to: "core", label: "same functions" },
    { from: "cli", to: "core" },
    { from: "cli", to: "scanner", label: "kestrix code scan" },
    { from: "cc", to: "scanner", label: "hook on every edit" },
    { from: "ci", to: "scanner" },
    { from: "web", to: "site", dashed: true, label: "read-only GETs" },
    { from: "detect", to: "es", dashed: true, label: "loopback" },
    { from: "btc", to: "mempool", dashed: true, label: "opt-in lookup" },
    { from: "btc", to: "anthropic", dashed: true, label: "opt-in, your key" },
    { from: "osv", to: "osvnet", dashed: true, label: "db update, on request" },
  ],
};

export const emailFlowDiagram: DiagramData = {
  title: "How an email check flows",
  summary:
    "An uploaded email is parsed within size limits (in an isolated worker on the hosted service), checked by six analyzers, turned into a verdict by ordered rules that include a combination of weak signals, and written to a report that never holds the message body. The report appears in Recent results for 30 days.",
  rows: [
    [{ group: "intake", span: 12 }],
    [{ group: "analyzers", span: 12 }],
    [
      { group: "decide", span: 8 },
      { group: "kept", span: 4 },
    ],
  ],
  groups: [
    { id: "intake", title: "Intake" },
    { id: "analyzers", title: "Six analyzers, each reading the parsed message" },
    { id: "decide", title: "Decide" },
    { id: "kept", title: "Kept" },
  ],
  nodes: [
    { id: "upload", group: "intake", label: "Upload", sublabel: "a saved email, up to 10 MiB when hosted" },
    { id: "worker", group: "intake", label: "Isolated worker", sublabel: "hosted service only: a limited process, nothing stored" },
    { id: "parse", group: "intake", label: "Bounded parse", sublabel: "size, depth and header limits; nothing is opened or visited" },

    { id: "auth", group: "analyzers", label: "auth", sublabel: "SPF, DKIM, DMARC" },
    { id: "sender", group: "analyzers", label: "sender", sublabel: "From, Reply-To, Return-Path" },
    { id: "lookalike", group: "analyzers", label: "lookalike", sublabel: "domains that imitate others" },
    { id: "links", group: "analyzers", label: "links", sublabel: "never visited" },
    { id: "attachments", group: "analyzers", label: "attachments", sublabel: "never opened" },
    { id: "intent", group: "analyzers", label: "intent", sublabel: "pressure and payment cues" },

    { id: "verdict", group: "decide", label: "Verdict rules", sublabel: "malicious, suspicious, insufficient evidence or clean; 3 weak signals from 2 analyzers also make suspicious" },
    { id: "report", group: "decide", label: "Report", sublabel: "reason codes, hosts and hashes; never the message body" },

    { id: "recent", group: "kept", kind: "store", label: "Recent results", sublabel: "30 days; encrypted when hosted" },
  ],
  edges: [
    { from: "upload", to: "worker" },
    { from: "worker", to: "parse" },
    { from: "parse", to: "analyzers", label: "headers, body, links, attachments" },
    { from: "analyzers", to: "verdict", label: "findings, each with a severity" },
    { from: "verdict", to: "report" },
    { from: "report", to: "recent" },
  ],
};

export const pluginFlowDiagram: DiagramData = {
  title: "How the Claude Code plugin works",
  summary:
    "Around every file edit Claude makes, a before hook snapshots the file and an after hook scans it with kestrix-scan, so only the findings the edit introduced go back to Claude as context and Claude fixes them. A separate install guard checks package installs against the local OSV index, and a session-start notice says scanning is on.",
  rows: [
    [{ group: "edit", span: 12 }],
    [
      { group: null, span: 3 },
      { group: "feedback", span: 9 },
    ],
    [
      { group: "install", span: 8 },
      { group: "session", span: 4 },
    ],
  ],
  groups: [
    { id: "edit", title: "Every file edit" },
    { id: "feedback", title: "Feedback" },
    { id: "install", title: "Package installs (Bash)" },
    { id: "session", title: "Session start" },
  ],
  nodes: [
    { id: "claude", group: "edit", label: "Claude edits a file", sublabel: "Write, Edit, MultiEdit or NotebookEdit" },
    { id: "pre", group: "edit", label: "PreToolUse hook", sublabel: "snapshots the file; prints nothing, blocks nothing" },
    { id: "write", group: "edit", label: "The edit is written", sublabel: "the file changes on disk" },
    { id: "post", group: "edit", label: "PostToolUse hook", sublabel: "kestrix-scan scan --hook on the changed file" },

    { id: "fixes", group: "feedback", label: "Claude fixes the code", sublabel: "or suppresses a false positive, with a reason" },
    { id: "context", group: "feedback", label: "Context back to Claude", sublabel: "rule, CWE and fix for each finding" },
    { id: "fresh", group: "feedback", label: "Only the new findings", sublabel: "medium or worse, compared with the snapshot" },

    { id: "bash", group: "install", label: "Claude runs an install", sublabel: "pip, uv, npm, pnpm or yarn" },
    { id: "guard", group: "install", label: "Install guard", sublabel: "PreToolUse on Bash; checks the local OSV index" },
    { id: "outcome", group: "install", label: "Warn or deny", sublabel: "deny a known malicious package; warn on a vulnerable pin" },

    { id: "notice", group: "session", label: "Notice", sublabel: "tells Claude and you, once, that scanning is on" },
  ],
  edges: [
    { from: "claude", to: "pre" },
    { from: "pre", to: "write" },
    { from: "write", to: "post" },
    { from: "post", to: "fresh", label: "scan the changed file" },
    { from: "fresh", to: "context" },
    { from: "context", to: "fixes" },
    { from: "fixes", to: "claude", label: "the next edit repeats the loop" },
    { from: "bash", to: "guard" },
    { from: "guard", to: "outcome" },
  ],
};
