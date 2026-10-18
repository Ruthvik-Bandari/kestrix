// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { dashboardPath } from "../../app/paths";
import type { IconName } from "../../components/Icon";
import type { Tone } from "../../components/tone";

/*
 * Landing copy. Every claim here must match docs/modules/*.md and docs/security-model.md:
 * no accuracy rates, certifications or behavior the code does not have.
 */

export interface Feature {
  name: string;
  path: string;
  icon: IconName;
  protects: string;
}

export const features: Feature[] = [
  {
    name: "Email check",
    path: dashboardPath("mail"),
    icon: "mail",
    protects:
      "Phishing, impersonation and fake-invoice emails. Drop in a saved message and see exactly what is wrong with it, and why.",
  },
  {
    name: "Web check",
    path: dashboardPath("webcheck"),
    icon: "globe",
    protects:
      "Missing HTTPS protections, an expiring certificate and unsafe browser security headers on a website you run.",
  },
  {
    name: "Forensics",
    path: dashboardPath("forensics"),
    icon: "search",
    protects:
      "Files that are not what their name claims, hidden encrypted payloads, photos that reveal where they were taken, and look-alike links.",
  },
  {
    name: "Detection repair",
    path: dashboardPath("detect"),
    icon: "wrench",
    protects:
      "Detection rules that silently stop catching attacks or bury your team in false alarms. Get a fix that was replayed on labeled events.",
  },
  {
    name: "Bitcoin quantum risk",
    path: dashboardPath("bitcoin"),
    icon: "bitcoin",
    protects:
      "Coins whose public key is already visible on the blockchain, the first target for a future quantum computer, with a plan to move them.",
  },
];

export interface Flow {
  name: string;
  icon: IconName;
  input: { title: string; text: string; token: string };
  checks: string[];
  verdict: { tone: Tone; label: string; lines: string[] };
  note: { icon: IconName; text: string };
}

export const flows: Flow[] = [
  {
    name: "Email check",
    icon: "mail",
    input: { title: "Drop a saved email", text: "An .eml file, plus the domains you care about if you like.", token: ".eml" },
    checks: [
      "Sender authentication (SPF, DKIM, DMARC)",
      "Display-name impersonation",
      "Look-alike domains",
      "Links, read as text",
      "Attachments, hashed not opened",
      "Scam wording",
    ],
    verdict: {
      tone: "crit",
      label: "Malicious",
      lines: ["From domain is a look-alike of a protected domain", "Asks to change bank details, urgently"],
    },
    note: { icon: "lock", text: "Runs offline. Links are never visited and attachments never opened." },
  },
  {
    name: "Web check",
    icon: "globe",
    input: { title: "Enter a website", text: "One you own or are authorized to assess.", token: "https://" },
    checks: ["HTTPS and redirects", "TLS certificate and expiry", "Security headers", "Cookie flags", "Site profile"],
    verdict: { tone: "med", label: "Grade B", lines: ["No Content-Security-Policy", "Fix: add a policy that limits scripts"] },
    note: { icon: "globe", text: "Sends one GET request (up to 5 redirects) and one TLS handshake. No crawling." },
  },
  {
    name: "Forensics",
    icon: "search",
    input: { title: "Choose a file or a link", text: "Files up to 50 MB; links are checked as text.", token: "file" },
    checks: ["MD5, SHA-1, SHA-256, SHA-512", "Real type from the first bytes", "Entropy: packed or encrypted data", "Photo metadata and GPS", "Link phishing signs"],
    verdict: { tone: "crit", label: "High", lines: ["Name disguises a .exe file as .pdf", "Program may be packed"] },
    note: { icon: "lock", text: "Offline. The file is never executed and the link is never fetched." },
  },
  {
    name: "Detection repair",
    icon: "wrench",
    input: { title: "Bring a Sigma rule", text: "With a field mapping and labeled events, or try a sample case.", token: ".yml" },
    checks: ["Field coverage in your events", "Replay on pinned Elasticsearch 8.19.3", "Diagnose: mapping, noise, logic, telemetry", "Up to 4 fixes of at most 3 edits", "Check on held-out events"],
    verdict: { tone: "ok", label: "Repaired", lines: ["CommandLine was renamed in your pipeline", "Diff and replay counts attached"] },
    note: { icon: "info", text: "Abstains instead of guessing when the evidence is unclear." },
  },
  {
    name: "Bitcoin quantum risk",
    icon: "bitcoin",
    input: { title: "Paste public addresses", text: "Up to 100. Never private keys or seed phrases.", token: "bc1…" },
    checks: ["Decode locally, verify checksums", "Is the public key on chain?", "Optional mempool.space lookup, off by default"],
    verdict: { tone: "high", label: "High risk", lines: ["Taproot output key is visible", "Migration plan for your wallet"] },
    note: { icon: "key", text: "Read-only: it cannot sign, send or move coins." },
  },
];

export interface Principle {
  icon: IconName;
  title: string;
  text: string;
}

export const principles: Principle[] = [
  {
    icon: "monitor",
    title: "Runs on your computer",
    text: "The dashboard and its API listen on 127.0.0.1 by default and refuse actions sent from other websites. There are no accounts in local mode.",
  },
  {
    icon: "lock",
    title: "Nothing uploaded in local mode",
    text: "Files and messages go only to the Kestrix server on this machine. Only the website check, the optional chain lookup and the optional AI guardian reach the network, and each says so first.",
  },
  {
    icon: "mail",
    title: "Links are never visited",
    text: "The email check reads links as text. It never renders the message, runs scripts or opens attachments.",
  },
  {
    icon: "info",
    title: "Every finding explains itself",
    text: "Each result carries a reason code, a plain explanation and its evidence. Heuristic scores are labeled as heuristics, never as probabilities.",
  },
  {
    icon: "shield",
    title: "Honest outcomes",
    text: "When evidence is thin it says so: abstained, unsupported or insufficient evidence, never a forced answer.",
  },
  {
    icon: "file",
    title: "Evidence is hashed",
    text: "Messages, files, rules and datasets are identified by SHA-256, and detection evidence is written as content-addressed files.",
  },
  {
    icon: "globe",
    title: "Open source, Apache-2.0",
    text: "Read every check yourself. The code and the docs that describe its behavior are in the repository.",
  },
  {
    icon: "key",
    title: "Signed history",
    text: "Commits and tags are signed with the author's key, so you can see who made each change and in what order.",
  },
];
