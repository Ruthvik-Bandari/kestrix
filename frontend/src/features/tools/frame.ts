// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { docsPath } from "../../app/paths";
import type { ToolPage } from "../../app/tools";
import type { IconName } from "../../components/Icon";
import { formatBytes } from "../../lib/format";
import { maxMessageBytes, maxUploadBytes } from "../../lib/limits";
import { isHosted } from "../../lib/mode";
import type { HistoryTool } from "../../lib/types";
import { HOSTED_DOC_PATH } from "../docs/model";

/*
 * What every tool page says about itself around the live controls, written once: the capability
 * chips in its header, the wording of the three-step rail, and the outline of the report it will
 * produce. Everything here restates behaviour the page and the server already have (limits come
 * from lib/limits.ts, the rest from the docs in docs/modules/*.md); nothing is a measurement.
 */

/** A tool page, or one of a page's tabs that has its own wording. */
export type FrameKey = ToolPage | "forensics-url";

export interface Chip {
  icon: IconName;
  text: string;
  /** An in-app destination, such as the hosted-service docs. */
  to?: string;
}

export interface OutlineSection {
  icon: IconName;
  title: string;
  detail: string;
}

/** Where the work happens, as a chip. Hosted checks run on Kestrix's server; local ones stay on this computer. */
function where(): Chip {
  return isHosted()
    ? { icon: "globe", text: "Runs on Kestrix's server", to: docsPath(HOSTED_DOC_PATH) }
    : { icon: "monitor", text: "Runs on this computer" };
}

const NOT_HOSTED: Chip = { icon: "info", text: "Not on the hosted service" };

/**
 * The honest capability chips for a tool in the current mode. `guide` is true when the page is a setup
 * guide (always for the code scanner and Claude plugin; for detection repair and Bitcoin on the hosted service).
 */
export function chipsFor(key: FrameKey, guide = false): Chip[] {
  if (guide && (key === "detect" || key === "bitcoin")) {
    return [
      { icon: "terminal", text: "Run locally" },
      key === "detect"
        ? { icon: "gauge", text: "Replays on Elasticsearch 8.19.3" }
        : { icon: "key", text: "Read-only: never needs a private key" },
      ...(isHosted() ? [NOT_HOSTED] : []),
    ];
  }
  if (guide && key !== "code" && key !== "claude-plugin") return [{ icon: "terminal", text: "Run locally" }];
  switch (key) {
    case "mail":
      return [
        where(),
        { icon: "upload", text: `.eml up to ${formatBytes(maxMessageBytes())}` },
        { icon: "shieldCheck", text: "Never opens links" },
        { icon: "shieldCheck", text: "Never runs attachments" },
      ];
    case "webcheck":
      return [
        { ...where(), text: isHosted() ? "Requests come from Kestrix's server" : "Requests come from this computer" },
        { icon: "search", text: "Read-only GETs, up to 50 pages" },
        { icon: "shieldCheck", text: "Never logs in or submits forms" },
        ...(isHosted() ? [{ icon: "globe" as const, text: "Public addresses only" }] : []),
      ];
    case "forensics":
      return [
        where(),
        { icon: "upload", text: `Any file, up to ${formatBytes(maxUploadBytes())}` },
        { icon: "shieldCheck", text: "Never runs the file" },
      ];
    case "forensics-url":
      return [
        where(),
        { icon: "fileText", text: "Analyzed as text" },
        { icon: "shieldCheck", text: "Never opens or fetches the link" },
      ];
    case "detect":
      return [
        { icon: "monitor", text: "Runs on this computer" },
        { icon: "gauge", text: "Replays on Elasticsearch 8.19.3" },
        { icon: "shieldCheck", text: "Never applies a patch for you" },
      ];
    case "bitcoin":
      return [
        { icon: "monitor", text: "Runs on this computer" },
        { icon: "key", text: "Read-only: never needs a private key" },
        { icon: "globe", text: "Offline unless you turn on lookup" },
      ];
    case "code":
      return [
        { icon: "terminal", text: "Run locally" },
        { icon: "package", text: "Offline except db update" },
        { icon: "scanSearch", text: "Python, JavaScript, TypeScript" },
      ];
    case "claude-plugin":
      return [
        { icon: "terminal", text: "Run locally" },
        { icon: "scanSearch", text: "Scans every edit on your computer" },
        { icon: "alert", text: "Reports medium severity and above" },
      ];
  }
}

/** What each of the three steps says about this tool, before and after a run. */
export interface RailCopy {
  /** Step 1 before anything is entered. */
  input: string;
  /** Step 2 before a result. */
  evidence: string;
  /** Step 3 before a result. */
  decide: string;
}

export const railCopy: Record<FrameKey, RailCopy> = {
  mail: { input: "Choose an .eml file", evidence: "Verdict, findings and evidence", decide: "A suggested next step" },
  webcheck: { input: "Enter an address and confirm", evidence: "Grade, failed checks and evidence", decide: "A fix for each problem" },
  forensics: { input: "Choose a file", evidence: "Real type, fingerprints, entropy", decide: "Findings to review" },
  "forensics-url": { input: "Paste a link", evidence: "Domain parts and signals", decide: "Trust it or type the address yourself" },
  detect: { input: "Pick a sample case or paste a rule", evidence: "Diagnosis, diff and replay counts", decide: "Review the patch, then apply it yourself" },
  bitcoin: { input: "Paste public addresses", evidence: "Key exposure per address", decide: "Follow a migration plan" },
  code: { input: "", evidence: "", decide: "" },
  "claude-plugin": { input: "", evidence: "", decide: "" },
};

/** The report's sections in the order they appear: headings and one line each, never sample values. */
export const outlines: Record<Exclude<FrameKey, "code" | "claude-plugin">, OutlineSection[]> = {
  mail: [
    { icon: "octagon", title: "Verdict", detail: "A plain-language verdict with the finding tally and a heuristic score." },
    { icon: "arrowRight", title: "Suggested next step", detail: "General advice for that verdict. Nothing is done for you." },
    { icon: "listChecks", title: "What Kestrix found", detail: "Findings most severe first, each with evidence and a reason code." },
    { icon: "mail", title: "Message", detail: "Subject, sender, SHA-256 and how many parts, links and attachments." },
    { icon: "info", title: "What this check can tell you", detail: "The limits of the check, in the report's own words." },
  ],
  webcheck: [
    { icon: "gauge", title: "Grade", detail: "A to F with the score and how it was worked out." },
    { icon: "listChecks", title: "Findings", detail: "Failed checks first, each with evidence seen and how to fix it." },
    { icon: "lock", title: "Certificate and TLS", detail: "Validity, protocol, issuer and expiry." },
    { icon: "route", title: "Redirect chain", detail: "Every hop the request followed." },
    { icon: "fileSearch", title: "Site profile", detail: "Forms, cookies, scripts and what they say about the site." },
    { icon: "globe", title: "Pages checked", detail: "Whole-site scans only: each page requested and what came back." },
  ],
  forensics: [
    { icon: "octagon", title: "Verdict", detail: "Whether the content matches the name, and what needs a look." },
    { icon: "listChecks", title: "Findings", detail: "Most severe first, each with a reason code." },
    { icon: "file", title: "File type", detail: "Detected from the bytes, not the extension." },
    { icon: "fingerprint", title: "Fingerprints", detail: "SHA-256, SHA-1, MD5 and SHA-512 you can copy." },
    { icon: "chart", title: "Entropy and byte values", detail: "How random the bytes look, with random-looking regions marked." },
    { icon: "pin", title: "Image metadata", detail: "EXIF tags, including any embedded location." },
  ],
  "forensics-url": [
    { icon: "octagon", title: "Verdict", detail: "A heuristic level and score, not a probability." },
    { icon: "link", title: "How the link breaks down", detail: "Scheme, subdomain, registered domain and host." },
    { icon: "listChecks", title: "Signals that fired", detail: "Each one with its explanation and reason code." },
  ],
  detect: [
    { icon: "octagon", title: "Outcome", detail: "Repaired, unchanged, abstained, unsupported, insufficient evidence or engine unavailable." },
    { icon: "search", title: "Diagnosis", detail: "Why the rule misses attacks or raises false alarms." },
    { icon: "wrench", title: "Patch", detail: "A diff of the smallest fix. It is never applied for you." },
    { icon: "chart", title: "Replay counts", detail: "Caught, missed and false alarms on development and held-out events." },
  ],
  bitcoin: [
    { icon: "octagon", title: "Scan results", detail: "How many addresses are exposed, hidden or unknown." },
    { icon: "listChecks", title: "Addresses", detail: "Type, network, key exposure, risk and what to do." },
    { icon: "route", title: "Migration plan", detail: "Steps for moving coins to an address that hides its key." },
  ],
};

/** The history tools a page's saved reports come from, for the stats strip. */
export const historyToolsFor: Partial<Record<FrameKey, HistoryTool[]>> = {
  mail: ["mail"],
  webcheck: ["webcheck"],
  forensics: ["forensics_file"],
  "forensics-url": ["forensics_url"],
};
