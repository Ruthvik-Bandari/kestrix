// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { pageAvailable } from "../../app/paths";
import { toolFor, type ToolPage } from "../../app/tools";
import { isHosted } from "../../lib/mode";

/*
 * Landing copy. Every claim here must match docs/modules/*.md, docs/security-model.md and
 * docs/hosted.md: no accuracy rates, customers, certifications, live feeds or guarantees. The
 * only numbers on the page come from the bundled synthetic email sample (samples/email.json).
 */

export interface LandingTool {
  page: ToolPage;
  name: string;
  line: string;
}

/** Tools for the question in front of you. */
export const everydayTools: LandingTool[] = [
  { page: "mail", name: "Email", line: "Check a saved email for phishing, impersonation and fake invoices." },
  { page: "webcheck", name: "Website", line: "Grade HTTPS, the certificate, security headers and cookies, with a fix for each problem." },
  { page: "forensics", name: "File & link", line: "See what a file really is and whether a link shows phishing signs, without opening either." },
];

/** Specialist tools: some run only on your own computer, some are setup guides. */
export const deeperTools: LandingTool[] = [
  { page: "detect", name: "Detection repair", line: "Find why a Sigma rule misses attacks and test the smallest fix on labeled events." },
  { page: "code", name: "Code & Claude", line: "Scan code for security mistakes, and have Claude Code check what it writes." },
  { page: "bitcoin", name: "Bitcoin", line: "See which addresses show a public key a future quantum computer could target." },
];

export type Availability = "In your browser" | "In the workbench" | "Run locally" | "Setup guide";

/** Where a tool can be used in this mode: guides in both modes, live tools only where the server serves them. */
export function availability(page: ToolPage): Availability {
  if (!toolFor(page).live) return "Setup guide";
  if (!pageAvailable(page)) return "Run locally";
  return isHosted() ? "In your browser" : "In the workbench";
}

export const steps = [
  {
    label: "Input",
    title: "Bring one thing to check",
    text: "A saved email, a website, a file or a link. Pick the tool, add the input and run the check.",
  },
  {
    label: "Evidence",
    title: "Read what was found",
    text: "Every finding has a severity, a plain-language reason and the evidence behind it.",
  },
  {
    label: "Decision",
    title: "Decide what comes next",
    text: "You get a verdict and its limits. Scores are heuristics, not probabilities, and a clean result means no checks fired.",
  },
];

export const trust = {
  local: [
    "Email, file and link checks run on the Kestrix server on your own computer. It only answers requests from that computer, and there are no accounts.",
    "A website check connects to the site you enter. The optional Bitcoin chain lookup and the optional AI review are separate network actions you turn on.",
    "Reports are kept for 30 days by default, and you can turn history off.",
  ],
  hosted: [
    "Email, website, file and link checks are processed on the server. A website check connects from the server to the public site you enter.",
    "Raw uploads are not stored. Reports are kept 30 days by default, encrypted, and removed when you turn history off or delete your account.",
    "Detection repair and Bitcoin run on your own computer only.",
  ],
  limits: "Results are heuristics, not probabilities. A clean result means none of the checks fired, not that something is safe.",
};
