// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ComponentType } from "react";
import { BitcoinScene } from "./scenes/BitcoinScene";
import { DetectScene } from "./scenes/DetectScene";
import { EmailScene } from "./scenes/EmailScene";
import { FileScene } from "./scenes/FileScene";
import { UrlScene } from "./scenes/UrlScene";
import { WebScene } from "./scenes/WebScene";
import { bitcoinSample, detectSample, emailSample, fileSample, urlSample, webcheckSample } from "./samples";

/*
 * Landing copy. Every claim here must match docs/modules/*.md and docs/security-model.md:
 * no accuracy rates, certifications or behavior the code does not have.
 */

/*
 * Every "with Kestrix" value comes from samples/*.json (real output on synthetic
 * inputs). The "without" side is a scenario, phrased as one: no time savings, percentages, user
 * counts or accuracy figures anywhere on the page.
 */

export interface Chapter {
  id: string;
  nav: string;
  number: string;
  kicker: string;
  title: string;
  lede: string;
  /** The dashboard page this chapter's tool lives on (app/paths.ts decides where it is served). */
  page: string;
  sample: { name: string; data: { provenance: string } };
  Scene: ComponentType;
}

export const chapters: Chapter[] = [
  {
    id: "invoice",
    nav: "Email",
    number: "01",
    kicker: "Email check",
    title: "The invoice that wasn’t",
    lede: "A bank-detail change from a supplier you know, with the invoice attached. Read it the way you normally would, then drag the beam across it.",
    page: "mail",
    sample: { name: "email", data: emailSample },
    Scene: EmailScene,
  },
  {
    id: "quiet-rule",
    nav: "Detection",
    number: "02",
    kicker: "Detection repair",
    title: "The rule that went quiet",
    lede: "A detection rule stops matching after a log pipeline renames one field. No error, no alert, nothing to notice. Same events, replayed on the real engine.",
    page: "detect",
    sample: { name: "detect", data: detectSample },
    Scene: DetectScene,
  },
  {
    id: "not-a-pdf",
    nav: "File",
    number: "03",
    kicker: "Forensics · file",
    title: "Not a PDF",
    lede: "The icon says PDF. The name says PDF. The first two bytes say something else.",
    page: "forensics",
    sample: { name: "file", data: fileSample },
    Scene: FileScene,
  },
  {
    id: "lying-link",
    nav: "Link",
    number: "04",
    kicker: "Forensics · link",
    title: "The link that lies",
    lede: "One character decides where this link really goes. Most people never look past the first name they recognise.",
    page: "forensics",
    sample: { name: "url", data: urlSample },
    Scene: UrlScene,
  },
  {
    id: "attacker-view",
    nav: "Website",
    number: "05",
    kicker: "Web check",
    title: "Your site, as an attacker sees it",
    lede: "A sign-in page that works fine for visitors. The protections that matter live in headers nobody sees.",
    page: "webcheck",
    sample: { name: "webcheck", data: webcheckSample },
    Scene: WebScene,
  },
  {
    id: "exposed-key",
    nav: "Bitcoin",
    number: "06",
    kicker: "Bitcoin quantum risk",
    title: "Coins with an exposed key",
    lede: "Some address types publish their public key, the part a future quantum computer would need. The list in your wallet doesn’t tell you which.",
    page: "bitcoin",
    sample: { name: "bitcoin", data: bitcoinSample },
    Scene: BitcoinScene,
  },
];
