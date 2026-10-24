// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { Severity } from "../../lib/types";
import emailJson from "./samples/email.json";
import webcheckJson from "./samples/webcheck.json";

/*
 * Real Kestrix output on synthetic inputs, written by scripts/build_landing_samples.py and
 * checked against the code by tests/test_landing_samples.py. The landing page shows these
 * values as they are: never edit the JSON by hand, regenerate it.
 */

export interface EmailFinding {
  id: string;
  analyzer: string;
  severity: Severity;
  title: string;
  evidence: string | null;
}

export interface EmailSample {
  provenance: string;
  message: {
    from_name: string;
    from_address: string;
    reply_to: string;
    to: string;
    subject: string;
    date: string;
    paragraphs: string[];
    link_text: string;
    link_href: string;
    attachment: string;
  };
  protected_domains: string[];
  report: { verdict: string; heuristic_score: number; notice: string; findings: EmailFinding[] };
}

export interface WebcheckSample {
  provenance: string;
  site_title: string;
  status_code: number;
  response_headers: Record<string, string>;
  grade: string;
  score: number;
  findings: { id: string; severity: Severity; title: string; recommendation: string; evidence: string | null }[];
}

export const emailSample = emailJson as EmailSample;
export const webcheckSample = webcheckJson as WebcheckSample;
