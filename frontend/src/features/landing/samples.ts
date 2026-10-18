// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { Severity } from "../../lib/types";
import bitcoinJson from "./samples/bitcoin.json";
import detectJson from "./samples/detect.json";
import emailJson from "./samples/email.json";
import fileJson from "./samples/file.json";
import urlJson from "./samples/url.json";
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

export interface ExplainedFinding {
  id: string;
  severity: Severity;
  title: string;
  explanation: string;
}

export interface FileSample {
  provenance: string;
  filename: string;
  size: number;
  first_bytes_hex: string;
  first_bytes_ascii: string;
  sha256: string;
  file_type: {
    id: string;
    label: string;
    executable: boolean;
    extension: string | null;
    expected_extensions: string[];
    extension_mismatch: boolean;
  };
  entropy: {
    overall: number;
    block_size: number;
    block_count: number;
    high_entropy_threshold: number;
    high_entropy_bytes: number;
    high_entropy_region_count: number;
    points: number[];
  };
  printable_ratio: number;
  findings: ExplainedFinding[];
}

export interface UrlSample {
  provenance: string;
  url: string;
  host: string;
  registrable_domain: string | null;
  score: number;
  level: string;
  score_note: string;
  findings: ExplainedFinding[];
}

export interface DetectCounts {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}

export interface DetectSample {
  provenance: string;
  case_id: string;
  case_title: string;
  rule_title: string;
  engine_version: string;
  outcome: string;
  fault: string;
  coverage: { sigma_field: string; index_field: string; mapped: boolean; present: number; total: number }[];
  hypotheses: { family: string; reason_codes: string[]; fields: string[]; alternative_index_fields: string[] }[];
  patch: { kind: string; sigma_field: string; from_field: string; to_field: string }[];
  diff: string;
  events: { event_id: string; label: string; executable: string; command_line: string | null }[];
  healthy: { query: string; counts: DetectCounts; matched: string[] };
  before: { query: string; counts: DetectCounts; matched: string[] };
  after: { query: string; counts: DetectCounts; matched: string[] };
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

export interface BitcoinSample {
  provenance: string;
  history_note: string;
  cards: {
    label: string;
    synthetic_history: { chain: string; funded_outputs: number; spent_outputs: number; balance_sats: number } | null;
    assessment: {
      input: string;
      address_type: string;
      network: string | null;
      risk: "critical" | "high" | "low" | "unknown";
      key_exposure: string;
      explanation: string;
      recommendation: string;
    };
  }[];
  plans: Record<string, { summary: string; urgency: string; steps: string[] }>;
}

export const emailSample = emailJson as EmailSample;
export const fileSample = fileJson as FileSample;
export const urlSample = urlJson as UrlSample;
export const detectSample = detectJson as DetectSample;
export const webcheckSample = webcheckJson as WebcheckSample;
export const bitcoinSample = bitcoinJson as BitcoinSample;
