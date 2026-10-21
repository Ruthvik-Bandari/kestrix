// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Counts, DetectReport, ReplayResult } from "../../lib/types";
import { ReportView } from "./ReportView";

function replay(counts: Counts | null, error: string | null = null): ReplayResult {
  return {
    rule_sha256: "",
    mapping_sha256: "",
    dataset_sha256: "",
    query: null,
    error,
    counts,
    scenarios_expected: ["S-1"],
    scenarios_detected: [],
    matched_event_ids: [],
  };
}

const COUNTS: Counts = { tp: 3, fp: 4, fn: 1, tn: 7, unknown_matched: 0 };

function report(extra: Partial<DetectReport>): DetectReport {
  return { schema_version: 1, outcome: "abstained", reason: "no safe candidate", manifest: {}, ...extra };
}

describe("detection report", () => {
  it("shows a failed replay's counts as not available, never as 0", () => {
    render(
      <ReportView
        report={report({
          original: { development: replay(null, "elasticsearch returned 500"), validation: replay(COUNTS) },
        })}
      />,
    );
    const table = screen.getByRole("table", { name: /Development events/ });
    // Four measures, each "not available": the failed replay has no counts to show.
    expect(within(table).getAllByText("not available")).toHaveLength(4);
    expect(within(table).queryByText("0")).toBeNull();
    expect(screen.getByText(/Replay error before the change: elasticsearch returned 500/)).toBeTruthy();
    // The other split still shows real numbers.
    const validation = screen.getByRole("table", { name: /Validation events \(held out\)/ });
    expect(within(validation).getByText("3")).toBeTruthy();
  });

  it("marks a change as not available when either side has no counts", () => {
    render(
      <ReportView
        report={report({
          outcome: "repaired",
          selected: "p1",
          original: { development: replay(COUNTS) },
          candidates: [
            {
              candidate: {
                schema_version: 1,
                proposal_id: "p1",
                original_sha256: "",
                patch_kind: "rule",
                patch: [],
                reason_codes: ["noise_exclusion"],
                evidence_event_ids: [],
                assumptions: [],
                model_revision: "deterministic-b0",
                prompt_sha256: null,
              },
              development: replay(null, "timeout"),
              passed: true,
              policy_failures: [],
            },
          ],
        })}
      />,
    );
    const table = screen.getByRole("table", { name: /Development events/ });
    // After and Change are both unavailable for all four measures.
    expect(within(table).getAllByText("not available")).toHaveLength(8);
  });

  it("lists reason codes with where they came from", () => {
    render(
      <ReportView
        report={report({
          hypotheses: [
            {
              family: "mapping",
              fields: ["CommandLine"],
              alternative_index_fields: [],
              evidence_event_ids: [],
              reason_codes: ["field_renamed"],
            },
          ],
        })}
      />,
    );
    const section = screen.getByRole("heading", { name: "Reason codes" }).closest("section") as HTMLElement;
    expect(within(section).getByText("field_renamed")).toBeTruthy();
    expect(within(section).getByText(/Diagnosis: field mapping drift/)).toBeTruthy();
  });
});
