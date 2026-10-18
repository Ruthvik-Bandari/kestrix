import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { DetectReport, Outcome } from "../../lib/types";
import { OutcomeBanner } from "./OutcomeBanner";
import { describePatch, outcomeMeta, policyFailureText } from "./describe";

const outcomes: Outcome[] = ["repaired", "unchanged", "abstained", "unsupported", "insufficient_evidence", "engine_unavailable"];

function report(outcome: Outcome, extra: Partial<DetectReport> = {}): DetectReport {
  return { schema_version: 1, outcome, reason: null, manifest: {}, ...extra };
}

describe("outcome banner mapping", () => {
  it("gives every outcome a distinct, explicit headline and tone", () => {
    const titles = new Set(outcomes.map((o) => outcomeMeta[o].title));
    expect(titles.size).toBe(outcomes.length);
    expect(outcomeMeta.repaired.tone).toBe("ok");
    expect(outcomeMeta.unchanged.tone).toBe("ok");
    expect(outcomeMeta.abstained.tone).toBe("med");
    expect(outcomeMeta.unsupported.tone).toBe("low");
    expect(outcomeMeta.insufficient_evidence.tone).toBe("high");
    expect(outcomeMeta.engine_unavailable.tone).toBe("high");
    for (const o of outcomes) expect(outcomeMeta[o].title.toLowerCase()).not.toContain("no matches");
  });

  it.each(outcomes)("renders the %s headline", (outcome) => {
    render(<OutcomeBanner report={report(outcome)} />);
    expect(screen.getByText(outcomeMeta[outcome].title)).toBeTruthy();
  });

  it("flags a provisional repair and shows the reason", () => {
    render(
      <OutcomeBanner
        report={report("repaired", {
          provisional: true,
          reason: "development evidence only; supply validation fixtures before approval",
        })}
      />,
    );
    expect(screen.getByText("Repair proposed, but not yet validated")).toBeTruthy();
    expect(screen.getByRole("note").textContent).toContain("Provisional.");
    expect(screen.getByText(/development evidence only/)).toBeTruthy();
  });

  it("shows the engine start command when the engine is down", () => {
    render(<OutcomeBanner report={report("engine_unavailable", { reason: "cannot reach Elasticsearch" })} />);
    expect(screen.getByText("kestrix detect engine-up")).toBeTruthy();
  });

  it("summarises the before/after impact of a repair", () => {
    const replay = (tp: number, fp: number, fn: number) => ({
      rule_sha256: "",
      mapping_sha256: "",
      dataset_sha256: "",
      query: null,
      error: null,
      counts: { tp, fp, fn, tn: 0, unknown_matched: 0 },
      scenarios_expected: [],
      scenarios_detected: [],
      matched_event_ids: [],
    });
    const r = report("repaired", {
      provisional: false,
      selected: "b0-noise-1",
      original: { development: replay(3, 4, 0), validation: replay(4, 5, 0) },
      candidates: [
        {
          candidate: {
            schema_version: 1,
            proposal_id: "b0-noise-1",
            original_sha256: "",
            patch_kind: "rule",
            patch: [{ kind: "add_exclusion", predicates: [{ field: "ParentImage", modifier: "equals", values: ["x.exe"] }] }],
            reason_codes: [],
            evidence_event_ids: [],
            assumptions: [],
            model_revision: "deterministic-b0",
            prompt_sha256: null,
          },
          development: replay(3, 0, 0),
          validation: replay(4, 0, 0),
          passed: true,
          policy_failures: [],
        },
      ],
    });
    render(<OutcomeBanner report={r} />);
    expect(
      screen.getByText(
        "On validation events the rule went from catching 4 of 4 attack events with 5 false alarms to catching 4 of 4 attack events with no false alarms.",
      ),
    ).toBeTruthy();
  });

  it("describes patches and policy failures in plain language", () => {
    expect(
      describePatch({ kind: "mapping", sigma_field: "CommandLine", from_field: "winlog.CommandLine", to_field: "process.command_line" }),
    ).toBe("Read CommandLine from process.command_line instead of winlog.CommandLine.");
    expect(
      describePatch({
        kind: "set_predicate",
        selection: "cli",
        field: "CommandLine",
        predicate: { field: "CommandLine", modifier: "contains", values: ["-urlcache", "http"], match_all: true },
      }),
    ).toBe("In “cli”, match CommandLine when it contains “-urlcache” and “http”.");
    expect(policyFailureText("preservation_loss")).toBe("It stops catching a scenario the original rule caught.");
    expect(policyFailureText("brand_new_code")).toBe("brand new code");
  });
});
