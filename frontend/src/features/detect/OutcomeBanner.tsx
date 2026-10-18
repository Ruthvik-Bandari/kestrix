// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Verdict } from "../../components/ui";
import type { DetectReport } from "../../lib/types";
import { EngineHint } from "./EngineHint";
import { impactSummary, outcomeMeta } from "./describe";

export function OutcomeBanner({ report, titleId }: { report: DetectReport; titleId?: string }) {
  const meta = outcomeMeta[report.outcome];
  const provisional = report.outcome === "repaired" && report.provisional === true;
  const impact = report.outcome === "repaired" ? impactSummary(report) : null;
  return (
    <div className="space-y-3">
      <Verdict
        tone={provisional ? "med" : meta.tone}
        title={provisional ? "Repair proposed, but not yet validated" : meta.title}
        {...(titleId ? { titleId } : {})}
      >
        <p>{meta.explain}</p>
        {impact ? <p className="mt-1 font-medium text-ink">{impact}</p> : null}
        {report.reason ? (
          <p className="mt-2 text-[0.875rem]">
            <span className="font-medium text-ink">Reason: </span>
            <span className="break-words">{report.reason}</span>
          </p>
        ) : null}
      </Verdict>
      {provisional ? (
        <p role="note" className="rounded-lg border border-line px-4 py-3 text-ink-2">
          <span className="font-medium text-ink">Provisional.</span> This fix was only screened on development events.
          Add validation events (a separate labeled set) before you approve it.
        </p>
      ) : null}
      {report.outcome === "engine_unavailable" ? <EngineHint /> : null}
    </div>
  );
}
