// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useFocusOnArrival, VerdictCard } from "../../components/report";
import type { DetectReport } from "../../lib/types";
import { EngineHint } from "./EngineHint";
import { impactSummary, outcomeMeta } from "./describe";

/**
 * The result's opening card. Every explicit outcome has its own label, icon and sentence; only
 * `repaired` (validated) and `unchanged` look like success, and a provisional repair is a warning.
 * The label takes focus when the report arrives.
 */
export function OutcomeBanner({ report }: { report: DetectReport }) {
  const heading = useFocusOnArrival(report);
  const meta = outcomeMeta[report.outcome];
  const provisional = report.outcome === "repaired" && report.provisional === true;
  const impact = report.outcome === "repaired" ? impactSummary(report) : null;
  return (
    <div className="space-y-3">
      <VerdictCard
        tone={provisional ? "med" : meta.tone}
        icon={provisional ? "alert" : meta.icon}
        label={provisional ? "Repair proposed" : meta.label}
        headingId="detect-result"
        headingRef={heading}
        title={provisional ? "Not yet validated: screened on development events only" : meta.title}
      >
        <p>{meta.explain}</p>
        {impact ? <p className="mt-1 font-medium text-ink">{impact}</p> : null}
        {report.reason ? (
          <p className="mt-2 text-[0.875rem]">
            <span className="font-medium text-ink">Reason: </span>
            <span className="break-words">{report.reason}</span>
          </p>
        ) : null}
      </VerdictCard>
      {provisional ? (
        <p role="note" className="max-w-[68ch] rounded-xl border border-line px-4 py-3 text-ink-2">
          <span className="font-medium text-ink">Provisional.</span> This fix was only screened on development events.
          Add validation events (a separate labeled set) before you approve it.
        </p>
      ) : null}
      {report.outcome === "engine_unavailable" ? <EngineHint /> : null}
    </div>
  );
}
