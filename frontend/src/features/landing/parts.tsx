// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../components/Icon";
import { severityLabel, severityOrder, severityTone, tones } from "../../components/tone";
import { cx } from "../../components/ui";
import type { Severity } from "../../lib/types";
import { emailSample } from "./samples";

/** The severity as a labelled chip: the word and the icon carry it, not the color alone. */
export function SeverityChip({ severity }: { severity: Severity }) {
  const tone = tones[severityTone[severity]];
  return (
    <span className={cx("inline-flex flex-none items-center gap-1 rounded-md px-2 py-0.5 font-mono text-[0.6875rem] font-medium uppercase", tone.soft)}>
      <Icon name={tone.icon} size={12} />
      {severityLabel[severity]}
    </span>
  );
}

const SHOWN = 3;
const SHORT_EVIDENCE = 40;

/** How many findings of each severity, with low and info together as "other". */
export function severitySummary(findings: { severity: Severity }[]) {
  const count = (severity: Severity) => findings.filter((f) => f.severity === severity).length;
  return { high: count("high"), medium: count("medium"), other: count("low") + count("info") };
}

/**
 * The featured example: the bundled synthetic email run through the real analyzer (samples/email.json,
 * written by scripts/build_landing_samples.py). The card draws every value from that file.
 */
export function ReportCard() {
  const { report, message } = emailSample;
  const ranked = [...report.findings].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
  const top = ranked.slice(0, SHOWN);
  const summary = severitySummary(report.findings);
  const verdict = report.verdict.charAt(0).toUpperCase() + report.verdict.slice(1);
  return (
    <figure id="example" tabIndex={-1} className="m-0 outline-none">
      <article aria-label="Example email report" className="panel panel-glow overflow-hidden rounded-xl">
        <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-3.5 font-mono text-[0.6875rem] tracking-[0.08em] text-ink-2 uppercase sm:px-6">
          <span className="inline-flex items-center gap-2">
            <Icon name="mail" size={15} />
            Email analysis
          </span>
          <span>Synthetic example</span>
        </div>
        <div className="px-5 pt-5 pb-4 sm:px-6 sm:pt-6">
          <div className="flex items-center gap-3.5">
            <span className="flex size-11 flex-none items-center justify-center rounded-full bg-crit-bg text-crit">
              <Icon name="octagon" size={22} />
            </span>
            <div>
              <p className="text-[1.75rem] leading-tight font-semibold tracking-[-0.02em] text-ink">{verdict}</p>
              <p className="text-[0.875rem] text-ink-2">
                <span className="tabular-nums">{report.findings.length}</span> findings, each with its evidence
              </p>
            </div>
          </div>
          <div className="mt-5 border-l-2 border-line-strong pl-3.5">
            <p className="text-[0.9375rem] leading-snug font-semibold break-words text-ink">{message.subject}</p>
            <p className="mt-0.5 font-mono text-[0.8125rem] break-all text-ink-2">From {message.from_address}</p>
          </div>
        </div>
        <ul aria-label="Top findings" className="mx-5 divide-y divide-line border-t border-line sm:mx-6">
          {top.map((finding) => (
            <li key={finding.id} className="flex items-start justify-between gap-3 py-3">
              <div className="min-w-0">
                <p className="text-[0.9375rem] leading-snug text-ink">{finding.title}</p>
                {finding.evidence && finding.evidence.length <= SHORT_EVIDENCE ? (
                  <p className="mt-0.5 font-mono text-[0.75rem] break-all text-ink-2">{finding.evidence}</p>
                ) : null}
              </div>
              <SeverityChip severity={finding.severity} />
            </li>
          ))}
        </ul>
        <div className="mt-1 flex flex-wrap items-center justify-between gap-x-4 gap-y-1 bg-inset px-5 py-3.5 font-mono text-[0.75rem] tracking-[0.04em] text-ink-2 uppercase sm:px-6">
          <span className="tabular-nums">
            {summary.high} high · {summary.medium} medium · {summary.other} other
          </span>
          <span>
            Top {top.length} of {report.findings.length}
          </span>
        </div>
      </article>
      <figcaption className="mt-3 text-right font-mono text-[0.75rem] tracking-[0.04em] text-ink-2">
        Synthetic example · actual analyzer output
      </figcaption>
    </figure>
  );
}
