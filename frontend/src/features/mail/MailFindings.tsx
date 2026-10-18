// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Badge } from "../../components/ui";
import { severityLabel, severityOrder, severityTone } from "../../components/tone";
import type { MailAnalyzer, MailFinding } from "../../lib/types";

export const analyzerLabel: Record<MailAnalyzer, string> = {
  auth: "Sender authentication",
  sender: "Sender addresses",
  lookalike: "Look-alike domain",
  links: "Links",
  attachments: "Attachments",
  intent: "Wording (heuristic)",
};

/** Findings grouped by severity, most severe first. Every value is rendered as plain text. */
export function MailFindings({ findings }: { findings: MailFinding[] }) {
  return (
    <div className="space-y-6">
      {severityOrder.map((severity) => {
        const group = findings.filter((finding) => finding.severity === severity);
        if (group.length === 0) return null;
        const headingId = `mail-findings-${severity}`;
        return (
          <section key={severity} aria-labelledby={headingId}>
            <h3 id={headingId} className="mb-2 flex items-center gap-2 font-semibold">
              <Badge tone={severityTone[severity]}>{severityLabel[severity]}</Badge>
              <span className="text-ink-2">{group.length === 1 ? "1 finding" : `${group.length} findings`}</span>
            </h3>
            <ul className="divide-y divide-line rounded-lg border border-line bg-surface">
              {group.map((finding, index) => (
                <li key={`${finding.id}-${index.toString()}`} className="px-4 py-4">
                  <p className="font-semibold">{finding.title}</p>
                  <p className="mt-1 max-w-[72ch] text-ink-2">{finding.explanation}</p>
                  {finding.evidence ? (
                    <p className="mt-2 text-[0.875rem]">
                      <span className="text-ink-3">Evidence: </span>
                      <code className="break-all text-ink">{finding.evidence}</code>
                    </p>
                  ) : null}
                  <p className="mt-1 font-mono text-xs text-ink-3">
                    {analyzerLabel[finding.analyzer]} · {finding.id}
                  </p>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}
