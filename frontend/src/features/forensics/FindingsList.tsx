// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Badge } from "../../components/ui";
import { severityLabel, severityTone } from "../../components/tone";
import type { ForensicFinding } from "../../lib/types";

export function FindingsList({ findings }: { findings: ForensicFinding[] }) {
  return (
    <ul className="divide-y divide-line rounded-lg border border-line bg-surface">
      {findings.map((finding) => (
        <li key={finding.id} className="px-4 py-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={severityTone[finding.severity]}>{severityLabel[finding.severity]}</Badge>
            <h3 className="font-semibold">{finding.title}</h3>
          </div>
          <p className="mt-2 max-w-[72ch] text-ink-2">{finding.explanation}</p>
          <p className="mt-1 font-mono text-xs text-ink-3">{finding.id}</p>
        </li>
      ))}
    </ul>
  );
}
