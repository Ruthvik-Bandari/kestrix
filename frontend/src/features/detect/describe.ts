// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { IconName } from "../../components/Icon";
import type { Tone } from "../../components/tone";
import type { CandidateEntry, Counts, DetectReport, Family, Outcome, Patch, ReplayResult } from "../../lib/types";

export interface OutcomeMeta {
  tone: Tone;
  /** A distinct icon per outcome, so no outcome other than a success looks like one. */
  icon: IconName;
  label: string;
  title: string;
  explain: string;
}

/** Plain-language framing for every workflow outcome. No outcome is ever shown as "no matches". */
export const outcomeMeta: Record<Outcome, OutcomeMeta> = {
  repaired: {
    tone: "ok",
    icon: "checkCircle",
    label: "Repaired",
    title: "A tested fix is ready to review",
    explain:
      "Kestrix found the cause, proposed a bounded change and replayed it on labeled events. Review the change before you deploy it.",
  },
  unchanged: {
    tone: "ok",
    icon: "shieldCheck",
    label: "Unchanged",
    title: "No repair needed: the rule already works",
    explain: "The original rule catches every labeled attack without false alarms on the development events.",
  },
  abstained: {
    tone: "med",
    icon: "help",
    label: "Abstained",
    title: "No safe fix found, so the rule was left as it is",
    explain:
      "Kestrix would rather propose nothing than a change it could not verify. The diagnosis below shows what it tried.",
  },
  unsupported: {
    tone: "low",
    icon: "info",
    label: "Unsupported",
    title: "This rule uses a feature Kestrix can't repair yet",
    explain: "Nothing was changed. The reason below names the unsupported part of the rule.",
  },
  insufficient_evidence: {
    tone: "high",
    icon: "alert",
    label: "Insufficient evidence",
    title: "The data this rule needs isn't being collected",
    explain:
      "No rule change can bring back telemetry that was never recorded. Collect the fields below, then run the repair again.",
  },
  engine_unavailable: {
    tone: "high",
    icon: "octagon",
    label: "Engine unavailable",
    title: "The detection engine isn't reachable",
    explain: "Start the pinned engine, then run again. Nothing was replayed.",
  },
};

export const familyMeta: Record<Family, { label: string; explain: string }> = {
  mapping: {
    label: "Field mapping drift",
    explain: "The rule looks for a field under a name your data no longer uses.",
  },
  missing_telemetry: {
    label: "Missing telemetry",
    explain: "A field the rule depends on is never recorded in these events.",
  },
  noise: {
    label: "Noise",
    explain: "Legitimate activity matches the rule and raises false alarms.",
  },
  logic: {
    label: "Logic gap",
    explain: "Attacks are missed even though every field the rule needs is present.",
  },
};

const policyText: Record<string, string> = {
  replay_error: "The change failed to run on the engine.",
  mandatory_scenario_missed: "It misses an attack scenario that must be caught.",
  preservation_loss: "It stops catching a scenario the original rule caught.",
  benign_matches_above_baseline: "It raises more false alarms than the healthy baseline.",
  no_benign_reduction: "It does not reduce false alarms.",
};

export function policyFailureText(code: string): string {
  return policyText[code] ?? code.replace(/_/g, " ");
}

const modifierText = { equals: "equals", contains: "contains", startswith: "starts with", endswith: "ends with" };

function quoteValues(values: string[], all = false): string {
  return values.map((v) => `“${v}”`).join(all ? " and " : " or ");
}

/** One sentence per patch operation, written for a reviewer rather than a parser. */
export function describePatch(patch: Patch): string {
  switch (patch.kind) {
    case "mapping":
      return `Read ${patch.sigma_field} from ${patch.to_field} instead of ${patch.from_field}.`;
    case "add_exclusion":
      return `Ignore events where ${patch.predicates
        .map((p) => `${p.field} ${modifierText[p.modifier]} ${quoteValues(p.values, p.match_all)}`)
        .join(" and ")}.`;
    case "set_predicate":
      return `In “${patch.selection}”, match ${patch.field} when it ${modifierText[patch.predicate.modifier]} ${quoteValues(patch.predicate.values, patch.predicate.match_all)}.`;
    case "set_condition":
      return `Change the condition to “${patch.condition}”.`;
  }
}

/** The replay a verdict should rest on: validation when it exists, else development. */
function decisive(result: { development: ReplayResult; validation?: ReplayResult | undefined }): {
  split: "validation" | "development";
  replay: ReplayResult;
} {
  return result.validation
    ? { split: "validation", replay: result.validation }
    : { split: "development", replay: result.development };
}

export function selectedCandidate(report: DetectReport): CandidateEntry | undefined {
  return report.candidates?.find((c) => c.candidate.proposal_id === report.selected);
}

function attacks(c: Counts): string {
  const total = c.tp + c.fn;
  return `${c.tp} of ${total} attack ${total === 1 ? "event" : "events"}`;
}

function alarms(n: number): string {
  return n === 0 ? "no false alarms" : `${n} false ${n === 1 ? "alarm" : "alarms"}`;
}

/** A one-line, plain-language before/after summary for a repaired report. */
export function impactSummary(report: DetectReport): string | null {
  const chosen = selectedCandidate(report);
  if (!report.original || !chosen) return null;
  const before = decisive(report.original);
  const after = decisive(chosen);
  if (before.split !== after.split) return null;
  const b = before.replay.counts;
  const a = after.replay.counts;
  // A failed replay has no counts; say nothing rather than a number.
  if (!b || !a) return null;
  return `On ${after.split} events the rule went from catching ${attacks(b)} with ${alarms(b.fp)} to catching ${attacks(a)} with ${alarms(a.fp)}.`;
}

/** Every reason code in a report with where it came from: diagnosis, the selected change, policy failures. */
export function reasonCodes(report: DetectReport): { code: string; source: string }[] {
  const out: { code: string; source: string }[] = [];
  const seen = new Set<string>();
  const add = (code: string, source: string) => {
    if (seen.has(`${source}|${code}`)) return;
    seen.add(`${source}|${code}`);
    out.push({ code, source });
  };
  for (const h of report.hypotheses ?? []) for (const code of h.reason_codes) add(code, `Diagnosis: ${familyMeta[h.family].label.toLowerCase()}`);
  for (const entry of report.candidates ?? []) {
    if (entry.candidate.proposal_id === report.selected) for (const code of entry.candidate.reason_codes) add(code, "Selected change");
    for (const code of entry.policy_failures ?? []) add(code, `Policy failure: ${entry.candidate.proposal_id}`);
  }
  return out;
}
