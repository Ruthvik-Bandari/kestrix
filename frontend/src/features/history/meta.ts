// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { IconName } from "../../components/Icon";
import { severityLabel, severityTone, type Tone } from "../../components/tone";
import type { HistoryItem, HistoryTool, MailVerdict, Severity, UrlReport, WebReport } from "../../lib/types";
import { levelMeta } from "../forensics/UrlAnalyzer";
import { verdictMeta } from "../mail/MailReportView";
import { gradeTone } from "../webcheck/WebcheckPage";

export const toolMeta: Record<HistoryTool, { name: string; icon: IconName; page: string }> = {
  mail: { name: "Email check", icon: "mailWarning", page: "mail" },
  webcheck: { name: "Web check", icon: "globeLock", page: "webcheck" },
  forensics_file: { name: "File forensics", icon: "fileSearch", page: "forensics" },
  forensics_url: { name: "Link check", icon: "fileSearch", page: "forensics?tab=url" },
};

/** The verdict chip for a listed result: the same tones and words as the tool's own result page. */
export function verdictChip(item: Pick<HistoryItem, "tool" | "verdict">): { tone: Tone; label: string } {
  const { tool, verdict } = item;
  if (tool === "mail" && verdict in verdictMeta) {
    return { tone: verdictMeta[verdict as MailVerdict].tone, label: verdictMeta[verdict as MailVerdict].label };
  }
  if (tool === "webcheck" && verdict in gradeTone) {
    return { tone: gradeTone[verdict as WebReport["grade"]], label: `Grade ${verdict}` };
  }
  if (tool === "forensics_url" && verdict in levelMeta) {
    return { tone: levelMeta[verdict as UrlReport["level"]].tone, label: levelMeta[verdict as UrlReport["level"]].label };
  }
  if (tool === "forensics_file") {
    if (verdict === "none") return { tone: "ok", label: "No findings" };
    if (verdict in severityTone) {
      return { tone: severityTone[verdict as Severity], label: `${severityLabel[verdict as Severity]} severity` };
    }
  }
  return { tone: "neutral", label: verdict };
}

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

/** When a result was saved: the local date and time. */
export function savedAt(epochSeconds: number): { iso: string; text: string } {
  const date = new Date(epochSeconds * 1000);
  return { iso: date.toISOString(), text: dateTime.format(date) };
}
