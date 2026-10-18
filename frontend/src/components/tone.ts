// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { IconName } from "./Icon";
import type { Severity } from "../lib/types";

export type Tone = "crit" | "high" | "med" | "low" | "ok" | "neutral" | "accent";

interface ToneStyle {
  /** Tinted surface with readable text. */
  soft: string;
  /** Text color alone (for icons and labels on neutral surfaces). */
  text: string;
  /** Solid mark color (dots, meters, bars). */
  mark: string;
  icon: IconName;
}

export const tones: Record<Tone, ToneStyle> = {
  crit: { soft: "bg-crit-bg text-crit", text: "text-crit", mark: "bg-crit-mark", icon: "octagon" },
  high: { soft: "bg-high-bg text-high", text: "text-high", mark: "bg-high-mark", icon: "alert" },
  med: { soft: "bg-med-bg text-med", text: "text-med", mark: "bg-med-mark", icon: "alert" },
  low: { soft: "bg-low-bg text-low", text: "text-low", mark: "bg-low-mark", icon: "info" },
  ok: { soft: "bg-ok-bg text-ok", text: "text-ok", mark: "bg-ok-mark", icon: "checkCircle" },
  neutral: { soft: "bg-inset text-ink-2", text: "text-ink-2", mark: "bg-ink-3", icon: "minus" },
  accent: { soft: "bg-accent-soft text-accent-text", text: "text-accent-text", mark: "bg-accent", icon: "info" },
};

export const severityTone: Record<Severity, Tone> = { high: "crit", medium: "med", low: "low", info: "neutral" };

export const severityLabel: Record<Severity, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const severityOrder: Severity[] = ["high", "medium", "low", "info"];
