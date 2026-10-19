// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

/**
 * Which server the dashboard is talking to. `GET /api/health` answers `mode: "hosted"` on the
 * public service (ADR 0004); a local server sends no mode. The mode is read once at start-up
 * (main.tsx) and never changes while the page is open.
 */
export type Mode = "local" | "hosted";

let current: Mode = "local";

export function modeFromHealth(health: unknown): Mode {
  return typeof health === "object" && health !== null && (health as { mode?: unknown }).mode === "hosted"
    ? "hosted"
    : "local";
}

export function setMode(mode: Mode): void {
  current = mode;
}

export function getMode(): Mode {
  return current;
}

export function isHosted(): boolean {
  return current === "hosted";
}
