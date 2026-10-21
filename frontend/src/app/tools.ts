// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { IconName } from "../components/Icon";
import { pageAvailable } from "./paths";

/*
 * The dashboard's tools, in launcher order. The home grid and the sidebar both read this list.
 * `runs`: "dashboard" tools run live in the dashboard in this mode; "guide" tools show a
 * step-by-step guide for running them on your own computer (the code scanner and the Claude Code
 * plugin always, detection repair and Bitcoin on the hosted service).
 */

export interface Tool {
  /** Dashboard-relative page, such as "mail". */
  page: string;
  name: string;
  icon: IconName;
  /** Whether this tool has a live page in the dashboard at all (in local mode). */
  live: boolean;
}

export const tools: Tool[] = [
  { page: "mail", name: "Email check", icon: "mailWarning", live: true },
  { page: "webcheck", name: "Web check", icon: "globeLock", live: true },
  { page: "forensics", name: "File & link forensics", icon: "fileSearch", live: true },
  { page: "detect", name: "Detection repair", icon: "shieldCheck", live: true },
  { page: "code", name: "Code scanner", icon: "scanSearch", live: false },
  { page: "claude-plugin", name: "Claude Code plugin", icon: "bot", live: false },
  { page: "bitcoin", name: "Bitcoin quantum risk", icon: "bitcoin", live: true },
];

/** Workspace pages that sit beside the tools in the launcher and the sidebar. */
export const workspace: { page: string; name: string; icon: IconName }[] = [
  { page: "docs", name: "Docs", icon: "bookOpen" },
  { page: "history", name: "Recent results", icon: "history" },
];

/** Whether the tool runs on your own computer only in this mode (shown as "Run locally"). */
export function runsLocallyOnly(tool: Tool): boolean {
  return !tool.live || !pageAvailable(tool.page);
}
