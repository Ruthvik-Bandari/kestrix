// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { IconName } from "../components/Icon";
import { pageAvailable } from "./paths";

/*
 * The dashboard's tools, in launcher order: the one place each tool's name, icon and one-line
 * summary are written. The home grid, the sidebar shortcuts, every tool and guide page header and
 * the docs read this list; the longer reference and the command-line guide for each tool live in
 * features/tools/content.ts. A tool whose page is a guide (the code scanner and the Claude Code
 * plugin always, detection repair and Bitcoin on the hosted service) shows "Run locally".
 */

export type ToolPage = "mail" | "webcheck" | "forensics" | "detect" | "code" | "claude-plugin" | "bitcoin";

export interface Tool {
  /** Dashboard-relative page, such as "mail"; also the tool's docs page, docs/<page>. */
  page: ToolPage;
  name: string;
  /** Short label for the navigation rail, where the group heading already says "Checks" or "Advanced". */
  navName: string;
  icon: IconName;
  /** One sentence: what the tool does. The page lede everywhere the tool is introduced. */
  summary: string;
  /** Whether this tool has a live page in the dashboard at all (in local mode). */
  live: boolean;
}

export const tools: Tool[] = [
  {
    page: "mail",
    navName: "Email",
    name: "Email check",
    icon: "mailWarning",
    summary: "Checks a saved email for phishing, impersonation and fake-invoice signs, with a reason for every finding.",
    live: true,
  },
  {
    page: "webcheck",
    navName: "Website",
    name: "Web check",
    icon: "globeLock",
    summary: "Grades a website's HTTPS, TLS certificate, security headers and cookies from A to F, with a fix for each problem.",
    live: true,
  },
  {
    page: "forensics",
    navName: "File & link",
    name: "File & link forensics",
    icon: "fileSearch",
    summary:
      "Shows what a file really is and whether a link has common phishing signs, without running the file or opening the link.",
    live: true,
  },
  {
    page: "detect",
    navName: "Detection repair",
    name: "Detection repair",
    icon: "shieldCheck",
    summary:
      "Finds why a Sigma rule misses attacks or fires on benign activity, and proves the smallest fix by replaying labeled events.",
    live: true,
  },
  {
    page: "code",
    navName: "Code scanner",
    name: "Code scanner",
    icon: "scanSearch",
    summary:
      "kestrix-scan finds security mistakes in 13 languages, web, CI and infrastructure files, hard-coded secrets and vulnerable dependencies.",
    live: false,
  },
  {
    page: "claude-plugin",
    navName: "Claude integration",
    name: "Claude Code plugin",
    icon: "bot",
    summary: "Claude Code checks the code it writes: every edit is scanned, and Claude fixes what it introduced in the same turn.",
    live: false,
  },
  {
    page: "bitcoin",
    navName: "Bitcoin",
    name: "Bitcoin quantum risk",
    icon: "bitcoin",
    summary:
      "Shows which of your Bitcoin addresses have a public key visible on the blockchain, and how to move coins to an address that hides it.",
    live: true,
  },
];

/** The tools that make up the rail and Home groups: single source for both. */
export const toolGroups: { title: string; pages: ToolPage[] }[] = [
  { title: "Checks", pages: ["mail", "webcheck", "forensics"] },
  { title: "Advanced", pages: ["detect", "bitcoin"] },
  { title: "Developer tools", pages: ["code", "claude-plugin"] },
];

export const TOOL_PAGES: ToolPage[] = tools.map((tool) => tool.page);

export function toolFor(page: ToolPage): Tool {
  const tool = tools.find((item) => item.page === page);
  if (!tool) throw new Error(`unknown tool ${page}`);
  return tool;
}

/**
 * The short availability hint for navigation and Home, or null where the tool simply runs:
 * "Guide" where the page is always a setup guide (code scanner, Claude integration), "Local guide"
 * where it is live locally but only a guide on the hosted service (detection repair, Bitcoin).
 */
export function availabilityHint(tool: Tool): "Guide" | "Local guide" | null {
  if (!tool.live) return "Guide";
  return pageAvailable(tool.page) ? null : "Local guide";
}
