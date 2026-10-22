// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ToolPage } from "../../app/tools";
import type { DocSection } from "./blocks";

/** One topic page. `path` is what follows "/docs/" ("" is the documentation home). */
export interface DocPage {
  path: string;
  /** The page's h1. */
  title: string;
  /** The short label in the navigation tree. */
  nav: string;
  /** One sentence under the title, and the page's line on the home page and in search. */
  summary: string;
  sections: DocSection[];
}

/** What a page is for (Diataxis): learn by doing, do a task, look something up, or understand. */
export interface PageMeta {
  type: "tutorial" | "how-to" | "reference" | "explanation";
  /** The repository files the page summarizes. */
  source: string[];
  /** When the content was last checked against them (YYYY-MM-DD). */
  reviewed: string;
}

/** A navigation entry: a page, with the pages nested under it. */
export interface TreeNode {
  path: string;
  children?: TreeNode[];
}

/** A top-level group of the navigation tree. */
export interface TreeSection {
  title: string;
  nodes: TreeNode[];
}

/** The docs page a tool's "Read the docs" link goes to. */
export const TOOL_DOC_PATH: Record<ToolPage, string> = {
  mail: "tools/email",
  webcheck: "tools/website",
  forensics: "tools/forensics",
  detect: "tools/detection-repair",
  code: "code-security/kestrix-scan",
  "claude-plugin": "code-security/claude-plugin",
  bitcoin: "tools/bitcoin",
};

/** Pages other places link to by name. */
export const HOSTED_DOC_PATH = "getting-started/hosted-service";

/**
 * Where the old flat addresses went (/docs/mail, /docs/packages, ...), so every link ever shared keeps
 * working. "overview" was the old home.
 */
export const LEGACY_DOC_PATHS: Record<string, string> = {
  overview: "",
  hosted: HOSTED_DOC_PATH,
  mail: TOOL_DOC_PATH.mail,
  webcheck: TOOL_DOC_PATH.webcheck,
  forensics: TOOL_DOC_PATH.forensics,
  detect: TOOL_DOC_PATH.detect,
  code: TOOL_DOC_PATH.code,
  bitcoin: TOOL_DOC_PATH.bitcoin,
  packages: "code-security/kestrix-scan/install-and-cli",
  "claude-plugin": TOOL_DOC_PATH["claude-plugin"],
};
