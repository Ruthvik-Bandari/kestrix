// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { toolFor, type ToolPage } from "../../../app/tools";
import { toolContent } from "../../tools/content";
import { pages, type DocSection } from "../blocks";
import type { DocPage } from "../model";

/** One of the reference sections written once in features/tools/content.ts ("What it is", "How it works", ...). */
export function ref(tool: ToolPage, heading: string): DocSection {
  const found = toolContent[tool].reference.find((item) => item.heading === heading);
  if (!found) throw new Error(`no "${heading}" section for ${tool}`);
  return found;
}

/** A tool's overview page: what it is, how it helps and typical uses (all from tools/content.ts), then its topic pages. */
export function toolOverview(tool: ToolPage, path: string, children: string[]): DocPage {
  const { name, summary } = toolFor(tool);
  return {
    path,
    title: name,
    nav: name,
    summary,
    sections: [
      ref(tool, "What it is"),
      ref(tool, "How it helps"),
      ref(tool, "Typical uses"),
      { heading: "In this tool", blocks: [pages(...children)] },
    ],
  };
}

/** A tool's "Limits and measured accuracy" page title, repeated for every tool so the pages read alike. */
export const LIMITS_NAV = "Limits and accuracy";
