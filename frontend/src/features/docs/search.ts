// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { tools } from "../../app/tools";
import { headingId } from "../../components/OnThisPage";
import { toolContent } from "../tools/content";
import type { Block } from "./blocks";
import { docPages, metaOf, pageAt, sectionOf } from "./content";
import type { DocPage } from "./model";

/*
 * Client-side search, no dependency: a small index built once, on first use, from the typed pages (their
 * titles, summaries, h2 headings and every block's text). It runs in the browser, so it works offline.
 */

/** The element id of each h2 on a page, in order, unique within the page. */
export function sectionIds(page: DocPage): string[] {
  const seen = new Map<string, number>();
  return page.sections.map((section) => {
    const base = headingId("docs", section.heading);
    const count = (seen.get(base) ?? 0) + 1;
    seen.set(base, count);
    return count === 1 ? base : `${base}-${count}`;
  });
}

/** The visible text of a block, without markup, for the index. */
export function blockText(block: Block): string {
  switch (block.kind) {
    case "p":
    case "note":
    case "see":
    case "landing":
    case "route":
      return block.text;
    case "list":
    case "steps":
      return block.items.join(" ");
    case "code":
      return block.code;
    case "table":
      return [block.caption ?? "", ...block.rows.flat()].join(" ");
    case "tools":
      return tools.map((tool) => `${tool.name} ${tool.summary}`).join(" ");
    case "pages":
      return block.paths.map((path) => `${pageAt(path)?.title ?? ""} ${pageAt(path)?.summary ?? ""}`).join(" ");
    case "guide": {
      const guide = toolContent[block.tool].local;
      return [
        ...guide.requirements,
        ...guide.install.flatMap((item) => [item.command, item.note ?? ""]),
        guide.verify.command,
        guide.verify.detail,
        ...guide.steps.flatMap((step) => [step.title, step.detail ?? "", step.command ?? ""]),
        ...guide.troubleshooting.flatMap((item) => [item.problem, item.fix]),
      ].join(" ");
    }
  }
}

export interface SearchEntry {
  path: string;
  /** "" for a result that is the page itself. */
  anchor: string;
  pageTitle: string;
  /** "Tools" or "Tools › Email check": where the page sits in the tree. */
  where: string;
  heading: string | null;
  text: string;
  /** Lower-case searchable text, split by field. */
  titleKey: string;
  headingKey: string;
  bodyKey: string;
  order: number;
}

export interface SearchHit {
  key: string;
  path: string;
  anchor: string;
  pageTitle: string;
  where: string;
  heading: string | null;
  snippet: string;
}

const strip = (text: string): string => text.replace(/`/g, "");

function whereOf(page: DocPage): string {
  const group = sectionOf(page.path);
  return group ? group.title : "Documentation";
}

let index: SearchEntry[] | null = null;

export function searchIndex(): SearchEntry[] {
  if (index) return index;
  const entries: SearchEntry[] = [];
  let order = 0;
  for (const page of docPages) {
    const where = whereOf(page);
    entries.push({
      path: page.path,
      anchor: "",
      pageTitle: page.title,
      where,
      heading: null,
      text: strip(page.summary),
      titleKey: strip(page.title).toLowerCase(),
      headingKey: "",
      bodyKey: strip(`${page.summary} ${page.nav}`).toLowerCase(),
      order: order++,
    });
    const ids = sectionIds(page);
    page.sections.forEach((section, i) => {
      const body = strip(section.blocks.map(blockText).join(" "));
      entries.push({
        path: page.path,
        anchor: ids[i] ?? "",
        pageTitle: page.title,
        where,
        heading: section.heading,
        text: body,
        titleKey: strip(page.title).toLowerCase(),
        headingKey: strip(section.heading).toLowerCase(),
        bodyKey: body.toLowerCase(),
        order: order++,
      });
    });
  }
  index = entries;
  return entries;
}

function snippetFor(entry: SearchEntry, tokens: string[]): string {
  const text = entry.text;
  const lower = entry.bodyKey;
  const at = tokens.map((token) => lower.indexOf(token)).filter((position) => position >= 0);
  if (at.length === 0) return text.slice(0, 110).trim();
  const first = Math.min(...at);
  const start = Math.max(0, first - 40);
  const cut = text.slice(start, start + 120).trim();
  return `${start > 0 ? "…" : ""}${cut}${start + 120 < text.length ? "…" : ""}`;
}

/** Tokens of a query: lower case, split on spaces. Dots, hyphens and underscores stay, so ids such as `mail.auth.dmarc_fail` work. */
export function tokens(query: string): string[] {
  return query
    .toLowerCase()
    .split(/\s+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
}

/**
 * Entries that contain every token, best first: a token in the page title scores most, then in the heading,
 * then at the start of a word in the text, then anywhere in it. Ties keep reading order.
 */
export function search(query: string, limit = 8): SearchHit[] {
  const words = tokens(query);
  if (words.length === 0) return [];
  const scored: { entry: SearchEntry; score: number }[] = [];
  for (const entry of searchIndex()) {
    let score = 0;
    let all = true;
    for (const word of words) {
      let best = 0;
      if (entry.titleKey.includes(word)) best = Math.max(best, entry.heading === null ? 12 : 4);
      if (entry.headingKey.includes(word)) best = Math.max(best, 8);
      if (entry.bodyKey.includes(word)) {
        const startsWord = entry.bodyKey.includes(` ${word}`) || entry.bodyKey.startsWith(word);
        best = Math.max(best, startsWord ? 2 : 1);
      }
      if (best > 0) {
        // Repeated mentions rank higher, so the page that lists an id outranks one that only names it.
        const count = entry.bodyKey.split(word).length - 1;
        best += Math.min(count, 10) * 0.1;
      }
      if (best === 0) {
        all = false;
        break;
      }
      score += best;
    }
    // Reference pages win ties: a bare id is usually looked up, not read about.
    if (all) scored.push({ entry, score: score + (metaOf(entry.path).type === "reference" ? 0.5 : 0) });
  }
  scored.sort((a, b) => b.score - a.score || a.entry.order - b.entry.order);
  return scored.slice(0, limit).map(({ entry }) => ({
    key: `${entry.path}#${entry.anchor}`,
    path: entry.path,
    anchor: entry.anchor,
    pageTitle: entry.pageTitle,
    where: entry.where,
    heading: entry.heading,
    snippet: snippetFor(entry, words),
  }));
}
