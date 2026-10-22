// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ToolPage } from "../../app/tools";

/** Documentation content blocks. Text in `backticks` is shown as code; nothing is parsed as HTML. */
export type Block =
  | { kind: "p"; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "steps"; items: string[] }
  | { kind: "code"; code: string; label?: string }
  /** A table. `head` and every row have the same number of cells; cells may use `backticks`. */
  | { kind: "table"; head: string[]; rows: string[][]; caption?: string }
  /** A callout: `info` for context, `caution` for a limit the reader must not miss. */
  | { kind: "note"; tone: "info" | "caution"; text: string }
  /** Every tool, linked to its docs overview, with its one-line summary (app/tools.ts). */
  | { kind: "tools" }
  /** The install-and-use checklist of one tool (features/tools/ToolGuide), nested under its section. */
  | { kind: "guide"; tool: ToolPage }
  /** Docs pages, by page path, each with its title and one-line summary (title and summary live on the page). */
  | { kind: "pages"; paths: string[] }
  /** A link to another docs page, by page path. */
  | { kind: "see"; text: string; to: string }
  /** A link to the public landing page. */
  | { kind: "landing"; text: string }
  /** A link to another page of the app (the privacy notice, the terms), by an app path. */
  | { kind: "route"; text: string; to: string };

export interface DocSection {
  heading: string;
  blocks: Block[];
}

export const p = (text: string): Block => ({ kind: "p", text });
export const list = (...items: string[]): Block => ({ kind: "list", items });
export const steps = (...items: string[]): Block => ({ kind: "steps", items });
export const code = (source: string, label?: string): Block =>
  label === undefined ? { kind: "code", code: source } : { kind: "code", code: source, label };
export const table = (head: string[], rows: string[][], caption?: string): Block =>
  caption === undefined ? { kind: "table", head, rows } : { kind: "table", head, rows, caption };
export const note = (text: string, tone: "info" | "caution" = "info"): Block => ({ kind: "note", tone, text });
export const see = (text: string, to: string): Block => ({ kind: "see", text, to });
export const pages = (...paths: string[]): Block => ({ kind: "pages", paths });
export const guide = (tool: ToolPage): Block => ({ kind: "guide", tool });
export const section = (heading: string, ...blocks: Block[]): DocSection => ({ heading, blocks });
