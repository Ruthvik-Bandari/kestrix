// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

/** Documentation content blocks. Text in `backticks` is shown as code; nothing is parsed as HTML. */
export type Block =
  | { kind: "p"; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "steps"; items: string[] }
  | { kind: "code"; code: string; label?: string }
  /** Every tool, linked to its docs page, with its one-line summary (app/tools.ts). */
  | { kind: "tools" }
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
