// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Fragment } from "react";
import { CopyButton, cx } from "../../components/ui";
import type { Example } from "./examples";

/** Text with `backtick` spans shown as inline code. Plain text only: never parsed as HTML. */
export function Inline({ text }: { text: string }) {
  const parts = text.split("`");
  return (
    <>
      {parts.map((part, index) =>
        index % 2 === 1 ? (
          <code key={index} className="rounded-md bg-inset px-1.5 py-0.5 font-mono text-[0.875em] text-ink">
            {part}
          </code>
        ) : (
          <Fragment key={index}>{part}</Fragment>
        ),
      )}
    </>
  );
}

/** One shell command (or snippet) with a copy button. */
export function Command({ command, label }: { command: string; label?: string | undefined }) {
  const multiline = command.includes("\n");
  // Claude Code slash commands are typed in a session, not a shell: no "$" prompt for them.
  const shell = !multiline && !command.startsWith("/");
  return (
    <div className="flex items-start gap-2 rounded-xl border border-line bg-inset py-1.5 pr-1.5 pl-3">
      <pre
        className="min-w-0 flex-1 overflow-x-auto py-1.5 font-mono text-[0.8125rem] leading-relaxed text-ink"
        tabIndex={0}
        role="region"
        aria-label={label ?? `Command: ${command.split("\n", 1)[0] ?? ""}`}
      >
        <code>
          {shell ? (
            <span className="text-ink-3 select-none" aria-hidden="true">
              ${" "}
            </span>
          ) : null}
          {command}
        </code>
      </pre>
      <CopyButton text={command} label={`Copy ${multiline ? "snippet" : "command"}: ${command.split("\n", 1)[0] ?? ""}`} className="flex-none" />
    </div>
  );
}

/** A real Kestrix output, with where it comes from. */
export function ExampleOutput({ example, className }: { example: Example; className?: string }) {
  return (
    <figure className={cx("min-w-0", className)}>
      <figcaption className="mb-2 font-medium text-ink">{example.caption}</figcaption>
      <pre
        className="max-h-[26rem] overflow-auto rounded-xl border border-line bg-inset p-3 font-mono text-[0.78rem] leading-relaxed whitespace-pre text-ink"
        tabIndex={0}
        role="region"
        aria-label={`Example output: ${example.caption}`}
      >
        <code>{example.text}</code>
      </pre>
      <p className="mt-2 text-[0.8125rem] text-ink-3">{example.source}</p>
    </figure>
  );
}
