// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Link } from "react-router";
import { landingPath } from "../../app/paths";
import { tools } from "../../app/tools";
import { Icon } from "../../components/Icon";
import { cx } from "../../components/ui";
import { Command, Inline } from "../tools/parts";
import { ToolGuide } from "../tools/ToolGuide";
import type { Block } from "./blocks";
import { pageAt } from "./content";
import { DiagramView } from "./DiagramView";
import { TOOL_DOC_PATH } from "./model";
import { useDocPath } from "./scope";

const SEVERITY_TEXT: Record<string, string> = {
  critical: "text-crit",
  high: "text-high",
  medium: "text-med",
  low: "text-low",
  info: "text-ink-2",
};

/** In a "Severity" column the first word (critical, high, medium, low, info) is coloured; the word itself always stays. */
function Cell({ text, severity }: { text: string; severity: boolean }) {
  // An id such as `mail.auth.dmarc_fail` may break after a dot or underscore, never in the middle of a word.
  const id = /^`([^`]+)`$/.exec(text)?.[1];
  if (id)
    return (
      <code className="rounded-md bg-inset px-1.5 py-0.5 font-mono text-[0.875em] text-ink">
        {id.split(/(?<=[._])/).map((part, i) => (
          <span key={i}>
            {part}
            <wbr />
          </span>
        ))}
      </code>
    );
  const first = severity ? /^(critical|high|medium|low|info)\b/.exec(text)?.[1] : undefined;
  if (!first) return <Inline text={text} />;
  return (
    <>
      <span className={cx("font-semibold", SEVERITY_TEXT[first])}>{first}</span>
      <Inline text={text.slice(first.length)} />
    </>
  );
}

function DocTable({ head, rows, caption }: { head: string[]; rows: string[][]; caption: string | undefined }) {
  const severityColumn = head.findIndex((name) => name.toLowerCase() === "severity");
  return (
    <div
      className="max-w-full overflow-x-auto rounded-xl border border-line"
      tabIndex={0}
      role="region"
      aria-label={caption ?? `Table: ${head.join(", ")}`}
    >
      <table className="data-table">
        {caption ? <caption className="border-b border-line px-3 py-2 text-left text-[0.8125rem] text-ink-3">{caption}</caption> : null}
        <thead>
          <tr>
            {head.map((name) => (
              <th key={name} scope="col">
                {name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={rowIndex}>
              {row.map((cell, index) => (
                <td key={index} className="min-w-[7rem] text-ink-2 first:min-w-[9rem] first:text-ink">
                  <Cell text={cell} severity={index === severityColumn} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ArrowLink({ to, children }: { to: string; children: string }) {
  return (
    <Link to={to} className="link inline-flex items-center gap-1.5 font-semibold">
      {children}
      <Icon name="arrowRight" size={14} />
    </Link>
  );
}

const PROSE = "max-w-[70ch]";

export function BlockView({ block }: { block: Block }) {
  const docPath = useDocPath();
  switch (block.kind) {
    case "p":
      return (
        <p className={PROSE}>
          <Inline text={block.text} />
        </p>
      );
    case "list":
      return (
        <ul className={cx(PROSE, "list-disc space-y-1.5 pl-5 marker:text-ink-3")}>
          {block.items.map((item) => (
            <li key={item}>
              <Inline text={item} />
            </li>
          ))}
        </ul>
      );
    case "steps":
      return (
        <ol className={cx(PROSE, "space-y-2.5")}>
          {block.items.map((item, index) => (
            <li key={item} className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-3">
              <span
                className="flex size-7 items-center justify-center rounded-full border border-line bg-surface text-[0.8125rem] font-semibold text-accent-text"
                aria-hidden="true"
              >
                {index + 1}
              </span>
              <span className="pt-0.5">
                <Inline text={item} />
              </span>
            </li>
          ))}
        </ol>
      );
    case "code":
      return <Command command={block.code} label={block.label} />;
    case "table":
      return <DocTable head={block.head} rows={block.rows} caption={block.caption} />;
    case "note":
      return (
        <aside
          aria-label={block.tone === "caution" ? "Caution" : "Note"}
          className={cx(
            PROSE,
            "flex gap-3 rounded-xl border border-line border-l-[3px] bg-inset/60 px-4 py-3",
            block.tone === "caution" ? "border-l-med-mark" : "border-l-accent",
          )}
        >
          <Icon name={block.tone === "caution" ? "alert" : "info"} size={18} className={cx("mt-0.5 flex-none", block.tone === "caution" ? "text-med" : "text-accent-text")} />
          <p className="text-ink">
            <Inline text={block.text} />
          </p>
        </aside>
      );
    case "diagram":
      return <DiagramView diagram={block.diagram} />;
    case "tools":
      return (
        <ul className={cx(PROSE, "space-y-2.5")}>
          {tools.map((tool) => (
            <li key={tool.page} className="flex gap-3">
              <Icon name={tool.icon} size={18} className="mt-0.5 flex-none text-accent-text" />
              <span>
                <Link to={docPath(TOOL_DOC_PATH[tool.page])} className="link font-semibold">
                  {tool.name}
                </Link>
                : {tool.summary}
              </span>
            </li>
          ))}
        </ul>
      );
    case "guide":
      return <ToolGuide tool={block.tool} compact />;
    case "pages":
      return (
        <ul className="divide-y divide-line overflow-hidden rounded-xl border border-line">
          {block.paths.map((path) => {
            const page = pageAt(path);
            if (!page) return null;
            return (
              <li key={path}>
                <Link to={docPath(path)} className="group flex items-center justify-between gap-4 px-4 py-3 hover:bg-inset">
                  <span className="min-w-0">
                    <span className="block font-semibold text-accent-text group-hover:underline">{page.title}</span>
                    <span className="block text-[0.875rem] text-ink-2">{page.summary}</span>
                  </span>
                  <Icon name="arrowRight" size={16} className="flex-none text-ink-3" />
                </Link>
              </li>
            );
          })}
        </ul>
      );
    case "see":
      return (
        <p>
          <ArrowLink to={docPath(block.to)}>{block.text}</ArrowLink>
        </p>
      );
    case "route":
      return (
        <p>
          <ArrowLink to={block.to}>{block.text}</ArrowLink>
        </p>
      );
    case "landing":
      return (
        <p>
          <ArrowLink to={landingPath()}>{block.text}</ArrowLink>
        </p>
      );
  }
}
