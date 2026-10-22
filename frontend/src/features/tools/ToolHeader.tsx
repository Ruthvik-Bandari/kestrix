// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Link } from "react-router";
import { dashboardPath } from "../../app/paths";
import { toolFor, type ToolPage } from "../../app/tools";
import { Icon } from "../../components/Icon";
import { Chips, GuideRail, StageProvider, StepRail, useStage } from "../../components/toolframe";
import { Badge } from "../../components/ui";
import { ago } from "../../lib/format";
import { useHistory } from "../../lib/queries";
import { useTitle } from "../../lib/useTitle";
import { TOOL_DOC_PATH } from "../docs/model";
import { savedAt, verdictChip } from "../history/meta";
import { chipsFor, historyToolsFor, railCopy, type FrameKey } from "./frame";

/**
 * The user's own saved reports for this tool: how many and the latest verdict, from the history the
 * server already keeps. Nothing renders while history is off, still loading, failed or has nothing
 * for this tool, so the strip never shows a number that is not real. Only the newest page of results
 * is read, so a long history shows "N+".
 */
export function HistoryStats({ frame }: { frame: FrameKey }) {
  const history = useHistory();
  const data = history.data;
  const kinds = historyToolsFor[frame];
  if (!kinds || !data?.enabled || !Array.isArray(data.items)) return null;
  const mine = data.items.filter((item) => kinds.includes(item.tool));
  const last = mine[0];
  if (!last) return null;
  const chip = verdictChip(last);
  const more = data.total > data.items.length;
  return (
    <aside aria-label="Your saved reports for this tool" className="min-w-0 rounded-xl border border-line bg-surface-solid px-4 py-3 lg:w-[17.5rem]">
      <p className="text-[0.75rem] font-semibold tracking-[0.1em] text-ink-2 uppercase">Your saved reports</p>
      <p className="mt-1 flex items-baseline gap-1.5">
        <span className="num text-2xl leading-none font-semibold text-ink">
          {mine.length.toLocaleString()}
          {more ? "+" : ""}
        </span>
        <span className="text-[0.875rem] text-ink-2">{mine.length === 1 && !more ? "report" : "reports"}</span>
      </p>
      <p className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[0.8125rem] text-ink-2">
        Last:
        <Badge tone={chip.tone}>{chip.label}</Badge>
        <time dateTime={savedAt(last.created_at).iso}>{ago(last.created_at)}</time>
      </p>
      <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[0.8125rem] font-medium">
        <Link to={dashboardPath(`history/${last.id}`)} className="link">
          Open the last report
        </Link>
        <Link to={dashboardPath("history")} className="link">
          All results
        </Link>
      </p>
    </aside>
  );
}

/**
 * A tool page's header band: a large icon tile, the name, one line on what it does with the way to
 * the docs, capability chips (where it runs, limits, what it never does), your own history for the
 * tool and the three-step rail. Live tools pass nothing more: the rail follows the stage their
 * `ToolLayout` reports. Guide pages pass `guide`, whose rail links to the guide's sections.
 */
export function ToolHeader({
  page,
  variant,
  aside,
  guide = false,
}: {
  page: ToolPage;
  /** A page tab with its own wording, such as the link check on the forensics page. */
  variant?: FrameKey;
  /** Extra live status at the right of the band (the detection engine). */
  aside?: ReactNode;
  guide?: boolean;
}) {
  const tool = toolFor(page);
  const frame = variant ?? page;
  const stage = useStage();
  useTitle(tool.name);
  return (
    <header className="mb-6 rounded-xl border border-line bg-inset/50 px-4 py-4 sm:px-6 sm:py-5">
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-start lg:gap-8">
        <div className="flex min-w-0 gap-4 sm:gap-5">
          <span
            className="flex size-12 flex-none items-center justify-center rounded-xl bg-accent text-on-accent sm:size-14"
            aria-hidden="true"
          >
            <Icon name={tool.icon} size={28} className="max-sm:size-6" />
          </span>
          <div className="min-w-0">
            <h1 className="display text-[clamp(1.625rem,3.2vw,2.125rem)] leading-[1.2] text-ink">{tool.name}</h1>
            <p className="mt-2 max-w-[68ch] text-base text-ink-2">
              {tool.summary}{" "}
              <Link to={dashboardPath(`docs/${TOOL_DOC_PATH[page]}`)} className="link inline-flex items-center gap-1 font-medium whitespace-nowrap">
                Read the docs
                <Icon name="arrowRight" size={14} />
              </Link>
            </p>
          </div>
        </div>
        {aside || !guide ? (
          <div className="flex flex-wrap items-start gap-3 lg:justify-end">
            {aside}
            {guide ? null : <HistoryStats frame={frame} />}
          </div>
        ) : null}
      </div>
      <div className="mt-4">
        <Chips chips={chipsFor(frame, guide)} />
      </div>
      <div className="mt-4 border-t border-line pt-3.5">
        {guide ? (
          <GuideRail
            steps={[
              { title: "Set it up", hint: "Requirements, install and a check that it worked", href: "#guide-setup" },
              { title: "Use it", hint: "The steps, with a real example output", href: "#guide-use" },
              { title: "Fix problems", hint: "What the usual errors mean", href: "#guide-help" },
            ]}
          />
        ) : (
          <StepRail stage={stage} copy={railCopy[frame]} />
        )}
      </div>
    </header>
  );
}

/** A live tool page: the header band plus the stage its layout reports, around the page body. */
export function ToolFrame({ page, variant, aside, children }: { page: ToolPage; variant?: FrameKey; aside?: ReactNode; children: ReactNode }) {
  return (
    <StageProvider>
      <ToolHeader page={page} {...(variant ? { variant } : {})} aside={aside} />
      {children}
    </StageProvider>
  );
}
