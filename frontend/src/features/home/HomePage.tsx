// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Link } from "react-router";
import { dashboardPath } from "../../app/paths";
import { availabilityHint, toolFor, toolGroups } from "../../app/tools";
import { Icon, type IconName } from "../../components/Icon";
import { Badge, ErrorState, Skeleton } from "../../components/ui";
import { plural } from "../../lib/format";
import { isHosted } from "../../lib/mode";
import { useHistory } from "../../lib/queries";
import { useTitle } from "../../lib/useTitle";
import { savedAt, toolMeta, verdictChip } from "../history/meta";

const RECENT_SHOWN = 5;

function TaskRow({
  icon,
  title,
  detail,
  children,
}: {
  icon: IconName;
  title: string;
  detail: string;
  children: ReactNode;
}) {
  return (
    <li className="flex flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:gap-4 sm:px-5">
      <span className="flex min-w-0 flex-1 items-center gap-4">
        <span className="launcher-icon flex size-11 flex-none items-center justify-center rounded-lg">
          <Icon name={icon} size={22} className="text-accent-text" />
        </span>
        <span className="min-w-0">
          <span className="block text-[1.0625rem] font-semibold text-ink">
            {title}
          </span>
          <span className="block text-[0.9375rem] text-ink-2">{detail}</span>
        </span>
      </span>
      <span className="flex flex-none flex-wrap gap-2">{children}</span>
    </li>
  );
}

function Tasks() {
  return (
    <section aria-labelledby="tasks-title" className="panel">
      <h2
        id="tasks-title"
        className="border-b border-line px-4 py-3 text-base font-semibold sm:px-5"
      >
        Start a check
      </h2>
      <ul className="divide-y divide-line">
        <TaskRow
          icon="mailWarning"
          title="Check an email"
          detail="Choose a saved .eml file. It is read, never opened or run."
        >
          <Link to={dashboardPath("mail")} className="btn btn-primary btn-sm">
            Choose an .eml file
            <Icon name="arrowRight" size={15} />
          </Link>
        </TaskRow>
        <TaskRow
          icon="globeLock"
          title="Review a website"
          detail="Enter an address to grade its HTTPS, certificate, headers and cookies."
        >
          <Link
            to={dashboardPath("webcheck")}
            className="btn btn-primary btn-sm"
          >
            Enter an address
            <Icon name="arrowRight" size={15} />
          </Link>
        </TaskRow>
        <TaskRow
          icon="fileSearch"
          title="Inspect a file or link"
          detail="See what a file really is, or whether a link shows phishing signs, without opening either."
        >
          <Link
            to={dashboardPath("forensics")}
            className="btn btn-secondary btn-sm"
          >
            <Icon name="upload" size={15} />
            Inspect a file
          </Link>
          <Link
            to={dashboardPath("forensics?tab=url")}
            className="btn btn-secondary btn-sm"
          >
            <Icon name="globe" size={15} />
            Inspect a link
          </Link>
        </TaskRow>
      </ul>
    </section>
  );
}

function RecentResults() {
  const history = useHistory();
  const data = history.data;
  return (
    <section aria-labelledby="recent-title">
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <h2
          id="recent-title"
          className="text-xl font-semibold tracking-[-0.015em]"
        >
          Recent results
        </h2>
        {data && data.enabled && data.total > 0 ? (
          <Link to={dashboardPath("history")} className="link text-[0.9375rem]">
            View all ({data.total})
          </Link>
        ) : null}
      </div>
      {history.isPending ? (
        <div
          className="panel space-y-3 p-4"
          role="status"
          aria-label="Loading recent results"
        >
          <Skeleton className="h-6 w-full" />
          <Skeleton className="h-6 w-full" />
          <Skeleton className="h-6 w-2/3" />
        </div>
      ) : history.isError ? (
        <ErrorState error={history.error}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => {
              void history.refetch();
            }}
          >
            Try again
          </button>
        </ErrorState>
      ) : !data ? null : !data.enabled ? (
        <div className="panel px-5 py-5">
          <p className="font-semibold text-ink">History is off</p>
          <p className="mt-1 max-w-[65ch] text-ink-2">
            New results are not saved, so nothing is listed here.
          </p>
          <Link
            to={dashboardPath("settings")}
            className="btn btn-secondary btn-sm mt-4"
          >
            <Icon name="settings" size={15} />
            Turn it on in Settings
          </Link>
        </div>
      ) : data.items.length === 0 ? (
        <div className="panel px-5 py-5">
          <p className="font-semibold text-ink">No saved results yet</p>
          <p className="mt-1 max-w-[65ch] text-ink-2">
            Run a check and its report is saved here for {data.retention_days}{" "}
            days.
          </p>
          <Link
            to={dashboardPath("mail")}
            className="btn btn-primary btn-sm mt-4"
          >
            Check an email
            <Icon name="arrowRight" size={15} />
          </Link>
        </div>
      ) : (
        <div className="panel overflow-x-auto px-4 py-1 sm:px-5">
          <table className="data-table max-sm:block">
            <caption className="sr-only">
              Your {Math.min(data.items.length, RECENT_SHOWN)} most recent saved
              results, newest first
            </caption>
            <thead className="max-sm:sr-only">
              <tr>
                <th scope="col" className="!pl-0">
                  Tool
                </th>
                <th scope="col">Result</th>
                <th scope="col">Findings</th>
                <th scope="col" className="!pr-0">
                  Time
                </th>
              </tr>
            </thead>
            <tbody className="max-sm:block">
              {data.items.slice(0, RECENT_SHOWN).map((item) => {
                const meta = toolMeta[item.tool];
                const chip = verdictChip(item);
                const when = savedAt(item.created_at);
                return (
                  <tr
                    key={item.id}
                    className="max-sm:grid max-sm:grid-cols-[1fr_auto] max-sm:items-center max-sm:gap-x-3 max-sm:gap-y-1 max-sm:border-b max-sm:border-line max-sm:py-3 max-sm:last:border-b-0"
                  >
                    <td className="!pl-0 max-sm:!border-0 max-sm:!p-0">
                      <Link
                        to={dashboardPath(
                          `history/${encodeURIComponent(item.id)}`,
                        )}
                        className="inline-flex items-center gap-2 font-semibold text-accent-text underline-offset-4 hover:underline"
                      >
                        <Icon name={meta.icon} size={16} />
                        {meta.name}
                      </Link>
                    </td>
                    <td className="max-sm:!border-0 max-sm:!p-0 max-sm:justify-self-end">
                      <Badge tone={chip.tone}>{chip.label}</Badge>
                    </td>
                    <td className="text-ink-2 max-sm:!border-0 max-sm:!p-0">
                      {plural(item.findings, "finding")}
                    </td>
                    <td className="!pr-0 text-ink-2 max-sm:!border-0 max-sm:!p-0 max-sm:justify-self-end">
                      <time dateTime={when.iso}>{when.text}</time>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Where the checks run: mode-specific, and only what the product does. */
function WhereChecksRun() {
  const hosted = isHosted();
  return (
    <section
      aria-labelledby="where-title"
      className="border-t-2 border-accent pt-4"
    >
      <Icon
        name={hosted ? "globe" : "monitor"}
        size={22}
        className="text-accent-text"
      />
      <h2 id="where-title" className="mt-3 text-lg leading-snug font-semibold">
        {hosted
          ? "Checks run on Kestrix's server"
          : "Checks run on this computer"}
      </h2>
      <p className="mt-2 text-[0.9375rem] text-ink-2">
        {hosted
          ? "Uploaded files and emails are analysed and never stored. Website checks contact the site you enter. Reports are kept for 30 days, encrypted."
          : "Email, file and link checks stay on this machine. Website checks contact the site you enter. Reports are kept here for 30 days by default."}
      </p>
      <Link
        to={dashboardPath("docs")}
        className="link mt-3 inline-flex items-center gap-1.5 text-[0.9375rem] font-medium"
      >
        Read the docs
        <Icon name="arrowRight" size={14} />
      </Link>
    </section>
  );
}

/** Advanced and developer tools, quieter than the everyday checks. */
function OtherTools() {
  const groups = toolGroups.filter((group) => group.title !== "Checks");
  return (
    <section aria-labelledby="other-title">
      <h2 id="other-title" className="mb-2 text-base font-semibold text-ink-2">
        Advanced and developer tools
      </h2>
      <div className="space-y-4">
        {groups.map((group) => (
          <div key={group.title}>
            <p className="px-1 text-[0.6875rem] font-semibold tracking-[0.08em] text-ink-3 uppercase">
              {group.title}
            </p>
            <ul className="mt-1 divide-y divide-line border-y border-line">
              {group.pages.map((page) => {
                const tool = toolFor(page);
                return (
                  <li key={page}>
                    <Link
                      to={dashboardPath(page)}
                      className="flex min-h-11 items-center gap-3 rounded-md px-1 py-2 hover:bg-inset"
                    >
                      <Icon
                        name={tool.icon}
                        size={17}
                        className="flex-none text-ink-3"
                      />
                      <span className="min-w-0 flex-1 text-[0.9375rem] font-medium text-ink">
                        {tool.name}
                      </span>{" "}
                      <span className="flex-none text-[0.75rem] text-ink-3">
                        {availabilityHint(tool) ?? "Runs here"}
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function HomePage() {
  useTitle("");
  const hosted = isHosted();
  return (
    <>
      <header className="mb-8 max-w-[68ch]">
        <p className="inline-flex items-center gap-2 rounded-md bg-inset px-2.5 py-1 text-[0.8125rem] font-medium text-ink-2">
          <Icon name={hosted ? "globe" : "monitor"} size={14} />
          {hosted
            ? "Hosted workspace"
            : "Local workspace · runs on this computer"}
        </p>
        <h1 className="display mt-3 text-[clamp(1.75rem,3.4vw,2.375rem)] leading-[1.15] text-ink">
          What would you like to check?
        </h1>
        <p className="mt-3 text-base text-ink-2">
          Pick the thing in front of you. Each check explains what it found and
          why.
        </p>
      </header>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-x-10 gap-y-10 xl:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="space-y-10">
          <Tasks />
          <RecentResults />
        </div>
        <div className="space-y-8 xl:pt-1">
          <WhereChecksRun />
          <OtherTools />
        </div>
      </div>
    </>
  );
}
