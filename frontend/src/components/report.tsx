// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState, type DragEvent, type ReactNode, type RefObject } from "react";
import { scrollBehavior } from "../lib/motion";
import { formatBytes, plural } from "../lib/format";
import type { Severity } from "../lib/types";
import { FileButton } from "./FileButton";
import { Icon, type IconName } from "./Icon";
import { severityLabel, severityOrder, severityTone, tones, type Tone } from "./tone";
import { JumpList, REPORT_ID, useReportStage, type ToolStage } from "./toolframe";
import { Badge, Button, cx, ErrorState, Spinner, Verdict } from "./ui";

/*
 * Shared pieces of the tool pages (email, website, file and link): the input/report split, the
 * verdict card, the severity tally and filterable finding disclosures, focus handling and the
 * pending, error and file-drop states. Presentation only; every value comes from the report.
 */

/**
 * The tool page body: a 24rem workspace column beside a flexible report column from 1100px up, stacked
 * below with the input first. Once a result is on screen the workspace column adds a jump list to the
 * report's sections under the input; it sticks while the long report scrolls, so the left side is never
 * an empty band. Pass `jump={false}` when the input is itself taller than a screen (a list of cases).
 * `stage` is the page's real state: it drives the step rail in the header band.
 */
export function ToolLayout({
  input,
  children,
  stage,
  jump = true,
}: {
  input: ReactNode;
  children: ReactNode;
  stage: ToolStage;
  jump?: boolean;
}) {
  useReportStage(stage);
  return (
    <div className="grid gap-6 min-[1100px]:grid-cols-[24rem_minmax(0,1fr)] min-[1100px]:gap-8">
      <div className="min-w-0 space-y-4">
        {input}
        {jump && stage === "result" ? (
          <div className="tool-sticky hidden min-[1100px]:block">
            <JumpList />
          </div>
        ) : null}
      </div>
      <div id={REPORT_ID} className="@container min-w-0 space-y-6">
        {children}
      </div>
    </div>
  );
}

/** Screen-reader announcement for a check's progress: polite, not repeated by the result itself. */
export function LiveStatus({ pending, done, pendingText, doneText }: { pending: boolean; done: boolean; pendingText: string; doneText: string }) {
  return (
    <div aria-live="polite" className="sr-only">
      {pending ? pendingText : done ? doneText : ""}
    </div>
  );
}

/** A ref for the result heading; the heading takes focus (and scrolls into view) when the report arrives. */
export function useFocusOnArrival(dep: unknown): RefObject<HTMLHeadingElement | null> {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    ref.current?.focus();
    ref.current?.scrollIntoView({ block: "start", behavior: scrollBehavior() });
  }, [dep]);
  return ref;
}

/** Moves focus to its content when it appears, so an error is announced and reachable. */
export function FocusAlert({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return (
    <div ref={ref} tabIndex={-1} className="rounded-xl outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--focus)">
      {children}
    </div>
  );
}

/** A failed request: what failed, the server's reason, and a retry that reuses the inputs. */
export function FailedRequest({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  return (
    <FocusAlert>
      <ErrorState error={error}>
        <p className="text-[0.875rem]">Your input is still filled in.</p>
        <Button variant="secondary" size="sm" className="mt-3" onClick={onRetry}>
          Try again
        </Button>
      </ErrorState>
    </FocusAlert>
  );
}

/** A problem found before anything is sent (wrong type, too large). */
export function LocalProblem({ title, detail }: { title: string; detail: ReactNode }) {
  return (
    <FocusAlert>
      <div role="alert">
        <Verdict tone="crit" icon="xCircle" title={title}>
          {detail}
        </Verdict>
      </div>
    </FocusAlert>
  );
}

/** Indeterminate progress that says what is happening; no percentage is invented. */
export function PendingPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="panel relative overflow-hidden p-5 pl-6 sm:p-6 sm:pl-7" role="status">
      <span className="absolute inset-y-0 left-0 w-1.5 bg-accent" aria-hidden="true" />
      <p className="flex items-center gap-2 font-semibold text-ink">
        <Spinner />
        {title}
      </p>
      <p className="mt-2 max-w-[68ch] text-ink-2">{children}</p>
      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-inset" aria-hidden="true">
        <div className="h-full w-1/3 animate-pulse rounded-full bg-accent motion-reduce:animate-none" />
      </div>
    </div>
  );
}

/** Help shown beside the input before a result: flat, with the heading and a body at the full column width. */
export function HelpPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-label={title}>
      <h2 className="text-lg font-semibold tracking-[-0.01em]">{title}</h2>
      <div className="@container mt-4">{children}</div>
    </section>
  );
}

/**
 * One section of a report: an icon, the heading, an optional count and aside. By default a panel with a
 * tinted header strip; `flat` leaves the body unframed for sections that bring their own list or table.
 * Sections with an id are listed in the jump list beside the report.
 */
export function ReportSection({
  id,
  icon,
  title,
  count,
  aside,
  level = 3,
  as: Tag = "section",
  flat = false,
  className,
  children,
}: {
  id: string;
  icon: IconName;
  title: ReactNode;
  count?: number | string;
  aside?: ReactNode;
  level?: 2 | 3;
  as?: "section" | "aside";
  flat?: boolean;
  className?: string;
  children: ReactNode;
}) {
  const Heading = level === 2 ? "h2" : "h3";
  const titleId = `${id}-title`;
  return (
    <Tag
      id={id}
      data-report-section={typeof title === "string" ? title : id}
      aria-labelledby={titleId}
      className={cx("scroll-mt-6", flat ? undefined : "panel overflow-hidden", className)}
    >
      <div className={cx("flex items-center gap-x-3", flat ? "mb-3" : "border-b border-line bg-inset/60 px-4 py-2.5 sm:px-5")}>
        <span
          className={cx(
            "flex size-7 flex-none items-center justify-center rounded-md border border-line text-accent-text",
            flat ? "bg-inset" : "bg-surface-solid",
          )}
          aria-hidden="true"
        >
          <Icon name={icon} size={15} />
        </span>
        <Heading id={titleId} className="min-w-0 text-base font-semibold tracking-[-0.01em] text-ink">
          {title}
        </Heading>
        {count !== undefined ? (
          <span className="num rounded-md border border-line bg-surface-solid px-1.5 text-[0.8125rem] font-medium text-ink-2">{count}</span>
        ) : null}
        {aside ? <div className="ml-auto flex-none text-right text-[0.875rem] text-ink-2">{aside}</div> : null}
      </div>
      <div className={flat ? undefined : "p-4 sm:p-5"}>{children}</div>
    </Tag>
  );
}

// File input -------------------------------------------------------------------

/**
 * Drag-and-drop target with a real file button as the keyboard path, the accepted format and
 * limit in the hint, and the chosen file with a remove control.
 */
export function FileDrop({
  icon,
  idleTitle,
  hint,
  chooseLabel,
  chooseAnotherLabel,
  accept,
  file,
  disabled = false,
  onFile,
  onClear,
}: {
  icon: IconName;
  idleTitle: string;
  hint: string;
  chooseLabel: string;
  chooseAnotherLabel: string;
  accept?: string;
  file: { name: string; size: number } | null;
  disabled?: boolean;
  onFile: (file: File) => void;
  onClear: () => void;
}) {
  const [dragging, setDragging] = useState(false);
  function onDrop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files[0];
    if (dropped && !disabled) onFile(dropped);
  }
  return (
    // Drag and drop is a pointer shortcut; the file button inside is the keyboard path.
    // eslint-disable-next-line jsx-a11y/no-static-element-interactions
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => {
        setDragging(false);
      }}
      onDrop={onDrop}
      className={cx(
        "flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-4 py-6 text-center transition-colors duration-150 motion-reduce:transition-none",
        dragging ? "border-accent bg-accent-soft" : "border-line-strong bg-surface",
      )}
    >
      <Icon name={icon} size={26} className="text-ink-3" />
      {file ? (
        <>
          <p className="max-w-full font-medium break-all text-ink">{file.name}</p>
          <p className="hint">{formatBytes(file.size)}</p>
        </>
      ) : (
        <>
          <p className="font-medium text-ink">{idleTitle}</p>
          <p className="hint">{hint}</p>
        </>
      )}
      <div className="mt-1 flex flex-wrap items-center justify-center gap-2">
        {disabled ? null : <FileButton label={file ? chooseAnotherLabel : chooseLabel} {...(accept ? { accept } : {})} onFile={onFile} />}
        {file && !disabled ? (
          <Button variant="ghost" size="sm" onClick={onClear}>
            <Icon name="x" size={15} />
            Remove file
          </Button>
        ) : null}
      </div>
    </div>
  );
}

// Verdict and findings --------------------------------------------------------------

/**
 * The result's opening card: tone, icon and a label that takes focus on arrival (the result
 * heading), a plain-language sentence, then an optional aside (finding tally, score).
 */
export function VerdictCard({
  tone,
  icon,
  lead,
  label,
  headingId,
  headingRef,
  title,
  children,
  aside,
}: {
  tone: Tone;
  icon?: IconName;
  /** Replaces the icon, for example a grade tile. */
  lead?: ReactNode;
  label: ReactNode;
  headingId: string;
  headingRef: RefObject<HTMLHeadingElement | null>;
  title: ReactNode;
  children?: ReactNode;
  aside?: ReactNode;
}) {
  const style = tones[tone];
  return (
    <div
      id={`${headingId}-band`}
      data-report-section="Verdict"
      className={cx("@container relative scroll-mt-6 overflow-hidden rounded-xl border border-line p-5 pl-6 sm:p-6 sm:pl-7", style.soft)}
    >
      <span className={cx("absolute inset-y-0 left-0 w-1.5", style.mark)} aria-hidden="true" />
      <div className="grid gap-5 @[40rem]:grid-cols-[minmax(0,1fr)_16rem] @[40rem]:items-center">
        <div className="flex min-w-0 gap-4">
          {lead ?? <Icon name={icon ?? style.icon} size={28} className="mt-1 flex-none" />}
          <div className="min-w-0 text-ink">
            <p className="mb-0.5 text-[0.75rem] font-semibold tracking-[0.1em] text-ink-2 uppercase">Verdict</p>
            <h2
              id={headingId}
              ref={headingRef}
              tabIndex={-1}
              className={cx("scroll-mt-20 text-2xl leading-tight font-semibold tracking-[-0.015em] break-words outline-none", style.text)}
            >
              {label}
            </h2>
            <p className="mt-1.5 max-w-[62ch] text-base text-ink">{title}</p>
            {children ? <div className="mt-2 max-w-[62ch] text-[0.9375rem] text-ink-2">{children}</div> : null}
          </div>
        </div>
        {aside ? <div className="min-w-0 border-t border-line pt-4 @[40rem]:border-t-0 @[40rem]:border-l @[40rem]:pt-0 @[40rem]:pl-6">{aside}</div> : null}
      </div>
    </div>
  );
}

export function severityCounts(findings: { severity: Severity }[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/** Finding count with a proportional bar and the same numbers as text. */
export function FindingTally({ findings }: { findings: { severity: Severity }[] }) {
  const counts = severityCounts(findings);
  const present = severityOrder.filter((s) => counts[s] > 0);
  if (findings.length === 0) {
    return <p className="text-[0.9375rem] font-medium text-ink">No findings</p>;
  }
  return (
    <div>
      <p className="text-ink">
        <span className="text-3xl font-semibold">{findings.length.toLocaleString()}</span>{" "}
        <span className="text-ink-2">{findings.length === 1 ? "finding" : "findings"}</span>
      </p>
      <div className="mt-2 flex h-2 gap-0.5 overflow-hidden rounded-full" aria-hidden="true">
        {present.map((s) => (
          <span key={s} className={cx("h-full", tones[severityTone[s]].mark)} style={{ flexGrow: counts[s], flexBasis: 0 }} />
        ))}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-0.5 text-[0.8125rem] text-ink-2">
        {present.map((s) => (
          <li key={s}>
            {counts[s].toLocaleString()} {severityLabel[s].toLowerCase()}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Reviewed advice for the verdict. Written presentation copy, not something the server returns. */
export function NextStep({ children }: { children: ReactNode }) {
  return (
    <section
      id="next-step"
      data-report-section="Next step"
      className="relative scroll-mt-6 overflow-hidden rounded-xl border border-line bg-accent-soft px-5 py-4 pl-6"
      aria-label="Suggested next step"
    >
      <span className="absolute inset-y-0 left-0 w-1 bg-accent" aria-hidden="true" />
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="flex items-center gap-2 font-semibold text-ink">
          <Icon name="arrowRight" size={16} className="text-accent-text" />
          Suggested next step
        </h3>
        <span className="text-[0.75rem] text-ink-2">General advice for this result. Nothing has been done for you.</span>
      </div>
      <div className="mt-1.5 max-w-[68ch] text-ink-2">{children}</div>
    </section>
  );
}

/**
 * Findings most severe first, with filter buttons that show the real counts. Each finding is a
 * native details/summary: severity label and icon, then the title; evidence sits inside.
 */
export function FindingList<T extends { severity: Severity; title: string }>({
  findings,
  keyOf,
  renderDetail,
  id,
  heading = "Findings",
}: {
  findings: T[];
  keyOf: (finding: T, index: number) => string;
  renderDetail: (finding: T) => ReactNode;
  id: string;
  heading?: string;
}) {
  const [picked, setPicked] = useState<Severity | "all">("all");
  const counts = severityCounts(findings);
  const present = severityOrder.filter((s) => counts[s] > 0);
  const filter = picked !== "all" && counts[picked] === 0 ? "all" : picked;
  const sorted = [...findings].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
  const shown = filter === "all" ? sorted : sorted.filter((f) => f.severity === filter);
  return (
    <ReportSection
      id={id}
      icon="listChecks"
      title={heading}
      count={findings.length}
      level={2}
      flat
      aside={
        <span aria-live="polite">
          {filter === "all" ? plural(findings.length, "finding") : `Showing ${shown.length.toLocaleString()} of ${plural(findings.length, "finding")}`}
        </span>
      }
    >
      {present.length > 1 ? (
        <div role="group" aria-label="Filter findings by severity" className="mb-3 flex flex-wrap gap-2">
          {(["all", ...present] as const).map((key) => {
            const active = filter === key;
            const count = key === "all" ? findings.length : counts[key];
            return (
              <button
                key={key}
                type="button"
                aria-pressed={active}
                onClick={() => {
                  setPicked(key);
                }}
                className={cx(
                  "inline-flex min-h-11 items-center gap-2 rounded-md border px-3 text-[0.875rem] font-medium transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--focus) motion-reduce:transition-none sm:min-h-9",
                  active ? "border-ink bg-ink text-bg" : "border-line-strong bg-surface-solid text-ink hover:bg-inset",
                )}
              >
                {key === "all" ? "All" : severityLabel[key]}
                <span className={cx("num text-[0.75rem]", active ? "opacity-80" : "text-ink-2")}>{count}</span>
              </button>
            );
          })}
        </div>
      ) : null}
      <ul className="divide-y divide-line overflow-hidden rounded-xl border border-line bg-surface-solid">
        {shown.map((finding, index) => (
          <li key={`${filter}-${keyOf(finding, index)}`} className="relative">
            <span className={cx("absolute inset-y-0 left-0 w-1", tones[severityTone[finding.severity]].mark)} aria-hidden="true" />
            <details className="group" open={index === 0 && filter === "all" && finding.severity !== "info" ? true : undefined}>
              <summary className="flex min-h-11 cursor-pointer list-none items-start gap-3 py-3 pr-4 pl-5 select-none hover:bg-inset focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-(--focus) [&::-webkit-details-marker]:hidden">
                <span className="mt-0.5 flex-none">
                  <Badge tone={severityTone[finding.severity]}>{severityLabel[finding.severity]}</Badge>
                </span>
                <span className="min-w-0 flex-1 pt-0.5 font-medium break-words text-ink">{finding.title}</span>
                <Icon
                  name="chevronDown"
                  size={16}
                  className="mt-1.5 flex-none -rotate-90 text-ink-3 transition-transform duration-150 group-open:rotate-0 motion-reduce:transition-none"
                />
              </summary>
              <div className="space-y-2.5 pr-4 pb-4 pl-5 pt-1 sm:pl-[6.5rem]">{renderDetail(finding)}</div>
            </details>
          </li>
        ))}
      </ul>
    </ReportSection>
  );
}

/** Labelled evidence text in a monospace inset: wraps anywhere, plain text only. */
export function Evidence({ label = "Evidence", children }: { label?: string; children: string }) {
  return (
    <div className="overflow-hidden rounded-md border border-line border-l-2 border-l-line-strong bg-inset">
      <p className="border-b border-line px-3 py-1 font-mono text-[0.6875rem] tracking-[0.06em] text-ink-2 uppercase">{label}</p>
      <code className="block px-3 py-2 text-[0.8125rem] break-all whitespace-pre-wrap text-ink">{children}</code>
    </div>
  );
}

/** Reason code: the stable machine identifier, last and quiet. */
export function ReasonCode({ children }: { children: ReactNode }) {
  return <p className="font-mono text-xs break-all text-ink-3">{children}</p>;
}
