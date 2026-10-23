// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { Link } from "react-router";
import { scrollBehavior } from "../lib/motion";
import type { Chip, OutlineSection, RailCopy } from "../features/tools/frame";
import { Icon } from "./Icon";
import { cx } from "./ui";

/*
 * The shared frame of every tool page ("master page"): the step rail that follows the page's real
 * state, the numbered workspace panel for the input, the report outline shown before a result and
 * the jump list shown after one. Presentation only: stage and counts come from the page.
 */

/** The id of the element that holds a tool's report, which the jump list reads, and of the workspace it links back to. */
export const REPORT_ID = "tool-report";
export const WORKSPACE_ID = "tool-workspace";

// Stage -------------------------------------------------------------------------

/** Where a tool page is: nothing entered, input ready to run, running, a result, or a failed run. */
export type ToolStage = "input" | "ready" | "running" | "result" | "error";

export function stageOf({ ready, pending, failed, done }: { ready: boolean; pending: boolean; failed: boolean; done: boolean }): ToolStage {
  if (pending) return "running";
  if (failed) return "error";
  if (done) return "result";
  return ready ? "ready" : "input";
}

const StageContext = createContext<{ stage: ToolStage; setStage: (stage: ToolStage) => void } | null>(null);

/** Holds the page's stage for the header band; the page's `ToolLayout` reports it. */
export function StageProvider({ children }: { children: ReactNode }) {
  const [stage, setStage] = useState<ToolStage>("input");
  return <StageContext.Provider value={{ stage, setStage }}>{children}</StageContext.Provider>;
}

export function useStage(): ToolStage {
  return useContext(StageContext)?.stage ?? "input";
}

/** Reports a page's stage to its header band. Outside a `StageProvider` it does nothing. */
export function useReportStage(stage: ToolStage): void {
  const setStage = useContext(StageContext)?.setStage;
  useEffect(() => {
    setStage?.(stage);
  }, [stage, setStage]);
}

// Step rail ----------------------------------------------------------------------

type StepState = "done" | "current" | "todo";

const states: Record<ToolStage, [StepState, StepState, StepState]> = {
  input: ["current", "todo", "todo"],
  ready: ["current", "todo", "todo"],
  running: ["done", "current", "todo"],
  result: ["done", "done", "current"],
  error: ["current", "todo", "todo"],
};

function hints(stage: ToolStage, copy: RailCopy): [string, string, string] {
  return [
    stage === "ready"
      ? "Ready: run it when you are"
      : stage === "error"
        ? "The check failed. Your input is still filled in."
        : stage === "running" || stage === "result"
          ? "Input received"
          : copy.input,
    stage === "running" ? "Checking…" : stage === "result" ? "The report is ready" : copy.evidence,
    stage === "result" ? "Your call, with the evidence in the report" : copy.decide,
  ];
}

const titles = ["Add the input", "Read the evidence", "Decide"] as const;

const stateText: Record<StepState, string> = { done: "done", current: "current step", todo: "not started" };

function Segment({ index, state, title, hint }: { index: number; state: StepState; title: string; hint?: string | undefined }) {
  return (
    <li aria-current={state === "current" ? "step" : undefined} className="min-w-0">
      <span
        className={cx(
          "block h-1 rounded-full transition-colors duration-200 motion-reduce:transition-none",
          state === "todo" ? "bg-line" : "bg-accent",
        )}
        aria-hidden="true"
      />
      <p className="mt-2.5 flex items-center gap-2">
        <span
          className={cx(
            "flex size-6 flex-none items-center justify-center rounded-full text-[0.75rem] font-semibold transition-colors duration-200 motion-reduce:transition-none",
            state === "done" && "bg-accent text-on-accent",
            state === "current" && "border-2 border-accent bg-accent-soft text-accent-text",
            state === "todo" && "border border-line-strong text-ink-2",
          )}
          aria-hidden="true"
        >
          {state === "done" ? <Icon name="check" size={13} /> : index + 1}
        </span>
        <span className={cx("min-w-0 text-[0.875rem] leading-tight font-semibold", state === "todo" ? "text-ink-2" : "text-ink")}>
          {title}
          <span className="sr-only"> ({stateText[state]})</span>
        </span>
      </p>
      {hint ? <p className="mt-1 hidden pl-8 text-[0.8125rem] leading-snug text-ink-2 sm:block">{hint}</p> : null}
    </li>
  );
}

/** "1 Add the input, 2 Read the evidence, 3 Decide", with the current step taken from the page's real state. */
export function StepRail({ stage, copy }: { stage: ToolStage; copy: RailCopy }) {
  const state = states[stage];
  const text = hints(stage, copy);
  const current = state.indexOf("current");
  return (
    <div>
      <ol aria-label="Progress" className="grid grid-cols-3 gap-3 sm:gap-5">
        {titles.map((title, index) => (
          <Segment key={title} index={index} state={state[index] ?? "todo"} title={title} hint={text[index]} />
        ))}
      </ol>
      <p className="mt-2 text-[0.8125rem] leading-snug text-ink-2 sm:hidden" aria-hidden="true">
        {text[current] ?? ""}
      </p>
    </div>
  );
}

/** The rail of a guide page: its real sections as three steps, each a link to that section. */
export function GuideRail({ steps }: { steps: { title: string; hint: string; href: string }[] }) {
  return (
    <ol aria-label="Steps" className="grid grid-cols-3 gap-3 sm:gap-5">
      {steps.map((step, index) => (
        <li key={step.href} className="min-w-0">
          <span className="block h-1 rounded-full bg-accent" aria-hidden="true" />
          <a href={step.href} className="group mt-2.5 block rounded-md">
            <span className="flex items-center gap-2">
              <span
                className="flex size-6 flex-none items-center justify-center rounded-full border-2 border-accent bg-accent-soft text-[0.75rem] font-semibold text-accent-text"
                aria-hidden="true"
              >
                {index + 1}
              </span>
              <span className="min-w-0 text-[0.875rem] leading-tight font-semibold text-ink group-hover:underline">{step.title}</span>
            </span>
            <span className="mt-1 hidden pl-8 text-[0.8125rem] leading-snug text-ink-2 sm:block">{step.hint}</span>
          </a>
        </li>
      ))}
    </ol>
  );
}

// Chips ----------------------------------------------------------------------------

export function Chips({ chips }: { chips: Chip[] }) {
  return (
    <ul className="flex flex-wrap gap-2" aria-label="What this tool does and does not do">
      {chips.map((chip) => {
        const body = (
          <>
            <Icon name={chip.icon} size={14} className="flex-none text-accent-text" />
            {chip.text}
          </>
        );
        const cls = "tap inline-flex min-h-7 items-center gap-1.5 rounded-md border border-line bg-surface-solid px-2.5 py-1 text-[0.8125rem] leading-tight text-ink";
        return (
          <li key={chip.text}>
            {chip.to ? (
              <Link to={chip.to} className={cx(cls, "underline decoration-line-strong underline-offset-2 hover:bg-inset")}>
                {body}
              </Link>
            ) : (
              <span className={cls}>{body}</span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

// Workspace --------------------------------------------------------------------------

export interface WorkStep {
  key: string;
  title: string;
  /** Marks a step that can be skipped. */
  optional?: boolean;
  /** Sets the step apart as the one that runs the check. */
  run?: boolean;
  children: ReactNode;
}

/** The input panel: a labelled workspace whose sections (input, options, consent, run) are numbered. */
export function Workspace({ steps, label = "Workspace" }: { steps: WorkStep[]; label?: string }) {
  return (
    <section id={WORKSPACE_ID} aria-label={label} className="panel scroll-mt-6 overflow-hidden">
      <div className="flex items-center gap-2 border-b border-line bg-inset px-4 py-2 sm:px-5">
        <Icon name="sliders" size={15} className="text-ink-2" />
        <p className="text-[0.75rem] font-semibold tracking-[0.1em] text-ink-2 uppercase">{label}</p>
      </div>
      <ol>
        {steps.map((step, index) => (
          <li key={step.key} className={cx("border-line px-4 py-4 sm:px-5", index > 0 && "border-t", step.run && "bg-inset/60")}>
            <div className="mb-3 flex items-center gap-2.5">
              <span
                className="flex size-6 flex-none items-center justify-center rounded-md bg-ink font-mono text-[0.75rem] font-medium text-bg"
                aria-hidden="true"
              >
                {index + 1}
              </span>
              <h2 className="text-[0.9375rem] font-semibold text-ink">{step.title}</h2>
              {step.optional ? <span className="text-[0.8125rem] text-ink-2">optional</span> : null}
            </div>
            <div className="space-y-3">{step.children}</div>
          </li>
        ))}
      </ol>
    </section>
  );
}

// Outline and jump list ---------------------------------------------------------------------

/**
 * Before a result: the report's sections as a dashed wireframe, headings and one line each, with no
 * sample values; the page's own help (how to prepare the input, what to know) follows underneath.
 */
export function ReportOutline({ sections, children }: { sections: OutlineSection[]; children?: ReactNode }) {
  return (
    <div className="space-y-6">
      <section aria-labelledby="outline-title">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h2 id="outline-title" className="text-lg font-semibold tracking-[-0.01em]">
            What you will get
          </h2>
          <p className="text-[0.8125rem] text-ink-2">The report&apos;s sections, in order. This is an outline, not a result.</p>
        </div>
        <ol className="mt-4 grid gap-3 @3xl:grid-cols-2">
          {sections.map((section, index) => (
            <li
              key={section.title}
              className={cx(
                "flex gap-3 rounded-xl border border-dashed border-line-strong px-4 py-3.5",
                index === 0 && "@3xl:col-span-2 bg-inset/50",
              )}
            >
              <span className="flex size-9 flex-none items-center justify-center rounded-lg border border-line bg-surface-solid text-accent-text" aria-hidden="true">
                <Icon name={section.icon} size={18} />
              </span>
              <div className="min-w-0">
                <h3 className="flex items-baseline gap-2 font-semibold text-ink">
                  <span className="font-mono text-[0.75rem] font-normal text-ink-3" aria-hidden="true">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  {section.title}
                </h3>
                <p className="mt-0.5 max-w-[60ch] text-[0.875rem] text-ink-2">{section.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>
      {children ? <div className="@container border-t border-line pt-6">{children}</div> : null}
    </div>
  );
}


/** The report's sections as one string, "id|label" lines, so the DOM can be read as an external store. */
function readSections(): string {
  const root = document.getElementById(REPORT_ID);
  const nodes = [...(root?.querySelectorAll<HTMLElement>("[data-report-section]") ?? [])].filter((node) => node.id);
  const lines = nodes.map((node) => `${node.id}|${node.dataset.reportSection ?? node.id}`);
  return (document.getElementById(WORKSPACE_ID) ? [...lines, `${WORKSPACE_ID}|Change the input`] : lines).join("\n");
}

function watchReport(onChange: () => void): () => void {
  const root = document.getElementById(REPORT_ID);
  if (!root) return () => undefined;
  const observer = new MutationObserver(onChange);
  observer.observe(root, { childList: true, subtree: true });
  return () => {
    observer.disconnect();
  };
}

/**
 * After a result: links to the report's own sections (every `data-report-section` element with an
 * id inside the report), so the column beside a long report is never empty.
 */
export function JumpList() {
  const snapshot = useSyncExternalStore(watchReport, readSections, () => "");
  const items = snapshot ? snapshot.split("\n").map((line) => ({ id: line.slice(0, line.indexOf("|")), label: line.slice(line.indexOf("|") + 1) })) : [];
  if (items.length < 2) return null;
  return (
    <nav aria-label="In this report" className="panel px-4 py-3.5 sm:px-5">
      <p className="flex items-center gap-2 text-[0.75rem] font-semibold tracking-[0.1em] text-ink-2 uppercase">
        <Icon name="listChecks" size={15} />
        In this report
      </p>
      <ul className="mt-2 space-y-0.5">
        {items.map((item) => (
          <li key={item.id}>
            <a
              href={`#${item.id}`}
              className="tap flex min-h-8 items-center gap-2 rounded-md px-2 text-[0.875rem] text-ink-2 transition-colors duration-150 hover:bg-inset hover:text-ink motion-reduce:transition-none"
              onClick={(event) => {
                const target = document.getElementById(item.id);
                if (!target) return;
                event.preventDefault();
                target.scrollIntoView({ block: "start", behavior: scrollBehavior() });
              }}
            >
              <Icon name="chevronRight" size={14} className="flex-none text-ink-3" />
              {item.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
