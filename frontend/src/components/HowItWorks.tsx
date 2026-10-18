// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, useState } from "react";
import { Icon } from "./Icon";
import { cx } from "./ui";

export interface HowItWorksContent {
  /** Stable key for remembering whether the panel is open, such as "mail". */
  id: string;
  /** The module name, used in the panel title: "How <name> works". */
  name: string;
  purpose: string;
  steps: string[];
  usefulWhen: string[];
  doesNot: string[];
}

const PREFIX = "kestrix-how-";

function readOpen(id: string): boolean {
  try {
    return localStorage.getItem(PREFIX + id) !== "closed";
  } catch {
    return true;
  }
}

function writeOpen(id: string, open: boolean): void {
  try {
    localStorage.setItem(PREFIX + id, open ? "open" : "closed");
  } catch {
    // Storage can be unavailable (private mode); the panel still toggles for this visit.
  }
}

/**
 * Collapsible explainer at the top of a module page: what it is for, how it works, when it
 * helps and what it does not do. Open on the first visit; the choice is remembered per page.
 */
export function HowItWorks({ content }: { content: HowItWorksContent }) {
  const [open, setOpen] = useState(() => readOpen(content.id));
  const bodyId = useId();

  function toggle() {
    const next = !open;
    writeOpen(content.id, next);
    setOpen(next);
  }

  return (
    <section className="glass mb-8">
      <h2 className="m-0">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={toggle}
          className="flex min-h-14 w-full items-center gap-3 rounded-[inherit] px-4 py-3 text-left sm:px-5"
        >
          <span className="flex size-8 flex-none items-center justify-center rounded-lg bg-accent-soft text-accent-text">
            <Icon name="sparkle" size={17} />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block text-base font-semibold text-ink">How {content.name} works</span>
            <span className="block text-[0.8125rem] font-normal text-ink-2">
              {open ? "What it's for, the steps, and its limits" : "Show what it's for, the steps, and its limits"}
            </span>
          </span>
          <Icon
            name="chevronDown"
            size={18}
            className={cx("flex-none text-ink-3 transition-transform duration-200", open ? "rotate-180" : "")}
          />
        </button>
      </h2>
      <div id={bodyId} hidden={!open} className="border-t border-line px-4 pt-5 pb-6 sm:px-5">
        <p className="max-w-[72ch] text-[0.9375rem] text-ink">{content.purpose}</p>
        <div className="mt-5 grid gap-6 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <div>
            <h3 className="eyebrow">How it works</h3>
            <ol className="mt-3 space-y-3">
              {content.steps.map((step, index) => (
                <li key={step} className="flex gap-3">
                  <span className="step-dot" aria-hidden="true">
                    {index + 1}
                  </span>
                  <span className="pt-0.5 text-ink-2">{step}</span>
                </li>
              ))}
            </ol>
          </div>
          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-1">
            <div>
              <h3 className="eyebrow">When it's useful</h3>
              <ul className="mt-3 space-y-2">
                {content.usefulWhen.map((item) => (
                  <li key={item} className="flex gap-2 text-ink-2">
                    <Icon name="check" size={16} className="mt-1 flex-none text-ok" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="eyebrow">What it does not do</h3>
              <ul className="mt-3 space-y-2">
                {content.doesNot.map((item) => (
                  <li key={item} className="flex gap-2 text-ink-2">
                    <Icon name="minus" size={16} className="mt-1 flex-none text-ink-3" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
