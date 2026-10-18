// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Icon, type IconName } from "../../components/Icon";
import { Reveal } from "../../components/Reveal";
import { severityLabel, severityTone, tones } from "../../components/tone";
import { cx } from "../../components/ui";
import type { Severity } from "../../lib/types";
import { useSide } from "./Compare";

/** One state of a scene: the "device" on the left and the story or the findings on the right. */
export function Pane({ device, aside, wide = false }: { device: ReactNode; aside: ReactNode; wide?: boolean }) {
  const { side } = useSide();
  return (
    <div className={cx("scene-pane h-full", side === "with" ? "scene-pane-with" : "scene-pane-without")}>
      <div
        className={cx(
          "relative grid h-full gap-6 p-4 pt-14 sm:p-6 sm:pt-16 lg:gap-8 lg:p-8 lg:pt-16",
          wide ? "lg:grid-cols-1" : "lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]",
        )}
      >
        <div className="relative min-w-0 lg:sticky lg:top-24 lg:self-start">{device}</div>
        <div className="relative min-w-0">{aside}</div>
      </div>
    </div>
  );
}

/** Numbered marker pinned onto the exact part of a mock that a finding is about. */
export function Pin({ n, severity, className }: { n: number; severity: Severity; className?: string }) {
  const tone = tones[severityTone[severity]];
  return (
    <span
      className={cx(
        "pin inline-flex size-6 flex-none items-center justify-center rounded-full text-[0.75rem] font-bold text-white",
        tone.mark,
        className,
      )}
      aria-hidden="true"
    >
      {n}
    </span>
  );
}

/** Highlight ring for a part of a mock in the Kestrix state; plain in the other state. */
export function Mark({
  on,
  severity = "high",
  pin,
  children,
  className,
}: {
  on: boolean;
  severity?: Severity;
  pin?: number;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span className={cx("relative max-w-full", className ?? "inline-block", on && "xray-mark", on && `xray-${severityTone[severity]}`)}>
      {children}
      {on && pin !== undefined ? <Pin n={pin} severity={severity} className="absolute -top-2.5 -right-2.5 z-10" /> : null}
    </span>
  );
}

export function SeverityChip({ severity }: { severity: Severity }) {
  const tone = tones[severityTone[severity]];
  return (
    <span className={cx("inline-flex flex-none items-center gap-1 rounded-full px-2 py-0.5 text-[0.75rem] font-semibold", tone.soft)}>
      <Icon name={tone.icon} size={12} />
      {severityLabel[severity]}
    </span>
  );
}

export interface ShownFinding {
  id: string;
  severity: Severity;
  title: string;
  detail?: string | null;
  pin?: number;
}

/** Real findings as a list: severity, title, and the evidence or explanation behind each. */
export function FindingList({ findings, label }: { findings: ShownFinding[]; label: string }) {
  return (
    <ul className="glass divide-y divide-line overflow-hidden rounded-2xl" aria-label={label} data-testid="finding-list">
      {findings.map((finding, index) => (
        <li
          key={`${finding.id}-${String(index)}`}
          className="finding-row flex gap-3 px-3.5 py-2.5"
          style={{ animationDelay: `${String(index * 60)}ms` }}
        >
          {finding.pin !== undefined ? <Pin n={finding.pin} severity={finding.severity} className="mt-0.5" /> : null}
          <div className="min-w-0 flex-1">
            <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <SeverityChip severity={finding.severity} />
              <span className="text-[0.875rem] leading-snug font-semibold text-ink" data-finding-title="">
                {finding.title}
              </span>
            </p>
            {finding.detail ? <p className="mt-1 text-[0.8125rem] leading-snug break-words text-ink-2">{finding.detail}</p> : null}
            <code className="mt-0.5 block truncate text-[0.6875rem] text-ink-3">{finding.id}</code>
          </div>
        </li>
      ))}
    </ul>
  );
}

/** The "without" story: what plausibly happens next. A scenario, never a statistic. */
export function Story({ steps, outcome }: { steps: { icon: IconName; text: string }[]; outcome: { title: string; text: string } }) {
  return (
    <div className="flex h-full flex-col gap-4">
      <p className="text-[0.75rem] font-semibold tracking-[0.12em] text-ink-3 uppercase">What happens next · a scenario</p>
      <ol className="story grid gap-3">
        {steps.map((step, index) => (
          <li key={step.text} className="story-step flex gap-3" style={{ animationDelay: `${String(250 + index * 550)}ms` }}>
            <span className="flex size-8 flex-none items-center justify-center rounded-full border border-line-strong bg-surface-solid text-ink-2">
              <Icon name={step.icon} size={15} />
            </span>
            <p className="pt-1 text-[0.9375rem] text-ink-2">{step.text}</p>
          </li>
        ))}
      </ol>
      <div className="outcome-card mt-auto rounded-2xl border border-crit-mark/40 bg-crit-bg p-4" style={{ animationDelay: `${String(250 + steps.length * 550)}ms` }}>
        <p className="flex items-center gap-2 font-bold text-crit">
          <Icon name="octagon" size={17} />
          {outcome.title}
        </p>
        <p className="mt-1 text-[0.9375rem] text-ink">{outcome.text}</p>
      </div>
    </div>
  );
}

/** Big verdict stamp, rotated like ink on paper. */
export function Stamp({ label, sub, tone = "crit" }: { label: string; sub: string; tone?: "crit" | "ok" | "high" }) {
  return (
    <div className={cx("stamp inline-flex w-fit flex-col items-center justify-self-start rounded-xl border-[3px] px-4 py-2 text-center", `stamp-${tone}`)}>
      <span className="text-[1.5rem] leading-none font-black tracking-[0.12em] uppercase sm:text-[1.75rem]">{label}</span>
      <span className="mt-1 text-[0.75rem] font-semibold tracking-[0.06em]">{sub}</span>
    </div>
  );
}

/** "Real output" badge: opens the exact sample JSON the Kestrix state is drawn from. */
export function RealOutput({ name, data, provenance }: { name: string; data: unknown; provenance: string }) {
  return (
    <details className="real-output group mt-4">
      <summary className="inline-flex min-h-10 cursor-pointer list-none items-center gap-2 rounded-full border border-line-strong bg-surface px-3.5 text-[0.8125rem] font-semibold text-ink backdrop-blur-md hover:border-h2 [&::-webkit-details-marker]:hidden">
        <span className="size-2 rounded-full bg-[conic-gradient(var(--h1),var(--h2),var(--h3),var(--h4),var(--h1))]" aria-hidden="true" />
        Real output
        <code className="text-[0.75rem] text-ink-3">samples/{name}.json</code>
        <Icon name="chevronDown" size={14} className="text-ink-3 transition-transform group-open:rotate-180" />
      </summary>
      <div className="glass mt-3 rounded-2xl p-4">
        <p className="text-[0.875rem] text-ink-2">{provenance}</p>
        <pre
          className="mt-3 max-h-80 overflow-auto rounded-xl border border-line bg-inset p-3 text-[0.75rem] leading-relaxed whitespace-pre text-ink"
          tabIndex={0}
          role="region"
          aria-label={`${name}.json`}
        >
          <code>{JSON.stringify(data, null, 2)}</code>
        </pre>
      </div>
    </details>
  );
}

/** A chapter of the story: number, headline, lede, the comparison, and its real output. */
export function Chapter({
  id,
  number,
  kicker,
  title,
  lede,
  children,
  footer,
}: {
  id: string;
  number: string;
  kicker: string;
  title: string;
  lede: string;
  children: ReactNode;
  footer: ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="chapter relative mx-auto max-w-[80rem] scroll-mt-20 px-4 py-20 sm:px-6 lg:py-28">
      <Reveal className="relative mb-8 grid gap-4 lg:mb-12 lg:grid-cols-[auto_minmax(0,1fr)] lg:items-end lg:gap-10">
        <span className="chapter-number display select-none" aria-hidden="true">
          {number}
        </span>
        <div>
          <p className="eyebrow">{kicker}</p>
          <h2 id={id} tabIndex={-1} className="display mt-2 text-[clamp(2.25rem,6vw,4.5rem)] outline-none">
            {title}
          </h2>
          <p className="mt-4 max-w-[62ch] text-lg text-ink-2">{lede}</p>
        </div>
      </Reveal>
      <Reveal delay={80}>
        <div className="stage-glow relative">{children}</div>
      </Reveal>
      {footer}
    </section>
  );
}

/** A cursor that drifts onto its target and double-clicks it. Decorative; never under reduced motion. */
export function FakeCursor() {
  return (
    <span className="fake-cursor pointer-events-none absolute top-1/2 left-1/2 z-20" aria-hidden="true" data-testid="fake-cursor">
      <span className="fake-cursor-ring" />
      <svg width="22" height="22" viewBox="0 0 24 24" className="drop-shadow-[0_2px_4px_oklch(0_0_0/0.35)]">
        <path d="M4 2.5v17l4.6-4.3 3 6.6 2.8-1.3-3-6.4h6.3L4 2.5Z" fill="white" stroke="black" strokeWidth="1.3" strokeLinejoin="round" />
      </svg>
    </span>
  );
}
