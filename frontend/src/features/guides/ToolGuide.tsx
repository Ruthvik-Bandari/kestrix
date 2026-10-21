// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, type ReactNode } from "react";
import { Link } from "react-router";
import { dashboardPath } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { cx } from "../../components/ui";
import { guides, type GuideTool } from "./guides";
import { Command, ExampleOutput, Inline } from "./parts";

function Section({
  title,
  compact,
  children,
}: {
  title: string;
  compact: boolean;
  children: ReactNode;
}) {
  const id = useId();
  const Heading = compact ? "h3" : "h2";
  return (
    <section aria-labelledby={id} className={compact ? "mt-6 first:mt-0" : "mt-10 first:mt-0"}>
      <Heading
        id={id}
        className={cx("font-bold tracking-[-0.015em] text-ink", compact ? "mb-2 text-base" : "mb-3 text-xl")}
      >
        {title}
      </Heading>
      {children}
    </section>
  );
}

/** The command-line guide for one tool, in a fixed order: what, requirements, install, steps, example, troubleshooting, docs. */
export function ToolGuide({ tool, compact = false }: { tool: GuideTool; compact?: boolean }) {
  const guide = guides[tool];
  return (
    <div className="max-w-[72ch] text-[0.9375rem] leading-relaxed text-ink-2">
      <Section title="What it is and how it helps" compact={compact}>
        <p className="text-ink">{guide.summary}</p>
        <p className="mt-3 flex gap-2.5 rounded-xl bg-accent-soft px-3.5 py-3 text-ink">
          <Icon name="shield" size={18} className="mt-0.5 flex-none text-accent-text" />
          <span>{guide.protects}</span>
        </p>
        <ul className="mt-3 list-disc space-y-1.5 pl-5">
          {guide.helps.map((item) => (
            <li key={item}>
              <Inline text={item} />
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Requirements" compact={compact}>
        <ul className="space-y-1.5">
          {guide.requirements.map((item) => (
            <li key={item} className="flex gap-2">
              <Icon name="check" size={16} className="mt-1 flex-none text-ok" />
              <span>
                <Inline text={item} />
              </span>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Install" compact={compact}>
        <div className="space-y-2">
          {guide.install.map((item) => (
            <div key={item.command}>
              <Command command={item.command} />
              {item.note ? <p className="mt-1 text-[0.8125rem] text-ink-3">{item.note}</p> : null}
            </div>
          ))}
        </div>
      </Section>

      <Section title="Step by step" compact={compact}>
        <ol className="space-y-4">
          {guide.steps.map((step, index) => (
            <li key={step.title} className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-3">
              <span
                className="flex size-7 items-center justify-center rounded-full border border-line bg-surface text-[0.8125rem] font-semibold text-accent-text"
                aria-hidden="true"
              >
                {index + 1}
              </span>
              <div className="min-w-0 pt-0.5">
                <p className="font-medium text-ink">{step.title}</p>
                {step.detail ? (
                  <p className="mt-0.5">
                    <Inline text={step.detail} />
                  </p>
                ) : null}
                {step.command ? (
                  <div className="mt-2">
                    <Command command={step.command} />
                  </div>
                ) : null}
              </div>
            </li>
          ))}
        </ol>
      </Section>

      <Section title="Example output" compact={compact}>
        <ExampleOutput example={guide.example} />
      </Section>

      <Section title="Troubleshooting" compact={compact}>
        <dl className="space-y-3">
          {guide.troubleshooting.map((item) => (
            <div key={item.problem} className="rounded-xl border border-line px-3.5 py-3">
              <dt className="font-medium text-ink">
                <Inline text={item.problem} />
              </dt>
              <dd className="mt-1">
                <Inline text={item.fix} />
              </dd>
            </div>
          ))}
        </dl>
      </Section>

      <p className={compact ? "mt-6" : "mt-10"}>
        <Link to={dashboardPath(`docs/${guide.docsSlug}`)} className="link inline-flex items-center gap-1.5 font-semibold">
          <Icon name="bookOpen" size={16} />
          Read the full {guide.name} documentation
          <Icon name="arrowRight" size={14} />
        </Link>
      </p>
    </div>
  );
}
