// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, type ReactNode } from "react";
import type { ToolPage } from "../../app/tools";
import { Icon, type IconName } from "../../components/Icon";
import { cx } from "../../components/ui";
import { toolContent } from "./content";
import { examples } from "./examples";
import { Command, ExampleOutput, Inline } from "./parts";

function Section({
  title,
  compact,
  icon,
  children,
}: {
  title: string;
  compact: boolean;
  /** The icon tile before the heading on a guide page; the docs nesting has none. */
  icon?: IconName;
  children: ReactNode;
}) {
  const id = useId();
  const Heading = compact ? "h3" : "h2";
  return (
    <section aria-labelledby={id} className={compact ? "mt-6 first:mt-0" : undefined}>
      <div className={cx("flex items-center gap-2.5", compact ? "mb-2" : "mb-3")}>
        {!compact && icon ? (
          <span className="flex size-8 flex-none items-center justify-center rounded-lg border border-line bg-inset text-accent-text" aria-hidden="true">
            <Icon name={icon} size={16} />
          </span>
        ) : null}
        <Heading id={id} className={cx("font-bold tracking-[-0.015em] text-ink", compact ? "text-base" : "text-xl")}>
          {title}
        </Heading>
      </div>
      {children}
    </section>
  );
}

/**
 * How to install and run one tool yourself, as a short checklist: requirements, the install command,
 * a check that it worked, then the steps; a real example output and troubleshooting close it.
 * The tool's guide page lays it out as two columns of one checklist from 1280px up (set it up, then use it,
 * with troubleshooting across the bottom); its docs page nests it (`compact`, h3 headings, one column) under one section.
 */
export function ToolGuide({ tool, compact = false }: { tool: ToolPage; compact?: boolean }) {
  const guide = toolContent[tool].local;
  const setup = (
    <>
      <Section title="Requirements" compact={compact} icon="listChecks">
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

      <Section title="Install" compact={compact} icon="package">
        <div className="space-y-2">
          {guide.install.map((item) => (
            <div key={item.command}>
              <Command command={item.command} />
              {item.note ? <p className="mt-1 text-[0.8125rem] text-ink-3">{item.note}</p> : null}
            </div>
          ))}
        </div>
      </Section>

      <Section title="Check it works" compact={compact} icon="checkCircle">
        <Command command={guide.verify.command} />
        <p className="mt-1 text-[0.8125rem] text-ink-3">{guide.verify.detail}</p>
      </Section>

    </>
  );

  const stepsSection = (
    <>
      <Section title="Step by step" compact={compact} icon="play">
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
    </>
  );

  const example = (
    <Section title="Example output" compact={compact} icon="terminal">
      <ExampleOutput example={examples[tool]} />
    </Section>
  );

  const troubleshooting = (
    <Section title="Troubleshooting" compact={compact} icon="wrench">
      <dl className={cx(compact ? "space-y-3" : "grid gap-3 md:grid-cols-2 xl:grid-cols-1")}>
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
  );

  const text = "text-[0.9375rem] leading-relaxed text-ink-2";
  if (compact) {
    return (
      <div className={cx("max-w-[68ch]", text)}>
        {setup}
        {stepsSection}
        {example}
        {troubleshooting}
      </div>
    );
  }
  // Two columns of one checklist: set it up on the left, use it on the right, troubleshooting across the bottom.
  return (
    <div className={cx("grid items-start gap-6 xl:grid-cols-2", text)}>
      <div id="guide-setup" className="panel min-w-0 scroll-mt-6 divide-y divide-line">
        <div className="space-y-6 p-5 sm:p-6">{setup}</div>
      </div>
      <div id="guide-use" className="min-w-0 scroll-mt-6 space-y-6 xl:col-start-2 xl:row-span-2 xl:row-start-1">
        <div className="panel p-5 sm:p-6">{stepsSection}</div>
        <div className="panel p-5 sm:p-6">{example}</div>
      </div>
      <div id="guide-help" className="panel min-w-0 scroll-mt-6 p-5 sm:p-6 xl:col-start-1">
        {troubleshooting}
      </div>
    </div>
  );
}
