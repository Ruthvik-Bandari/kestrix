// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, type ReactNode } from "react";
import type { ToolPage } from "../../app/tools";
import { Icon } from "../../components/Icon";
import { cx } from "../../components/ui";
import { PYPI_PENDING, toolContent } from "./content";
import { examples } from "./examples";
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

/**
 * How to install and run one tool yourself, as a short checklist: requirements, the install command,
 * a check that it worked, then the steps; a real example output and troubleshooting close it.
 * The tool's guide page puts the checklist at reading width with the example output beside it from
 * 1280px up; its docs page nests it (`compact`, h3 headings, one column) under one section.
 */
export function ToolGuide({ tool, compact = false }: { tool: ToolPage; compact?: boolean }) {
  const guide = toolContent[tool].local;
  const setup = (
    <>
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
        <p className="mb-2 text-[0.8125rem] text-ink-3">{PYPI_PENDING}</p>
        <div className="space-y-2">
          {guide.install.map((item) => (
            <div key={item.command}>
              <Command command={item.command} />
              {item.note ? <p className="mt-1 text-[0.8125rem] text-ink-3">{item.note}</p> : null}
            </div>
          ))}
        </div>
      </Section>

      <Section title="Check it works" compact={compact}>
        <Command command={guide.verify.command} />
        <p className="mt-1 text-[0.8125rem] text-ink-3">{guide.verify.detail}</p>
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
    </>
  );

  const example = (
    <Section title="Example output" compact={compact}>
      <ExampleOutput example={examples[tool]} />
    </Section>
  );

  const troubleshooting = (
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
  );

  const text = "text-[0.9375rem] leading-relaxed text-ink-2";
  if (compact) {
    return (
      <div className={cx("max-w-[68ch]", text)}>
        {setup}
        {example}
        {troubleshooting}
      </div>
    );
  }
  return (
    <div className={cx("grid items-start gap-x-10 gap-y-10", "xl:grid-cols-[minmax(0,38rem)_minmax(0,1fr)]", text)}>
      <div className="min-w-0 max-w-[68ch]">{setup}</div>
      <div className="min-w-0 xl:sticky xl:top-6 xl:row-span-2 xl:col-start-2 xl:row-start-1">{example}</div>
      <div className="min-w-0 max-w-[68ch] xl:col-start-1">{troubleshooting}</div>
    </div>
  );
}
