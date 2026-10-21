// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../components/Icon";
import { headingId, OnThisPage } from "../../components/OnThisPage";
import { PublicShell } from "../../components/PublicShell";
import { useTitle } from "../../lib/useTitle";
import { DRAFT_BANNER, type LegalDoc } from "./content";

const sectionId = (heading: string) => headingId("legal", heading);

/** A legal page: the draft banner, the text at reading width, and from 1280px an "On this page" list beside it. */
export function LegalPage({ doc }: { doc: LegalDoc }) {
  useTitle(doc.title);
  const links = doc.sections.map((section) => ({ id: sectionId(section.heading), label: section.heading }));
  return (
    <PublicShell width="article">
      <div className="mx-auto w-fit max-w-full xl:grid xl:grid-cols-[minmax(0,68ch)_11rem] xl:gap-12">
        <article className="max-w-[68ch] min-w-0 py-2 sm:py-4">
          <p
            role="note"
            className="flex gap-2.5 rounded-xl bg-med-bg px-4 py-3 font-semibold text-ink shadow-[inset_0_0_0_1px_var(--line)]"
          >
            <Icon name="alert" size={20} className="mt-0.5 flex-none text-med" />
            {DRAFT_BANNER}
          </p>
          <h1 className="display mt-8 text-[clamp(2rem,5vw,2.75rem)]">{doc.title}</h1>
          <p className="mt-2 text-[0.875rem] text-ink-3">{doc.updated}</p>
          <div className="mt-6 space-y-4 text-[1.0625rem] leading-relaxed text-ink-2">
            {doc.intro.map((text) => (
              <p key={text}>{text}</p>
            ))}
          </div>
          {doc.sections.map((section) => (
            <section key={section.heading} className="mt-10" aria-labelledby={sectionId(section.heading)}>
              <h2 id={sectionId(section.heading)} className="scroll-mt-24 text-xl font-bold tracking-[-0.015em]">
                {section.heading}
              </h2>
              <div className="mt-3 space-y-3 leading-relaxed text-ink-2">
                {section.blocks.map((block, index) =>
                  "p" in block ? (
                    <p key={index}>{block.p}</p>
                  ) : (
                    <ul key={index} className="list-disc space-y-1.5 pl-6 marker:text-ink-3">
                      {block.ul.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  ),
                )}
              </div>
            </section>
          ))}
        </article>
        <OnThisPage items={links} className="xl:top-24 xl:pt-6" />
      </div>
    </PublicShell>
  );
}
