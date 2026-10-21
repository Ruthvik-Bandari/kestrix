// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../components/Icon";
import { PublicShell } from "../../components/PublicShell";
import { useTitle } from "../../lib/useTitle";
import { DRAFT_BANNER, type LegalDoc } from "./content";

export function LegalPage({ doc }: { doc: LegalDoc }) {
  useTitle(doc.title);
  return (
    <PublicShell width="wide">
      <article className="py-2 sm:py-4">
        <p
          role="note"
          className="flex gap-2.5 rounded-xl bg-med-bg px-4 py-3 font-semibold text-ink shadow-[inset_0_0_0_1px_var(--line)]"
        >
          <Icon name="alert" size={20} className="mt-0.5 flex-none text-med" />
          {DRAFT_BANNER}
        </p>
        <h1 className="display mt-8 text-[clamp(2.25rem,6vw,3.5rem)]">{doc.title}</h1>
        <p className="mt-2 text-[0.875rem] text-ink-3">{doc.updated}</p>
        <div className="mt-6 space-y-4 text-lg text-ink-2">
          {doc.intro.map((text) => (
            <p key={text}>{text}</p>
          ))}
        </div>
        {doc.sections.map((section) => (
          <section key={section.heading} className="mt-10" aria-labelledby={`legal-${slugify(section.heading)}`}>
            <h2 id={`legal-${slugify(section.heading)}`} className="text-xl font-bold tracking-[-0.015em]">
              {section.heading}
            </h2>
            <div className="mt-3 space-y-3 text-ink-2">
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
    </PublicShell>
  );
}

function slugify(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}
