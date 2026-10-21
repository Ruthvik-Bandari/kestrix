// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Link, NavLink, useParams } from "react-router";
import { dashboardPath, landingPath } from "../../app/paths";
import { tools } from "../../app/tools";
import { Icon } from "../../components/Icon";
import { cx, PageHeader } from "../../components/ui";
import { useTitle } from "../../lib/useTitle";
import { Command, Inline } from "../tools/parts";
import { ToolGuide } from "../tools/ToolGuide";
import type { Block } from "./blocks";
import { DOC_GROUPS, docPages, findDoc, type DocPage } from "./content";

function docPath(slug: string): string {
  return dashboardPath(slug ? `docs/${slug}` : "docs");
}

function DocsNav() {
  return (
    <nav aria-label="Documentation" className="lg:sticky lg:top-8">
      {DOC_GROUPS.map((group) => (
        <div key={group} className="mb-4 last:mb-0">
          <p className="mb-1.5 px-2 text-[0.75rem] font-semibold tracking-[0.08em] text-ink-3 uppercase">{group}</p>
          <ul className="flex flex-wrap gap-1.5 lg:block lg:space-y-0.5">
            {docPages
              .filter((page) => page.group === group)
              .map((page) => (
                <li key={page.slug}>
                  <NavLink
                    to={docPath(page.slug)}
                    end
                    className={({ isActive }) =>
                      cx(
                        "flex min-h-9 items-center gap-2 rounded-lg px-2.5 text-[0.875rem] font-medium transition-colors duration-150",
                        "max-lg:border max-lg:border-line",
                        isActive ? "bg-accent-soft text-accent-text" : "text-ink-2 hover:bg-inset hover:text-ink",
                      )
                    }
                  >
                    <Icon name={page.icon} size={16} className="flex-none" />
                    {page.nav}
                  </NavLink>
                </li>
              ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function BlockView({ block }: { block: Block }) {
  switch (block.kind) {
    case "p":
      return (
        <p>
          <Inline text={block.text} />
        </p>
      );
    case "list":
      return (
        <ul className="list-disc space-y-1.5 pl-5 marker:text-ink-3">
          {block.items.map((item) => (
            <li key={item}>
              <Inline text={item} />
            </li>
          ))}
        </ul>
      );
    case "steps":
      return (
        <ol className="space-y-2.5">
          {block.items.map((item, index) => (
            <li key={item} className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-3">
              <span
                className="flex size-7 items-center justify-center rounded-full border border-line bg-surface text-[0.8125rem] font-semibold text-accent-text"
                aria-hidden="true"
              >
                {index + 1}
              </span>
              <span className="pt-0.5">
                <Inline text={item} />
              </span>
            </li>
          ))}
        </ol>
      );
    case "code":
      return <Command command={block.code} label={block.label} />;
    case "tools":
      return (
        <ul className="space-y-2.5">
          {tools.map((tool) => (
            <li key={tool.page} className="flex gap-3">
              <Icon name={tool.icon} size={18} className="mt-0.5 flex-none text-accent-text" />
              <span>
                <Link to={docPath(tool.page)} className="link font-semibold">
                  {tool.name}
                </Link>
                : {tool.summary}
              </span>
            </li>
          ))}
        </ul>
      );
    case "landing":
      return (
        <p>
          <Link to={landingPath()} className="link inline-flex items-center gap-1.5 font-semibold">
            {block.text}
            <Icon name="arrowRight" size={14} />
          </Link>
        </p>
      );
  }
}

function DocArticle({ page }: { page: DocPage }) {
  return (
    <article className="min-w-0">
      <PageHeader title={page.title} lede={page.lede} />
      <div className="max-w-[70ch] text-[0.9375rem] leading-relaxed text-ink-2">
        {page.sections.map((section) => (
          <section key={section.heading} className="mt-9 first:mt-0">
            <h2 className="mb-3 text-xl font-bold tracking-[-0.015em] text-ink">{section.heading}</h2>
            <div className="space-y-3">
              {section.blocks.map((block, index) => (
                <BlockView key={index} block={block} />
              ))}
            </div>
          </section>
        ))}
        {page.tool ? (
          <section aria-labelledby="docs-install" className="mt-9">
            <h2 id="docs-install" className="mb-3 text-xl font-bold tracking-[-0.015em] text-ink">
              Install and use
            </h2>
            <ToolGuide tool={page.tool} compact />
          </section>
        ) : null}
      </div>
    </article>
  );
}

function DocNotFound() {
  return (
    <div className="min-w-0">
      <h1 className="text-2xl font-bold tracking-[-0.02em]">Page not found</h1>
      <p className="mt-2 text-ink-2">There is no documentation page at this address.</p>
      <p className="mt-4">
        <Link to={docPath("")} className="link inline-flex items-center gap-1.5 font-semibold">
          Go to the documentation overview
          <Icon name="arrowRight" size={14} />
        </Link>
      </p>
    </div>
  );
}

export default function DocsPage() {
  const { slug } = useParams();
  const page = findDoc(slug);
  useTitle(page ? (page.slug ? `${page.title} · Docs` : "Docs") : "Docs");
  return (
    <div className="grid gap-8 lg:grid-cols-[14rem_minmax(0,1fr)] lg:gap-10">
      <div className="lg:border-r lg:border-line lg:pr-6">
        <DocsNav />
      </div>
      {page ? <DocArticle page={page} /> : <DocNotFound />}
    </div>
  );
}
