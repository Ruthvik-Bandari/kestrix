// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState, type RefObject } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router";
import { Icon } from "../../components/Icon";
import { OnThisPage, OnThisPageMenu, type TocItem } from "../../components/OnThisPage";
import { cx } from "../../components/ui";
import { useTitle } from "../../lib/useTitle";
import { BlockView } from "./BlockView";
import { breadcrumbs, metaOf, readingOrder, resolveDoc } from "./content";
import { DocsDrawer } from "./DocsDrawer";
import { DocsSearch } from "./DocsSearch";
import { DocsTree } from "./DocsTree";
import type { DocPage } from "./model";
import { DocsScope, LAYOUTS, useDocPath, useScope } from "./scope";
import { sectionIds } from "./search";

/** The article's h2 headings, in order: the "On this page" links and the heading ids share this one list. */
export function sectionLinks(page: DocPage): TocItem[] {
  const ids = sectionIds(page);
  return page.sections.map((section, index) => ({ id: ids[index] ?? "", label: section.heading }));
}

function Breadcrumbs({ path }: { path: string }) {
  const docPath = useDocPath();
  const crumbs = breadcrumbs(path);
  if (crumbs.length === 0) return null;
  return (
    <nav aria-label="Breadcrumb" className="mb-4">
      <ol className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[0.8125rem] text-ink-3">
        {crumbs.map((crumb, index) => {
          const last = index === crumbs.length - 1;
          return (
            <li key={`${crumb.label}-${index}`} className="flex items-center gap-1.5">
              {index > 0 ? <Icon name="chevronRight" size={12} /> : null}
              {crumb.path !== undefined && !last ? (
                <Link to={docPath(crumb.path)} className="hover:text-ink hover:underline">
                  {crumb.label}
                </Link>
              ) : (
                <span aria-current={last ? "page" : undefined} className={last ? "text-ink-2" : undefined}>
                  {crumb.label}
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

function PrevNext({ path }: { path: string }) {
  const docPath = useDocPath();
  const at = readingOrder.findIndex((page) => page.path === path);
  const previous = at > 0 ? readingOrder[at - 1] : undefined;
  const next = at >= 0 ? readingOrder[at + 1] : undefined;
  if (!previous && !next) return null;
  return (
    <nav aria-label="Previous and next pages" className="mt-12 grid gap-3 border-t border-line pt-6 sm:grid-cols-2">
      {previous ? (
        <Link to={docPath(previous.path)} rel="prev" className="group flex flex-col gap-1 rounded-xl border border-line px-4 py-3 hover:bg-inset">
          <span className="flex items-center gap-1.5 text-[0.8125rem] text-ink-3">
            <Icon name="arrowLeft" size={14} />
            Previous
          </span>
          <span className="font-semibold text-accent-text group-hover:underline">{previous.title}</span>
        </Link>
      ) : (
        <span className="hidden sm:block" />
      )}
      {next ? (
        <Link to={docPath(next.path)} rel="next" className="group flex flex-col gap-1 rounded-xl border border-line px-4 py-3 text-right hover:bg-inset sm:col-start-2">
          <span className="flex items-center justify-end gap-1.5 text-[0.8125rem] text-ink-3">
            Next
            <Icon name="arrowRight" size={14} />
          </span>
          <span className="font-semibold text-accent-text group-hover:underline">{next.title}</span>
        </Link>
      ) : null}
    </nav>
  );
}

const TYPE_LABEL = { tutorial: "Tutorial", "how-to": "How-to guide", reference: "Reference", explanation: "Explanation" } as const;

function formatDate(iso: string): string {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
}

function DocArticle({ page, heading }: { page: DocPage; heading: RefObject<HTMLHeadingElement | null> }) {
  const layout = LAYOUTS[useScope()];
  const links = sectionLinks(page);
  const meta = metaOf(page.path);
  return (
    <article id="docs-content" tabIndex={-1} className="min-w-0 outline-none">
      <header className="mb-8 border-b border-line pb-6">
        {page.path ? <p className="eyebrow mb-2">{TYPE_LABEL[meta.type]}</p> : null}
        <h1 ref={heading} tabIndex={-1} className="display max-w-[30ch] text-[clamp(1.625rem,3.2vw,2.125rem)] leading-[1.2] text-ink outline-none sm:max-w-none">
          {page.title}
        </h1>
        <p className="mt-3 max-w-[70ch] text-base text-ink-2">{page.summary}</p>
      </header>
      <OnThisPageMenu items={links} className={cx("mb-8", layout.tocMenu)} />
      <div className="text-[0.9375rem] leading-relaxed text-ink-2">
        {page.sections.map((section, index) => (
          <section key={links[index]?.id} aria-labelledby={links[index]?.id} className="mt-10 first:mt-0">
            <h2 id={links[index]?.id} tabIndex={-1} className={cx("mb-3 text-xl font-bold tracking-[-0.015em] text-ink outline-none", layout.scrollMargin)}>
              {section.heading}
            </h2>
            <div className="space-y-4">
              {section.blocks.map((block, blockIndex) => (
                <BlockView key={blockIndex} block={block} />
              ))}
            </div>
          </section>
        ))}
      </div>
      {page.path ? (
        <p className="mt-10 max-w-[70ch] text-[0.8125rem] text-ink-3">
          Summarizes {meta.source.map((file, i) => (
            <span key={file}>
              {i > 0 ? ", " : ""}
              <code className="font-mono">{file}</code>
            </span>
          ))}
          . Content last checked against it on <time dateTime={meta.reviewed}>{formatDate(meta.reviewed)}</time>.
        </p>
      ) : null}
      <PrevNext path={page.path} />
    </article>
  );
}

function DocNotFound({ heading }: { heading: RefObject<HTMLHeadingElement | null> }) {
  const docPath = useDocPath();
  return (
    <div className="min-w-0">
      <h1 ref={heading} tabIndex={-1} className="text-2xl font-bold tracking-[-0.02em] outline-none">
        Page not found
      </h1>
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

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

function DocsBody() {
  const scope = useScope();
  const layout = LAYOUTS[scope];
  const docPath = useDocPath();
  const { "*": rest } = useParams();
  const location = useLocation();
  const resolved = resolveDoc(rest);
  const page = resolved.kind === "page" ? resolved.page : undefined;
  const path = page?.path ?? "";
  const heading = useRef<HTMLHeadingElement>(null);
  const treeSearch = useRef<HTMLInputElement>(null);
  const opener = useRef<HTMLButtonElement>(null);
  const treeColumn = useRef<HTMLElement>(null);
  const [drawer, setDrawer] = useState<"nav" | "search" | null>(null);
  useTitle(page ? (page.path ? `${page.title} · Docs` : "Docs") : "Docs");

  // A page change moves focus to the new page's heading (or to the section a link named) so screen readers
  // announce it; the first render leaves focus alone.
  const firstRender = useRef(true);
  const { hash } = location;
  useEffect(() => {
    const first = firstRender.current;
    firstRender.current = false;
    const timer = window.setTimeout(() => {
      const target = hash ? document.getElementById(decodeURIComponent(hash.slice(1))) : null;
      if (target) {
        target.scrollIntoView();
        if (!first) target.focus({ preventScroll: true });
      } else if (!first) {
        window.scrollTo({ top: 0 });
        heading.current?.focus({ preventScroll: true });
      }
    }, 0);
    return () => {
      window.clearTimeout(timer);
    };
  }, [path, hash, resolved.kind]);

  // "/" jumps to search: the sidebar's box where the sidebar shows, otherwise the drawer.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey || isTyping(event.target)) return;
      event.preventDefault();
      const wide =
        (typeof window.matchMedia !== "function" || window.matchMedia(layout.treeQuery).matches) &&
        (!treeColumn.current || getComputedStyle(treeColumn.current).display !== "none");
      if (wide) treeSearch.current?.focus();
      else setDrawer("search");
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
    };
  }, [layout.treeQuery]);

  if (resolved.kind === "redirect") return <Navigate to={docPath(resolved.to)} replace />;

  return (
    <div className="@container grid min-w-0 gap-y-6">
      <a
        href="#docs-content"
        className="sr-only rounded-lg bg-accent px-4 py-2 font-medium text-on-accent focus:not-sr-only focus:fixed focus:top-20 focus:left-2 focus:z-[60]"
      >
        Skip to the page content
      </a>
      <div className={cx("grid min-w-0 gap-y-6", layout.grid)}>
        <aside ref={treeColumn} aria-label="Documentation navigation" className={cx("self-start border-r border-line pr-5", layout.tree)}>
          <div className={cx("flex flex-col gap-3", layout.treeSticky)}>
            <DocsSearch inputRef={treeSearch} variant="popover" />
            <DocsTree current={path} />
          </div>
        </aside>
        <div className="min-w-0">
          <div className={cx("mb-5 flex items-center gap-2 border-b border-line pb-4", layout.bar)}>
            <button
              ref={opener}
              type="button"
              className="btn btn-secondary btn-sm min-h-10"
              aria-haspopup="dialog"
              aria-expanded={drawer !== null}
              aria-controls="docs-drawer"
              onClick={() => {
                setDrawer("nav");
              }}
            >
              <Icon name="menu" size={18} />
              Docs menu
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm min-h-10"
              aria-haspopup="dialog"
              aria-expanded={drawer !== null}
              aria-controls="docs-drawer"
              onClick={() => {
                setDrawer("search");
              }}
            >
              <Icon name="search" size={18} />
              Search
            </button>
          </div>
          {page ? (
            <>
              <Breadcrumbs path={path} />
              <DocArticle page={page} heading={heading} />
            </>
          ) : (
            <DocNotFound heading={heading} />
          )}
        </div>
        {page ? (
          <OnThisPage items={sectionLinks(page)} responsive={cx("hidden", layout.toc)} stickyTop={cx("sticky", layout.tocSticky)} />
        ) : null}
      </div>
      {drawer ? (
        <DocsDrawer
          current={path}
          focusSearch={drawer === "search"}
          onClose={() => {
            setDrawer(null);
            opener.current?.focus();
          }}
        />
      ) : null}
    </div>
  );
}

/** The in-app docs (local "/docs/*", hosted "/app/docs/*"), inside the app shell. */
export default function DocsPage() {
  return (
    <DocsScope.Provider value="app">
      <DocsBody />
    </DocsScope.Provider>
  );
}

/** The public docs ("/docs/*" on the hosted service): the same pages, linking within the public copy. */
export function PublicDocsBody() {
  return (
    <DocsScope.Provider value="public">
      <DocsBody />
    </DocsScope.Provider>
  );
}
