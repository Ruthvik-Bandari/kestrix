// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import { Icon } from "./Icon";
import { cx } from "./ui";

/*
 * "On this page": anchor links to the h2 headings of a long-form article (docs, legal). It is
 * plain links, so the content never depends on it; where IntersectionObserver exists it also
 * marks the section being read. It is a side column from 1280px up (or wherever `responsive` says); below that, `OnThisPageMenu` is the same links in a disclosure.
 */

export interface TocItem {
  id: string;
  label: string;
}

/** A stable element id for a heading's text. */
export function headingId(prefix: string, text: string): string {
  return `${prefix}-${text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
}

export function OnThisPage({
  items,
  className,
  stickyTop = "xl:top-8",
  responsive = "hidden xl:sticky xl:block",
}: {
  items: TocItem[];
  className?: string;
  stickyTop?: string;
  /** When the column shows and sticks; the default is from 1280px up. */
  responsive?: string;
}) {
  const [current, setCurrent] = useState<string | null>(null);
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const visible = new Set<string>();
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) visible.add(entry.target.id);
          else visible.delete(entry.target.id);
        }
        const first = items.find((item) => visible.has(item.id));
        if (first) setCurrent(first.id);
      },
      { rootMargin: "-8% 0px -70% 0px" },
    );
    for (const item of items) {
      const heading = document.getElementById(item.id);
      if (heading) observer.observe(heading);
    }
    return () => {
      observer.disconnect();
    };
  }, [items]);

  if (items.length < 2) return null;
  return (
    <nav aria-label="On this page" className={cx("self-start", responsive, stickyTop, className)}>
      <p className="mb-2 text-[0.75rem] font-semibold tracking-[0.08em] text-ink-3 uppercase">On this page</p>
      <ul className="space-y-0.5 border-l border-line">
        {items.map((item) => {
          const active = item.id === current;
          return (
            <li key={item.id}>
              <a
                href={`#${item.id}`}
                aria-current={active ? "location" : undefined}
                className={cx(
                  "-ml-px block border-l-2 py-1 pr-1 pl-3 text-[0.8125rem] leading-snug transition-colors duration-150 motion-reduce:transition-none",
                  active ? "border-accent font-medium text-accent-text" : "border-transparent text-ink-2 hover:text-ink",
                )}
              >
                {item.label}
              </a>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

/** The same links as a disclosure, for widths where the side column does not fit. */
export function OnThisPageMenu({ items, className }: { items: TocItem[]; className?: string }) {
  if (items.length < 2) return null;
  return (
    <details className={cx("group rounded-xl border border-line bg-inset/50", className)}>
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-2 px-4 text-[0.875rem] font-medium text-ink [&::-webkit-details-marker]:hidden">
        On this page
        <Icon name="chevronDown" size={16} className="text-ink-3 transition-transform duration-150 group-open:rotate-180 motion-reduce:transition-none" />
      </summary>
      <ul className="border-t border-line px-2 py-2">
        {items.map((item) => (
          <li key={item.id}>
            <a href={`#${item.id}`} className="flex min-h-9 items-center rounded-lg px-2 text-[0.875rem] text-ink-2 hover:bg-inset hover:text-ink">
              {item.label}
            </a>
          </li>
        ))}
      </ul>
    </details>
  );
}
