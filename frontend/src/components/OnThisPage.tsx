// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import { cx } from "./ui";

/*
 * "On this page": anchor links to the h2 headings of a long-form article (docs, legal). It is
 * plain links, so the content never depends on it; where IntersectionObserver exists it also
 * marks the section being read. It is a side column from 1280px up and absent below that.
 */

export interface TocItem {
  id: string;
  label: string;
}

/** A stable element id for a heading's text. */
export function headingId(prefix: string, text: string): string {
  return `${prefix}-${text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
}

export function OnThisPage({ items, className, stickyTop = "xl:top-8" }: { items: TocItem[]; className?: string; stickyTop?: string }) {
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
    <nav aria-label="On this page" className={cx("hidden self-start xl:sticky xl:block", stickyTop, className)}>
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
