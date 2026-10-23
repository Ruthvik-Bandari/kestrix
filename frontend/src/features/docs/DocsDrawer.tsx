// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { Icon } from "../../components/Icon";
import { DocsSearch } from "./DocsSearch";
import { DocsTree } from "./DocsTree";

const FOCUSABLE = "a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex='-1'])";

/**
 * The docs tree as a modal drawer, for widths where the sidebar does not fit. Like the app's own menu:
 * focus moves in on open (to the search box when it was opened to search) and is held there, Escape, the
 * scrim or a link closes it, and the page behind does not scroll.
 */
export function DocsDrawer({
  current,
  focusSearch,
  onClose,
}: {
  current: string;
  focusSearch: boolean;
  onClose: () => void;
}) {
  const panel = useRef<HTMLDivElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  }, [onClose]);

  useEffect(() => {
    const node = panel.current;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    (focusSearch ? search.current : node?.querySelector<HTMLElement>("nav a[href]"))?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !event.defaultPrevented) {
        event.preventDefault();
        close.current();
        return;
      }
      if (event.key !== "Tab" || !node) return;
      const items = [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((item) => !item.closest("[hidden]"));
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (event.shiftKey && (document.activeElement === first || !node.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !node.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [focusSearch]);

  // Rendered into <body>: inside the public shell the page's sticky header would otherwise sit above the drawer.
  return createPortal(
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/60" aria-hidden="true" onClick={onClose} />
      <div
        ref={panel}
        id="docs-drawer"
        role="dialog"
        aria-modal="true"
        aria-label="Documentation menu"
        className="absolute inset-y-0 left-0 flex w-[20rem] max-w-[88vw] flex-col gap-3 border-r border-line bg-rail px-3 py-4"
      >
        <div className="flex items-center justify-between px-1">
          <p className="text-[0.9375rem] font-bold tracking-[-0.01em] text-ink">Documentation</p>
          <button type="button" className="btn btn-ghost btn-sm min-h-10 min-w-10" aria-label="Close documentation menu" onClick={onClose}>
            <Icon name="x" size={20} />
          </button>
        </div>
        <DocsSearch inputRef={search} variant="inline" onNavigate={onClose} />
        <DocsTree current={current} onNavigate={onClose} />
      </div>
    </div>,
    document.body,
  );
}
