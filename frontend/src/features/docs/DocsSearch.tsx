// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, useMemo, useState, type KeyboardEvent, type RefObject } from "react";
import { useNavigate } from "react-router";
import { Icon } from "../../components/Icon";
import { cx } from "../../components/ui";
import { search, tokens, type SearchHit } from "./search";
import { useDocPath } from "./scope";

/**
 * The search box of the docs sidebar: a combobox over the client-side index (./search.ts). Type to see
 * matches, ArrowUp and ArrowDown to move, Enter to open one, Escape to close; "/" anywhere on the page
 * focuses it (DocsPage). In the drawer the results replace the tree ("inline"); beside the page they open
 * as a panel ("popover").
 */
export function DocsSearch({
  inputRef,
  variant,
  onNavigate,
}: {
  inputRef?: RefObject<HTMLInputElement | null>;
  variant: "popover" | "inline";
  onNavigate?: () => void;
}) {
  const docPath = useDocPath();
  const navigate = useNavigate();
  const id = useId();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [dismissed, setDismissed] = useState(false);
  const hits = useMemo(() => search(query), [query]);
  const searching = tokens(query).length > 0;
  const open = searching && !dismissed;
  const listId = `${id}-results`;
  const optionId = (index: number) => `${id}-option-${index}`;

  const go = (hit: SearchHit) => {
    setQuery("");
    setActive(0);
    onNavigate?.();
    void navigate(`${docPath(hit.path)}${hit.anchor ? `#${hit.anchor}` : ""}`);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      if (!searching || hits.length === 0) return;
      event.preventDefault();
      setDismissed(false);
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActive((current) => (current + step + hits.length) % hits.length);
    } else if (event.key === "Enter") {
      const hit = hits[active];
      if (open && hit) {
        event.preventDefault();
        go(hit);
      }
    } else if (event.key === "Escape") {
      if (open) {
        event.preventDefault();
        event.stopPropagation();
        setDismissed(true);
      } else if (query) {
        event.preventDefault();
        event.stopPropagation();
        setQuery("");
      }
    }
  };

  const results = open ? (
    hits.length > 0 ? (
      <div id={listId} role="listbox" aria-label="Search results" className="max-h-[min(28rem,70dvh)] overflow-y-auto overscroll-contain py-1">
        {hits.map((hit, index) => (
          // The input keeps focus (aria-activedescendant); a click picks the option.
          <div
            key={hit.key}
            id={optionId(index)}
            role="option"
            aria-selected={index === active}
            tabIndex={-1}
            onMouseDown={(event) => {
              event.preventDefault();
            }}
            onMouseMove={() => {
              if (index !== active) setActive(index);
            }}
            onClick={() => {
              go(hit);
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter") go(hit);
            }}
            className={cx("cursor-pointer border-l-2 px-3 py-2", index === active ? "border-accent bg-accent-soft" : "border-transparent")}
          >
            <span className="block text-[0.875rem] font-semibold text-ink">{hit.heading ?? hit.pageTitle}</span>
            <span className="block text-[0.75rem] text-ink-3">
              {hit.where} › {hit.heading ? hit.pageTitle : "Page"}
            </span>
            <span className="mt-0.5 line-clamp-2 block text-[0.8125rem] text-ink-2">{hit.snippet}</span>
          </div>
        ))}
      </div>
    ) : (
      <p className="px-3 py-3 text-[0.875rem] text-ink-2">No pages match “{query.trim()}”.</p>
    )
  ) : null;

  return (
    <div className="relative shrink-0">
      <div className="relative">
        <label htmlFor={`${id}-input`} className="sr-only">
          Search the documentation
        </label>
        <Icon name="search" size={16} className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-ink-3" />
        <input
          ref={inputRef}
          id={`${id}-input`}
          type="text"
          role="combobox"
          aria-expanded={open && hits.length > 0}
          aria-controls={open && hits.length > 0 ? listId : undefined}
          aria-autocomplete="list"
          aria-activedescendant={open && hits.length > 0 ? optionId(active) : undefined}
          autoComplete="off"
          spellCheck={false}
          placeholder="Search the docs"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActive(0);
            setDismissed(false);
          }}
          onKeyDown={onKeyDown}
          onBlur={() => {
            if (variant === "popover") setDismissed(true);
          }}
          onFocus={() => {
            setDismissed(false);
          }}
          className="h-10 w-full rounded-lg border border-line-strong bg-surface-solid pr-9 pl-9 text-[0.875rem] text-ink placeholder:text-ink-3"
        />
        {query === "" ? (
          <kbd
            aria-hidden="true"
            className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 rounded border border-line px-1.5 font-mono text-[0.75rem] text-ink-3 max-sm:hidden"
          >
            /
          </kbd>
        ) : (
          <button
            type="button"
            aria-label="Clear search"
            onClick={() => {
              setQuery("");
              inputRef?.current?.focus();
            }}
            className="absolute top-1/2 right-1 flex size-8 -translate-y-1/2 items-center justify-center rounded-md text-ink-3 hover:text-ink"
          >
            <Icon name="x" size={16} />
          </button>
        )}
      </div>
      <p className="sr-only" role="status">
        {open ? (hits.length === 0 ? "No results" : `${hits.length} result${hits.length === 1 ? "" : "s"}`) : ""}
      </p>
      {results ? (
        variant === "popover" ? (
          <div className="absolute top-full left-0 z-40 mt-2 w-[min(26rem,calc(100vw-2rem))] rounded-xl border border-line-strong bg-surface-solid shadow-[var(--shadow)]">{results}</div>
        ) : (
          <div className="mt-2 rounded-xl border border-line bg-surface-solid">{results}</div>
        )
      ) : null}
    </div>
  );
}
