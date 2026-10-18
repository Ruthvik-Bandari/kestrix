// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { cx } from "./ui";

export interface TabItem<K extends string> {
  key: K;
  label: ReactNode;
}

/** WAI-ARIA tabs with automatic activation and arrow/Home/End keys. */
export function Tabs<K extends string>({
  items,
  value,
  onChange,
  label,
  children,
}: {
  items: TabItem<K>[];
  value: K;
  onChange: (key: K) => void;
  label: string;
  children: ReactNode;
}) {
  const base = useId();
  const refs = useRef(new Map<K, HTMLButtonElement>());

  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    const index = items.findIndex((item) => item.key === value);
    const last = items.length - 1;
    const next =
      event.key === "ArrowRight"
        ? index === last ? 0 : index + 1
        : event.key === "ArrowLeft"
          ? index === 0 ? last : index - 1
          : event.key === "Home"
            ? 0
            : event.key === "End"
              ? last
              : null;
    if (next === null) return;
    event.preventDefault();
    const item = items[next];
    if (!item) return;
    onChange(item.key);
    refs.current.get(item.key)?.focus();
  }

  return (
    <div>
      <div
        role="tablist"
        aria-label={label}
        className="mb-6 inline-flex max-w-full gap-1 overflow-x-auto rounded-xl border border-line bg-surface p-1 shadow-[inset_0_1px_0_var(--glass-hi)] backdrop-blur-md"
      >
        {items.map((item) => {
          const selected = item.key === value;
          return (
            <button
              key={item.key}
              ref={(node) => {
                if (node) refs.current.set(item.key, node);
                else refs.current.delete(item.key);
              }}
              type="button"
              role="tab"
              id={`${base}-tab-${item.key}`}
              aria-selected={selected}
              aria-controls={`${base}-panel`}
              tabIndex={selected ? 0 : -1}
              onKeyDown={onKeyDown}
              onClick={() => {
                onChange(item.key);
              }}
              className={cx(
                "min-h-9 rounded-lg px-4 text-sm font-semibold whitespace-nowrap transition-colors duration-150",
                selected
                  ? "bg-[linear-gradient(120deg,var(--btn-a),var(--btn-b))] text-white shadow-[inset_0_1px_0_oklch(1_0_0/0.25),0_6px_18px_-8px_var(--glow)]"
                  : "text-ink-2 hover:bg-inset hover:text-ink",
              )}
            >
              {item.label}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" id={`${base}-panel`} aria-labelledby={`${base}-tab-${value}`}>
        {children}
      </div>
    </div>
  );
}
