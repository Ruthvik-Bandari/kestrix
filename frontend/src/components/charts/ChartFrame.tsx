// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useLayoutEffect, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode, type RefObject } from "react";

export const MARGIN = { top: 12, right: 16, bottom: 28, left: 40 };

/** Track an element's content width so SVG text stays crisp at every size. */
export function useWidth<T extends HTMLElement>(fallback = 640) {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(fallback);
  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return;
    setWidth(node.clientWidth || fallback);
    const observer = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.max(240, Math.round(entry.contentRect.width)));
    });
    observer.observe(node);
    return () => {
      observer.disconnect();
    };
  }, [fallback]);
  return [ref, width] as const;
}

/**
 * Shared chart shell: a focusable plot that reports the hovered index from the pointer
 * (nearest X) or the arrow keys, and a tooltip that shows the same values either way.
 */
export function ChartFrame({
  label,
  height,
  count,
  width,
  indexAt,
  pointFor,
  tooltip,
  valueText,
  children,
  containerRef,
}: {
  label: string;
  height: number;
  count: number;
  width: number;
  indexAt: (plotX: number) => number;
  pointFor: (index: number) => { x: number; y: number };
  tooltip: (index: number) => ReactNode;
  /** Spoken equivalent of the tooltip, for keyboard and screen-reader users. */
  valueText: (index: number) => string;
  children: (active: number | null) => ReactNode;
  containerRef: RefObject<HTMLDivElement | null>;
}) {
  const [active, setActive] = useState<number | null>(null);

  function onPointer(event: PointerEvent<SVGSVGElement>) {
    const box = event.currentTarget.getBoundingClientRect();
    const x = event.clientX - box.left - MARGIN.left;
    setActive(Math.max(0, Math.min(count - 1, indexAt(x))));
  }

  function onKey(event: KeyboardEvent<SVGSVGElement>) {
    const step = event.shiftKey ? Math.max(1, Math.round(count / 16)) : 1;
    const current = active ?? -1;
    let next: number | null = null;
    if (event.key === "ArrowRight") next = Math.min(count - 1, current + step);
    else if (event.key === "ArrowLeft") next = Math.max(0, (active ?? count) - step);
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = count - 1;
    else if (event.key === "Escape") {
      setActive(null);
      return;
    }
    if (next === null) return;
    event.preventDefault();
    setActive(next);
  }

  const point = active === null ? null : pointFor(active);
  const left = point ? Math.min(Math.max(point.x + MARGIN.left, 70), width - 70) : 0;

  return (
    <div ref={containerRef} className="relative">
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className="block touch-pan-y overflow-visible"
        tabIndex={0}
        role="slider"
        aria-label={`${label}. Use the arrow keys to read values; the data table below lists them too.`}
        aria-valuemin={0}
        aria-valuemax={count - 1}
        aria-valuenow={active ?? 0}
        aria-valuetext={active === null ? "No point selected" : valueText(active)}
        aria-orientation="horizontal"
        onPointerMove={onPointer}
        onPointerDown={onPointer}
        onPointerLeave={() => {
          setActive(null);
        }}
        onKeyDown={onKey}
        onBlur={() => {
          setActive(null);
        }}
      >
        {children(active)}
      </svg>
      {active !== null && point ? (
        <div
          className="pointer-events-none absolute z-10 -translate-x-1/2 rounded-md border border-line bg-surface px-2.5 py-1.5 text-[0.8125rem] whitespace-nowrap shadow-panel"
          style={{ left, top: Math.max(0, point.y + MARGIN.top - 52) }}
          aria-hidden="true"
        >
          {tooltip(active)}
        </div>
      ) : null}
    </div>
  );
}
