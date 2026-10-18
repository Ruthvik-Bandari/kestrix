// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { createContext, useContext, useId, useMemo, useState, type CSSProperties, type ReactNode } from "react";
import { Icon } from "../../components/Icon";
import { cx } from "../../components/ui";
import { useMediaQuery, usePrefersReducedMotion } from "../../lib/motion";

/*
 * "Without Kestrix ⟷ With Kestrix". Both states render into the same grid cell, so the stage
 * is as tall as the taller state and nothing shifts when you compare. The Kestrix state wipes
 * in from the left like a scanner: `scan` is how much of the stage (0-100 %) it covers.
 *
 * Two controls drive it: a segmented toggle (buttons with aria-pressed, every screen size) and a
 * native range input stretched invisibly over the stage, so on a mouse or pen you can grab the
 * beam anywhere and drag. The range is only rendered for fine pointers from the sm breakpoint
 * up, where it cannot trap touch scrolling. With reduced motion there is no wipe at all: both
 * states are shown one after the other, statically.
 */

export type Side = "without" | "with";

interface SideState {
  side: Side;
  /** False while the state is fully covered by the other one; animations pause then. */
  visible: boolean;
  /** True in the static reduced-motion layout: no auto-animation, no fake cursor. */
  still: boolean;
}

const SideContext = createContext<SideState>({ side: "without", visible: true, still: false });

/** Which state a scene part is rendered in, and whether it is on screen. */
export function useSide(): SideState {
  return useContext(SideContext);
}

const LABEL: Record<Side, string> = { without: "Without Kestrix", with: "With Kestrix" };

function SideTag({ side, className }: { side: Side; className?: string }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[0.75rem] font-bold tracking-[0.08em] uppercase",
        side === "with"
          ? "bg-[linear-gradient(120deg,var(--btn-a),var(--btn-b))] text-white shadow-[0_6px_20px_-8px_var(--glow)]"
          : "border border-line-strong bg-surface-solid text-ink-2",
        className,
      )}
    >
      <Icon name={side === "with" ? "shield" : "minus"} size={13} />
      {LABEL[side]}
    </span>
  );
}

function Layer({
  side,
  children,
  hidden = false,
  still = false,
  settled = false,
}: {
  side: Side;
  children: ReactNode;
  hidden?: boolean;
  still?: boolean;
  /** Fully revealed: its buttons sit above the drag surface so they can be clicked. */
  settled?: boolean;
}) {
  const value = useMemo(() => ({ side, visible: !hidden, still }), [side, hidden, still]);
  return (
    <SideContext.Provider value={value}>
      <div
        role="group"
        aria-label={LABEL[side]}
        data-side={side}
        data-visible={hidden ? "false" : "true"}
        className={cx(
          "compare-layer relative min-w-0",
          still ? "overflow-hidden rounded-[1.75rem] border border-line-strong" : "[grid-area:1/1]",
          side === "with" && !still && "compare-with",
          settled && "is-settled",
        )}
      >
        {children}
      </div>
    </SideContext.Provider>
  );
}

export function Compare({
  name,
  without,
  withKestrix,
  initial = 0,
  pointerSlider,
}: {
  /** Short scene name used in control labels, for example "the invoice email". */
  name: string;
  without: ReactNode;
  withKestrix: ReactNode;
  /** Starting scan position, 0 (all without) to 100 (all with). */
  initial?: number;
  /** Override the pointer check (tests). Defaults to "fine pointer and at least sm". */
  pointerSlider?: boolean;
}) {
  const reduced = usePrefersReducedMotion();
  const [scan, setScan] = useState(initial);
  const [dragging, setDragging] = useState(false);
  const id = useId();
  const fine = useMediaQuery(FINE_WIDE);
  const slider = pointerSlider ?? fine;
  const side: Side = scan >= 50 ? "with" : "without";

  if (reduced) {
    return (
      <div className="grid gap-6" data-compare="static">
        {(["without", "with"] as const).map((s) => (
          <div key={s} className="grid gap-3">
            <SideTag side={s} className="w-fit" />
            <Layer side={s} still>
              {s === "with" ? withKestrix : without}
            </Layer>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div data-compare="interactive" data-side={side}>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div role="group" aria-label={`Compare ${name}`} className="compare-toggle inline-grid grid-cols-2 rounded-full border border-line-strong bg-surface p-1 shadow-[inset_0_1px_0_var(--glass-hi)] backdrop-blur-md">
          {(["without", "with"] as const).map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={side === s}
              aria-controls={id}
              onClick={() => {
                setScan(s === "with" ? 100 : 0);
              }}
              className={cx(
                "relative min-h-10 rounded-full px-4 text-[0.875rem] font-semibold transition-colors duration-200",
                side === s
                  ? s === "with"
                    ? "bg-[linear-gradient(120deg,var(--btn-a),var(--btn-b))] text-white shadow-[0_6px_20px_-8px_var(--glow)]"
                    : "bg-surface-solid text-ink shadow-panel"
                  : "text-ink-2 hover:text-ink",
              )}
            >
              {LABEL[s]}
            </button>
          ))}
        </div>
        {slider ? (
          <p className="hidden items-center gap-2 text-[0.8125rem] text-ink-3 sm:flex" aria-hidden="true">
            <Icon name="arrowLeft" size={14} />
            Drag the beam across the scene
            <Icon name="arrowRight" size={14} />
          </p>
        ) : null}
      </div>

      <div
        id={id}
        className={cx("compare-stage relative grid isolate overflow-hidden rounded-[1.75rem]", dragging && "is-dragging")}
        style={{ "--scan": `${String(scan)}%`, "--scan-n": scan } as CSSProperties}
      >
        <Layer side="without" hidden={scan >= 100}>
          {without}
        </Layer>
        <Layer side="with" hidden={scan <= 0} settled={scan >= 100}>
          {withKestrix}
        </Layer>

        {/* The beam: decorative; the range input below carries the semantics. */}
        <div className="compare-beam pointer-events-none absolute inset-y-0 z-20" aria-hidden="true">
          {slider ? (
            <span className="compare-knob">
              <Icon name="arrowLeft" size={13} />
              <Icon name="arrowRight" size={13} />
            </span>
          ) : null}
        </div>
        <SideTag
          side="with"
          className={cx("pointer-events-none absolute top-3 left-3 z-20 transition-opacity duration-300", scan < 18 && "opacity-0")}
        />
        <SideTag
          side="without"
          className={cx("pointer-events-none absolute top-3 right-3 z-20 transition-opacity duration-300", scan > 82 && "opacity-0")}
        />

        {slider ? (
          <input
            type="range"
            min={0}
            max={100}
            step={1}
            value={scan}
            aria-label={`How much of ${name} Kestrix has scanned`}
            aria-valuetext={`${String(scan)}% with Kestrix, ${String(100 - scan)}% without`}
            onChange={(event) => {
              setScan(Number(event.currentTarget.value));
            }}
            onPointerDown={() => {
              setDragging(true);
            }}
            onPointerUp={() => {
              setDragging(false);
            }}
            onPointerCancel={() => {
              setDragging(false);
            }}
            onBlur={() => {
              setDragging(false);
            }}
            className="compare-range absolute inset-0 z-30 h-full w-full"
          />
        ) : null}
      </div>
      <p className="sr-only" aria-live="polite">
        Showing {LABEL[side]}.
      </p>
    </div>
  );
}

const FINE_WIDE = "(pointer: fine) and (min-width: 640px)";
