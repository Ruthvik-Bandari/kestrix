// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useRef, type ElementType, type PointerEvent, type ReactNode } from "react";
import { COARSE_POINTER, useMediaQuery, usePrefersReducedMotion } from "../lib/motion";
import { cx } from "./ui";

/** Largest tilt in degrees. Small on purpose: links inside must stay under the cursor. */
export const MAX_TILT = 5;

/**
 * A glass card that leans toward a mouse or pen and carries a moving sheen. Tilt is off for
 * reduced motion and for coarse (touch) pointers; then it is a plain glass card. Only CSS
 * custom properties change on pointer move, so React never re-renders while tilting.
 */
export function TiltCard({
  children,
  className,
  as: Tag = "div",
}: {
  children: ReactNode;
  className?: string;
  as?: ElementType;
}) {
  const ref = useRef<HTMLElement>(null);
  const reduced = usePrefersReducedMotion();
  const coarse = useMediaQuery(COARSE_POINTER);
  const enabled = !reduced && !coarse;

  function onPointerMove(event: PointerEvent<HTMLElement>) {
    const node = ref.current;
    if (!enabled || !node || event.pointerType === "touch") return;
    const rect = node.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    const x = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
    const y = Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height));
    node.style.setProperty("--ry", `${((x - 0.5) * 2 * MAX_TILT).toFixed(2)}deg`);
    node.style.setProperty("--rx", `${((0.5 - y) * 2 * MAX_TILT).toFixed(2)}deg`);
    node.style.setProperty("--mx", `${(x * 100).toFixed(1)}%`);
    node.style.setProperty("--my", `${(y * 100).toFixed(1)}%`);
    node.dataset.active = "true";
  }

  function onPointerLeave() {
    const node = ref.current;
    if (!node) return;
    node.style.removeProperty("--rx");
    node.style.removeProperty("--ry");
    node.dataset.active = "false";
  }

  return (
    <Tag
      ref={ref}
      className={cx("glass", enabled && "tilt", className)}
      data-tilt={enabled ? "on" : "off"}
      onPointerMove={enabled ? onPointerMove : undefined}
      onPointerLeave={enabled ? onPointerLeave : undefined}
    >
      {enabled ? <span className="tilt-sheen" aria-hidden="true" /> : null}
      {children}
    </Tag>
  );
}
