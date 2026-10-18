// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { CSSProperties, ReactNode } from "react";
import { useReveal } from "../lib/useReveal";

/** A block that rises into view on scroll (no motion under reduced motion). */
export function Reveal({ children, className, delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  const ref = useReveal<HTMLDivElement>();
  return (
    <div ref={ref} className={className} style={{ "--reveal-delay": `${String(delay)}ms` } as CSSProperties}>
      {children}
    </div>
  );
}
