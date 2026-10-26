// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId } from "react";

/** The Kestrix shield with an iridescent rim and a K. Decorative. */
export function BrandMark({ size = 28 }: { size?: number }) {
  const id = useId();
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" className="flex-none">
      <defs>
        <linearGradient id={`${id}-rim`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--h1)" />
          <stop offset="0.45" stopColor="var(--h2)" />
          <stop offset="0.8" stopColor="var(--h3)" />
          <stop offset="1" stopColor="var(--h4)" />
        </linearGradient>
      </defs>
      <path
        d="M16 2.5 4.5 7v8.2c0 7 4.8 12.6 11.5 14.3 6.7-1.7 11.5-7.3 11.5-14.3V7L16 2.5Z"
        fill="var(--surface-solid)"
        stroke={`url(#${id}-rim)`}
        strokeWidth="2"
      />
      <path d="M11.5 9H14v6.2L19 9h3.1l-5.5 6.4 5.8 8.6h-3.1l-4.4-6.6-.9 1.1V24h-2.5Z" fill={`url(#${id}-rim)`} />
    </svg>
  );
}
