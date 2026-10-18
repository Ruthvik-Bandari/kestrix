// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId } from "react";

/** The Kestrix shield with an iridescent rim and letter mark. Decorative. */
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
      <path d="M16 8.5 10 24h2.9l1.2-3.4h3.8l1.2 3.4H22L16 8.5Zm-1.1 9.6L16 14.7l1.1 3.4h-2.2Z" fill={`url(#${id}-rim)`} />
    </svg>
  );
}
