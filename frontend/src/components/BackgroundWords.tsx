// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { CSSProperties } from "react";

const WORDS = [
  "verify",
  "detect",
  "repair",
  "trace",
  "phishing",
  "sigma",
  "replay",
  "evidence",
  "dmarc",
  "entropy",
  "lookalike",
  "validate",
  "abstain",
  "hash",
  "triage",
  "provenance",
];

// Fixed layout so the field looks the same on every load and in tests.
const PLACEMENTS = WORDS.map((word, i) => ({
  word,
  left: (i * 37 + 7) % 92,
  top: (i * 53 + 11) % 90,
  duration: 38 + ((i * 7) % 26),
  delay: -((i * 11) % 40),
  dx: ((i % 5) - 2) * 14,
}));

/** Faint words drifting behind the page. Decorative: hidden from assistive technology. */
export function BackgroundWords() {
  return (
    <div className="bg-words" aria-hidden="true" data-testid="background-words">
      {PLACEMENTS.map((p) => (
        <span
          key={p.word}
          className="bg-word"
          style={
            {
              left: `${String(p.left)}%`,
              top: `${String(p.top)}%`,
              "--word-duration": `${String(p.duration)}s`,
              "--word-delay": `${String(p.delay)}s`,
              "--word-dx": `${String(p.dx)}px`,
            } as CSSProperties
          }
        >
          {p.word}
        </span>
      ))}
    </div>
  );
}
