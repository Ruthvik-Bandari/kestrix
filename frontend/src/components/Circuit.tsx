// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId } from "react";
import { BrandMark } from "./BrandMark";
import { Icon, type IconName } from "./Icon";
import { cx } from "./ui";

/** Soft light beams falling from the top edge of the nearest positioned box. Decorative, static. */
export function Beams({ className }: { className?: string }) {
  return <div className={cx("beams", className)} aria-hidden="true" />;
}

const CX = 600;
const CY = 232;
const R = 124;

/** Circuit traces from the left edge toward the dial; the right side is the same set mirrored. */
const TRACES = [
  "M-900 232H476",
  "M-900 112H58L82 136H214L310 232",
  "M-900 146H44L68 170H146L184 132H256",
  "M-900 186H24L50 212H104",
  "M-900 278H92L124 310H210L252 268H318",
  "M-900 316H56L78 338H236L270 304H340",
  "M200 232L248 280H268",
  "M346 232L394 184H430",
  "M400 159V200L432 232",
  "M353 93L387 127",
];
/** End points that carry a small glowing node. */
const NODES: [number, number][] = [
  [104, 212],
  [256, 132],
  [318, 268],
  [340, 304],
  [268, 280],
  [430, 184],
  [150, 232],
  [476, 232],
];
/** Short bright segments that sit on a trace. */
const SEGMENTS = ["M64 232H104", "M110 136H150", "M96 310H128", "M150 212H178", "M262 232H292"];
/** Traces a pulse travels along (animated variant only). */
const PULSES: { d: string; cls: string }[] = [
  { d: "M-900 232H476", cls: "pulse-a" },
  { d: "M-900 112H58L82 136H214L310 232", cls: "pulse-b" },
  { d: "M-900 316H56L78 338H236L270 304H340", cls: "pulse-c" },
];

function TraceSet({ animated, mirrored }: { animated: boolean; mirrored: boolean }) {
  return (
    <g transform={mirrored ? "translate(1200 0) scale(-1 1)" : undefined}>
      {TRACES.map((d) => (
        <path key={d} d={d} className="trace" />
      ))}
      {SEGMENTS.map((d) => (
        <path key={d} d={d} className="trace-seg" />
      ))}
      {NODES.map(([x, y]) => (
        <circle key={`${x}-${y}`} cx={x} cy={y} r={2.6} className="trace-node" />
      ))}
      {animated
        ? PULSES.map(({ d, cls }) => <path key={d} d={d} pathLength={1000} className={cx("trace-pulse", cls)} />)
        : null}
    </g>
  );
}

const TICKS = Array.from({ length: 72 }, (_, i) => i);
const TOOL_NODES: { name: IconName; x: number; y: number }[] = [
  { name: "mail", x: 340, y: 80 },
  { name: "globe", x: 400, y: 140 },
  { name: "fileSearch", x: 860, y: 80 },
  { name: "braces", x: 800, y: 140 },
];

/**
 * The hero illustration: circuit traces fanning out on both sides, round tool nodes joined by traces and
 * the Kestrix shield inside a dial with tick marks and concentric rings. Pure SVG drawn here (no images,
 * no inline styles); the look comes from classes in index.css. `animated` adds a slow pulse along three
 * traces and a breathing glow on the dial (both off under prefers-reduced-motion). Decorative.
 */
export function CircuitDial({ animated = false, className }: { animated?: boolean; className?: string }) {
  const id = useId();
  return (
    <svg
      viewBox="0 0 1200 360"
      className={cx("circuit", className)}
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <radialGradient id={`${id}-disc`} cx="50%" cy="38%" r="70%">
          <stop offset="0" className="stop-disc-a" />
          <stop offset="1" className="stop-disc-b" />
        </radialGradient>
        <radialGradient id={`${id}-halo`} cx="50%" cy="50%" r="50%">
          <stop offset="0.55" className="stop-halo-a" />
          <stop offset="1" className="stop-halo-b" />
        </radialGradient>
      </defs>
      <TraceSet animated={animated} mirrored={false} />
      <TraceSet animated={animated} mirrored />
      {TOOL_NODES.map(({ name, x, y }) => (
        <g key={name}>
          <circle cx={x} cy={y} r={19} className="tool-node" />
          <g transform={`translate(${x - 9} ${y - 9})`} className="tool-node-icon">
            <Icon name={name} size={18} />
          </g>
        </g>
      ))}
      <circle cx={CX} cy={CY} r={R + 40} fill={`url(#${id}-halo)`} className={cx("dial-halo", animated && "breathe")} />
      <circle cx={CX} cy={CY} r={R} className="dial-ring" />
      <circle cx={CX} cy={CY} r={R - 18} className="dial-ring-dim" />
      {TICKS.map((i) => {
        const a = (i / TICKS.length) * Math.PI * 2;
        const major = i % 6 === 0;
        const r1 = R - 14;
        const r2 = R - (major ? 24 : 20);
        return (
          <line
            key={i}
            x1={CX + Math.cos(a) * r1}
            y1={CY + Math.sin(a) * r1}
            x2={CX + Math.cos(a) * r2}
            y2={CY + Math.sin(a) * r2}
            className={major ? "dial-tick-major" : "dial-tick"}
          />
        );
      })}
      <circle cx={CX} cy={CY} r={R - 40} className="dial-disc" fill={`url(#${id}-disc)`} />
      <g transform={`translate(${CX - 48} ${CY - 50})`} className="dial-emblem">
        <BrandMark size={96} />
      </g>
    </svg>
  );
}
