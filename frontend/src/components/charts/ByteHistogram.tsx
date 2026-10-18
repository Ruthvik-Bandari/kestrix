// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { compact } from "../../lib/format";
import { ChartFrame, MARGIN, useWidth } from "./ChartFrame";

const HEIGHT = 200;
const X_TICKS = [0x00, 0x20, 0x7f, 0xff];

export function byteLabel(value: number): string {
  const hex = `0x${value.toString(16).toUpperCase().padStart(2, "0")}`;
  if (value === 0x20) return `${hex} (space)`;
  if (value > 0x20 && value < 0x7f) return `${hex} “${String.fromCharCode(value)}”`;
  if (value === 0x0a) return `${hex} (line feed)`;
  if (value === 0x0d) return `${hex} (carriage return)`;
  if (value === 0x09) return `${hex} (tab)`;
  return hex;
}

/** How often each of the 256 byte values occurs. 256 touching columns; log scale optional. */
export function ByteHistogram({ counts, log }: { counts: number[]; log: boolean }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const plotW = width - MARGIN.left - MARGIN.right;
  const plotH = HEIGHT - MARGIN.top - MARGIN.bottom;
  const max = Math.max(1, ...counts);
  const scale = (n: number) => (log ? Math.log10(n + 1) / Math.log10(max + 1) : n / max);
  const bin = plotW / 256;
  const y = (n: number) => plotH - scale(n) * plotH;
  const yTicks = log
    ? [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000].filter((t) => t <= max)
    : [0, max / 2, max];

  // One path for all columns keeps the DOM small (256 rects would be fine too).
  let bars = "";
  counts.forEach((n, i) => {
    if (n === 0) return;
    const top = y(n);
    bars += `M${(i * bin).toFixed(2)},${plotH}V${top.toFixed(2)}H${((i + 1) * bin).toFixed(2)}V${plotH}Z`;
  });

  const valueText = (i: number) => `Byte ${byteLabel(i)}: ${(counts[i] ?? 0).toLocaleString()} occurrences`;

  return (
    <ChartFrame
      containerRef={ref}
      label={`Byte value histogram${log ? " (logarithmic scale)" : ""}`}
      width={width}
      height={HEIGHT}
      count={256}
      indexAt={(px) => Math.floor(px / bin)}
      pointFor={(i) => ({ x: (i + 0.5) * bin, y: y(counts[i] ?? 0) })}
      valueText={valueText}
      tooltip={(i) => (
        <>
          <span className="font-semibold text-ink">{(counts[i] ?? 0).toLocaleString()}</span>
          <span className="text-ink-2"> × </span>
          <span className="font-mono text-ink-2">{byteLabel(i)}</span>
        </>
      )}
    >
      {(active) => (
        <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
          <rect x={0x20 * bin} width={(0x7f - 0x20) * bin} y={0} height={plotH} fill="var(--inset)" />
          <text x={0x20 * bin + 4} y={12} fontSize={11} fill="var(--ink-3)">
            printable text
          </text>
          {yTicks.map((t) => (
            <g key={t}>
              <line x1={0} x2={plotW} y1={y(t)} y2={y(t)} stroke="var(--line)" strokeWidth={1} />
              <text x={-8} y={y(t)} dy="0.32em" textAnchor="end" fontSize={11} fill="var(--ink-3)" className="tabular-nums">
                {compact(Math.round(t))}
              </text>
            </g>
          ))}
          <path d={bars} fill="var(--accent)" />
          {active !== null ? (
            <rect x={active * bin - 1} width={bin + 2} y={0} height={plotH} fill="var(--ink)" opacity={0.12} />
          ) : null}
          <line x1={0} x2={plotW} y1={plotH} y2={plotH} stroke="var(--line-strong)" strokeWidth={1} />
          {X_TICKS.map((t) => (
            <text
              key={t}
              x={(t + 0.5) * bin}
              y={plotH + 18}
              textAnchor={t === 0 ? "start" : t === 0xff ? "end" : "middle"}
              fontSize={11}
              fill="var(--ink-3)"
              className="font-mono"
            >
              {`0x${t.toString(16).toUpperCase().padStart(2, "0")}`}
            </text>
          ))}
        </g>
      )}
    </ChartFrame>
  );
}
