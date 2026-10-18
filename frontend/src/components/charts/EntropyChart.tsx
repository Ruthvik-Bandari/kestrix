// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { formatBytes, hexOffset } from "../../lib/format";
import type { FileReport } from "../../lib/types";
import { ChartFrame, MARGIN, useWidth } from "./ChartFrame";

const HEIGHT = 220;
const Y_TICKS = [0, 2, 4, 6, 8];

function niceTicks(max: number, target = 5): number[] {
  if (max <= 0) return [0];
  const raw = max / target;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const step = ([1, 2, 2.5, 5, 10].find((m) => m * pow >= raw) ?? 10) * pow;
  const ticks: number[] = [];
  for (let v = 0; v <= max + 1e-9; v += step) ticks.push(v);
  return ticks;
}

/** Entropy across the file: one 2px line, a 10% wash, and the "random-looking" threshold. */
export function EntropyChart({ entropy, size }: { entropy: FileReport["entropy"]; size: number }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const points = entropy.points;
  const plotW = width - MARGIN.left - MARGIN.right;
  const plotH = HEIGHT - MARGIN.top - MARGIN.bottom;
  const maxX = Math.max(1, size);
  const x = (offset: number) => (offset / maxX) * plotW;
  const y = (bits: number) => plotH - (bits / 8) * plotH;
  const spanBytes = entropy.block_size * entropy.points_span_blocks;

  if (points.length === 0) {
    return <p className="text-ink-2">The file is empty, so there is no entropy to chart.</p>;
  }

  // Each point averages a span of blocks; draw it at the span's midpoint.
  const mid = (offset: number) => x(Math.min(offset + spanBytes / 2, maxX));
  const line = points.map((p, i) => `${i ? "L" : "M"}${mid(p.offset).toFixed(1)},${y(p.entropy).toFixed(1)}`).join("");
  const first = points[0];
  const last = points.at(-1);
  const area =
    first && last ? `${line}L${mid(last.offset).toFixed(1)},${plotH}L${mid(first.offset).toFixed(1)},${plotH}Z` : "";
  const xTicks = niceTicks(maxX, width < 480 ? 3 : 5);

  const valueText = (i: number) => {
    const p = points[i];
    return p ? `${p.entropy.toFixed(2)} bits per byte at ${hexOffset(p.offset)} (${formatBytes(p.offset)})` : "";
  };

  return (
    <ChartFrame
      containerRef={ref}
      label="Entropy across the file, in bits per byte"
      width={width}
      height={HEIGHT}
      count={points.length}
      indexAt={(px) => {
        let best = 0;
        let dist = Infinity;
        points.forEach((p, i) => {
          const d = Math.abs(mid(p.offset) - px);
          if (d < dist) {
            dist = d;
            best = i;
          }
        });
        return best;
      }}
      pointFor={(i) => {
        const p = points[i];
        return p ? { x: mid(p.offset), y: y(p.entropy) } : { x: 0, y: 0 };
      }}
      valueText={valueText}
      tooltip={(i) => {
        const p = points[i];
        if (!p) return null;
        return (
          <>
            <span className="font-semibold text-ink">{p.entropy.toFixed(2)}</span>
            <span className="text-ink-2"> bits/byte · </span>
            <span className="font-mono text-ink-2">{hexOffset(p.offset)}</span>
          </>
        );
      }}
    >
      {(active) => {
        const activePoint = active === null ? null : points[active];
        return (
          <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
            {entropy.high_entropy_regions.map((r) => (
              <rect
                key={r.start}
                x={x(r.start)}
                width={Math.max(1, x(r.end) - x(r.start))}
                y={0}
                height={plotH}
                fill="var(--ink)"
                opacity={0.06}
              />
            ))}
            {Y_TICKS.map((t) => (
              <g key={t}>
                <line x1={0} x2={plotW} y1={y(t)} y2={y(t)} stroke="var(--line)" strokeWidth={1} />
                <text x={-8} y={y(t)} dy="0.32em" textAnchor="end" fontSize={11} fill="var(--ink-3)" className="tabular-nums">
                  {t}
                </text>
              </g>
            ))}
            <line
              x1={0}
              x2={plotW}
              y1={y(entropy.high_entropy_threshold)}
              y2={y(entropy.high_entropy_threshold)}
              stroke="var(--high-mark)"
              strokeWidth={1}
            />
            <text
              x={plotW}
              y={y(entropy.high_entropy_threshold) - 5}
              textAnchor="end"
              fontSize={11}
              fill="var(--ink-2)"
            >
              random-looking ≥ {entropy.high_entropy_threshold}
            </text>
            <path d={area} fill="var(--accent)" opacity={0.08} />
            <path d={line} fill="none" stroke="var(--accent)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
            <line x1={0} x2={plotW} y1={plotH} y2={plotH} stroke="var(--line-strong)" strokeWidth={1} />
            {xTicks.map((t) => (
              <text key={t} x={x(t)} y={plotH + 18} textAnchor={t === 0 ? "start" : "middle"} fontSize={11} fill="var(--ink-3)">
                {t === 0 ? "0" : formatBytes(t)}
              </text>
            ))}
            {activePoint ? (
              <g>
                <line
                  x1={mid(activePoint.offset)}
                  x2={mid(activePoint.offset)}
                  y1={0}
                  y2={plotH}
                  stroke="var(--ink-3)"
                  strokeWidth={1}
                />
                <circle
                  cx={mid(activePoint.offset)}
                  cy={y(activePoint.entropy)}
                  r={4.5}
                  fill="var(--accent)"
                  stroke="var(--surface)"
                  strokeWidth={2}
                />
              </g>
            ) : null}
          </g>
        );
      }}
    </ChartFrame>
  );
}
