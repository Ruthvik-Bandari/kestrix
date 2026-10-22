// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, useMemo } from "react";
import type { DiagramData } from "./blocks";
import { describeDiagram, layoutDiagram, type PlacedNode } from "./diagramLayout";

const KIND_NOTE: Record<string, string> = { store: "kept data", external: "outside Kestrix" };

function NodeShape({ placed }: { placed: PlacedNode }) {
  const { box, node } = placed;
  const kind = node.kind ?? "box";
  const cx = box.x + box.w / 2;
  const textTop = box.y + 10;
  return (
    <g>
      <rect
        x={box.x}
        y={box.y}
        width={box.w}
        height={box.h}
        rx={9}
        className={kind === "external" ? "fill-bg stroke-ink-3" : kind === "store" ? "fill-accent-soft stroke-accent-text" : "fill-surface-solid stroke-line-strong"}
        strokeWidth={1.25}
        strokeDasharray={kind === "external" ? "5 4" : undefined}
      />
      {kind === "store" ? <line x1={box.x} x2={box.x + box.w} y1={box.y + 7} y2={box.y + 7} className="stroke-accent-text" strokeWidth={1} /> : null}
      <text textAnchor="middle" className="fill-ink" fontSize={13} fontWeight={600}>
        {placed.label.map((line, i) => (
          <tspan key={i} x={cx} y={textTop + (kind === "store" ? 3 : 0) + 11 + i * 16}>
            {line}
          </tspan>
        ))}
      </text>
      {placed.sublabel.length > 0 ? (
        <text textAnchor="middle" className="fill-ink-2" fontSize={11}>
          {placed.sublabel.map((line, i) => (
            <tspan key={i} x={cx} y={textTop + (kind === "store" ? 3 : 0) + placed.label.length * 16 + 12 + i * 14}>
              {line}
            </tspan>
          ))}
        </text>
      ) : null}
    </g>
  );
}

/** An architecture or flow diagram, drawn as inline SVG from data. Narrow containers get the same content as a list. */
export function DiagramView({ diagram }: { diagram: DiagramData }) {
  const marker = useId();
  const layout = useMemo(() => layoutDiagram(diagram), [diagram]);
  const text = useMemo(() => describeDiagram(diagram), [diagram]);
  return (
    <figure className="@container my-2 max-w-full">
      <figcaption className="mb-2 text-[0.8125rem] font-semibold text-ink-2">{diagram.title}</figcaption>
      <div className="hidden @min-[620px]:block">
        <svg
          role="img"
          aria-label={`${diagram.title}. ${diagram.summary}`}
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          className="block h-auto w-full"
          fontFamily="inherit"
        >
          <defs>
            <marker id={marker} viewBox="0 0 10 10" refX={9} refY={5} markerWidth={8} markerHeight={8} orient="auto">
              <path d="M0 1 L9 5 L0 9 Z" className="fill-ink-2" />
            </marker>
          </defs>
          {layout.groups.map(({ group, box }) => (
            <g key={group.id}>
              <rect
                x={box.x}
                y={box.y}
                width={box.w}
                height={box.h}
                rx={14}
                className="fill-inset/50 stroke-line-strong"
                strokeWidth={1}
                strokeDasharray={group.outside ? "3 4" : undefined}
              />
            </g>
          ))}
          {layout.edges.map(({ edge, d }, i) => (
            <path
              key={i}
              d={d}
              fill="none"
              className="stroke-ink-2"
              strokeWidth={1.5}
              strokeDasharray={edge.dashed ? "6 4" : undefined}
              markerEnd={`url(#${marker})`}
            />
          ))}
          {layout.groups.map(({ group, box }) => (
            <text
              key={group.id}
              x={box.x + 14}
              y={box.y + 20}
              className="fill-ink-2 stroke-bg"
              fontSize={11}
              fontWeight={600}
              letterSpacing={0.6}
              strokeWidth={4}
              strokeLinejoin="round"
              paintOrder="stroke"
            >
              {group.title.toUpperCase()}
            </text>
          ))}
          {layout.nodes.map((placed) => (
            <NodeShape key={placed.node.id} placed={placed} />
          ))}
          {layout.edges.map(({ label }, i) =>
            label ? (
              <text
                key={i}
                x={label.x}
                y={label.y}
                textAnchor={label.anchor}
                className="fill-ink stroke-bg"
                fontSize={11.5}
                fontWeight={500}
                strokeWidth={4}
                strokeLinejoin="round"
                paintOrder="stroke"
              >
                {label.text}
              </text>
            ) : null,
          )}
        </svg>
      </div>
      <div className="@min-[620px]:sr-only">
        <p className="text-[0.8125rem] text-ink-2 @min-[620px]:sr-only">{diagram.summary}</p>
        <div className="mt-3 space-y-3">
          {text.groups.map((group) => (
            <section key={group.title} aria-label={group.title} className={`rounded-xl border bg-inset/50 px-3.5 py-3 ${group.outside ? "border-dashed border-line-strong" : "border-line"}`}>
              <h4 className="text-[0.75rem] font-semibold uppercase tracking-wide text-ink-2">{group.title}</h4>
              <ul className="mt-2 space-y-2">
                {group.nodes.map((node) => (
                  <li key={node.label} className="text-[0.875rem] leading-snug text-ink">
                    <span className="font-semibold">{node.label}</span>
                    {KIND_NOTE[node.kind] ? <span className="text-ink-3"> ({KIND_NOTE[node.kind]})</span> : null}
                    {node.sublabel ? <span className="block text-ink-2">{node.sublabel}</span> : null}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
        <h4 className="mt-4 text-[0.75rem] font-semibold uppercase tracking-wide text-ink-2">Connections</h4>
        <ul className="mt-2 space-y-1.5 text-[0.875rem] text-ink">
          {text.edges.map((edge) => (
            <li key={edge}>{edge}</li>
          ))}
        </ul>
      </div>
      {diagram.legend ? <p className="mt-2 max-w-[70ch] text-[0.8125rem] text-ink-3">{diagram.legend}</p> : null}
    </figure>
  );
}
