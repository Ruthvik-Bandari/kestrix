// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { DiagramData, DiagramEdge, DiagramGroup, DiagramNode } from "./blocks";

/*
 * Layout of a docs diagram: pure geometry, so it can be tested without a browser. Groups sit on a 12-column
 * grid, one band (row) after another; the nodes of a group fill a grid inside it. Arrows are orthogonal:
 * they leave the bottom (or top) of a box, run along a "lane" in the gutter between bands, and arrive at the
 * top (or bottom) of the target; boxes on the same band are joined by a straight arrow. The data is
 * responsible for leaving clear columns where an arrow has to cross a band (the layout test checks it).
 */

export const WIDTH = 800;
const MARGIN = 8;
const COLS = 12;
const GROUP_INSET = 5;
const GROUP_PAD = 12;
const TITLE_H = 30;
const GAP_FLOW = 36;
const GAP_PLAIN = 16;
const GAP_ROW = 16;
const LANE = 19;
const LABEL_PX = 13;
const SUB_PX = 11;
const EDGE_PX = 11.5;
const LINE_L = 16;
const LINE_S = 14;
const SPREAD = 18;

export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface PlacedNode {
  node: DiagramNode;
  box: Box;
  label: string[];
  sublabel: string[];
}

export interface PlacedGroup {
  group: DiagramGroup;
  box: Box;
}

export interface PlacedEdge {
  edge: DiagramEdge;
  /** SVG path data, with rounded corners. */
  d: string;
  /** The corners of the route. */
  points: [number, number][];
  label?: { text: string; x: number; y: number; anchor: "start" | "middle" | "end"; box: Box };
}

export interface DiagramLayout {
  width: number;
  height: number;
  groups: PlacedGroup[];
  nodes: PlacedNode[];
  edges: PlacedEdge[];
}

/** Rough text width for IBM Plex Sans at a size: wide enough that wrapped lines never run past a box. */
export function textWidth(text: string, px: number, bold = false): number {
  return text.length * px * (bold ? 0.6 : 0.55);
}

function wrap(text: string, px: number, bold: boolean, max: number): string[] {
  const lines: string[] = [];
  let line = "";
  for (const word of text.split(/\s+/).filter(Boolean)) {
    const next = line ? `${line} ${word}` : word;
    if (line && textWidth(next, px, bold) > max) {
      lines.push(line);
      line = word;
    } else line = next;
  }
  if (line) lines.push(line);
  return lines;
}

interface Entity {
  id: string;
  isNode: boolean;
  box: Box;
  row: number;
  group: string;
  nodeRow: number;
}

type Side = "t" | "b";
interface Route {
  edge: DiagramEdge;
  index: number;
  kind: "horizontal" | "down" | "up";
  from: Entity;
  to: Entity;
  sx: number;
  tx: number;
  /** The gap the lane lives in: "g<row>" between two bands, or "in:<group>:<node row>" inside a group. */
  gap: string;
  lane: number;
  label: string | undefined;
  labelW: number;
}

export function layoutDiagram(data: DiagramData): DiagramLayout {
  const groupById = new Map(data.groups.map((g) => [g.id, g]));
  const colW = (WIDTH - MARGIN * 2) / COLS;

  // ---- 1. Columns: where each group sits, and each node's width, text and height.
  const placedGroups: { group: DiagramGroup; row: number; x: number; w: number; nodes: DiagramNode[]; cols: number; gapX: number; nodeW: number; nodeRows: number[] }[] = [];
  data.rows.forEach((row, rowIndex) => {
    let col = 0;
    for (const cell of row) {
      const group = cell.group ? groupById.get(cell.group) : undefined;
      if (group) {
        const nodes = data.nodes.filter((n) => n.group === group.id);
        const cols = Math.max(1, group.columns ?? nodes.length);
        const flows = data.edges.some((e) => nodes.some((n) => n.id === e.from) && nodes.some((n) => n.id === e.to));
        const gapX = flows ? GAP_FLOW : GAP_PLAIN;
        const x = MARGIN + col * colW + GROUP_INSET;
        const w = cell.span * colW - GROUP_INSET * 2;
        const nodeW = (w - GROUP_PAD * 2 - (cols - 1) * gapX) / cols;
        placedGroups.push({ group, row: rowIndex, x, w, nodes, cols, gapX, nodeW, nodeRows: [] });
      }
      col += cell.span;
    }
  });

  const textOf = new Map<string, { label: string[]; sublabel: string[]; h: number }>();
  for (const g of placedGroups) {
    const inner = g.nodeW - 20;
    const nodeRowCount = Math.ceil(g.nodes.length / g.cols);
    for (let r = 0; r < nodeRowCount; r++) {
      let height = 0;
      for (const node of g.nodes.slice(r * g.cols, (r + 1) * g.cols)) {
        const label = wrap(node.label, LABEL_PX, true, inner);
        const sublabel = node.sublabel ? wrap(node.sublabel, SUB_PX, false, inner) : [];
        const h = 20 + label.length * LINE_L + sublabel.length * LINE_S + (sublabel.length ? 3 : 0);
        textOf.set(node.id, { label, sublabel, h });
        height = Math.max(height, h);
      }
      g.nodeRows.push(Math.max(44, height));
    }
  }

  // ---- 2. Entities with columns known, rows (y) pending.
  const entities = new Map<string, Entity>();
  for (const g of placedGroups) {
    entities.set(g.group.id, { id: g.group.id, isNode: false, box: { x: g.x, y: 0, w: g.w, h: 0 }, row: g.row, group: g.group.id, nodeRow: -1 });
    g.nodes.forEach((node, i) => {
      const r = Math.floor(i / g.cols);
      const c = i % g.cols;
      entities.set(node.id, {
        id: node.id,
        isNode: true,
        box: { x: g.x + GROUP_PAD + c * (g.nodeW + g.gapX), y: 0, w: g.nodeW, h: g.nodeRows[r] ?? 44 },
        row: g.row,
        group: g.group.id,
        nodeRow: r,
      });
    });
  }

  // ---- 3. Routes: which way each arrow runs and where it attaches horizontally.
  const routes: Route[] = [];
  data.edges.forEach((edge, index) => {
    const from = entities.get(edge.from);
    const to = entities.get(edge.to);
    if (!from || !to) throw new Error(`diagram edge ${edge.from} -> ${edge.to}: unknown id`);
    const sameBand = from.row === to.row;
    const inGroupSameRow = sameBand && from.isNode && to.isNode && from.group === to.group && from.nodeRow === to.nodeRow;
    const kind: Route["kind"] = inGroupSameRow || (sameBand && !(from.isNode && to.isNode && from.group === to.group)) ? "horizontal" : sameBand ? (to.nodeRow > from.nodeRow ? "down" : "up") : to.row > from.row ? "down" : "up";
    const gap = kind === "horizontal" ? "" : sameBand ? `in:${from.group}:${Math.min(from.nodeRow, to.nodeRow)}` : `g${kind === "down" ? from.row : from.row - 1}`;
    routes.push({ edge, index, kind, from, to, sx: 0, tx: 0, gap, lane: -1, label: edge.label, labelW: edge.label ? textWidth(edge.label, EDGE_PX) : 0 });
  });

  const vertical = routes.filter((r) => r.kind !== "horizontal");
  const side = (r: Route, end: "from" | "to"): Side => ((r.kind === "down") === (end === "from") ? "b" : "t");
  const center = (e: Entity) => e.box.x + e.box.w / 2;
  const clamp = (v: number, e: Entity) => Math.min(Math.max(v, e.box.x + 14), e.box.x + e.box.w - 14);

  // Spread the arrows that share one side of one node, ordered by where they go, so they do not stack.
  const spread = new Map<string, number>();
  const groupsOfEnds = new Map<string, Route[]>();
  for (const r of vertical) {
    for (const end of ["from", "to"] as const) {
      const e = r[end];
      if (!e.isNode) continue;
      const key = `${e.id}:${side(r, end)}`;
      groupsOfEnds.set(key, [...(groupsOfEnds.get(key) ?? []), r]);
    }
  }
  for (const [key, list] of groupsOfEnds) {
    const entityId = key.slice(0, key.lastIndexOf(":"));
    const node = entities.get(entityId);
    if (!node) continue;
    const otherX = (r: Route) => center(r.from.id === entityId ? r.to : r.from);
    const sorted = [...list].sort((a, b) => otherX(a) - otherX(b) || a.index - b.index);
    sorted.forEach((r, i) => {
      const end = r.from.id === entityId ? "from" : "to";
      spread.set(`${r.index}:${end}`, center(node) + (i - (sorted.length - 1) / 2) * SPREAD);
    });
  }
  const soleEnd = (r: Route, end: "from" | "to") => (groupsOfEnds.get(`${r[end].id}:${side(r, end)}`)?.length ?? 0) === 1;
  for (const r of vertical) {
    const fromX = spread.get(`${r.index}:from`);
    const toX = spread.get(`${r.index}:to`);
    if (fromX !== undefined && toX !== undefined) {
      r.sx = fromX;
      r.tx = toX;
      // A lone arrow into a node that sits right under (or over) its source goes straight.
      const inside = (x: number, e: Entity) => x >= e.box.x + 10 && x <= e.box.x + e.box.w - 10;
      if (soleEnd(r, "to") && inside(fromX, r.to)) r.tx = fromX;
      else if (soleEnd(r, "from") && inside(toX, r.from)) r.sx = toX;
    } else if (fromX !== undefined) {
      r.sx = fromX;
      r.tx = clamp(fromX, r.to);
    } else if (toX !== undefined) {
      r.tx = toX;
      r.sx = clamp(toX, r.from);
    } else {
      const lo = Math.max(r.from.box.x, r.to.box.x) + 14;
      const hi = Math.min(r.from.box.x + r.from.box.w, r.to.box.x + r.to.box.w) - 14;
      if (lo <= hi) r.sx = r.tx = (lo + hi) / 2;
      else {
        r.sx = clamp(center(r.to), r.from);
        r.tx = clamp(center(r.from), r.to);
      }
    }
  }
  // Several arrows into one group edge: keep them apart.
  for (const end of ["from", "to"] as const) {
    const byGroupSide = new Map<string, Route[]>();
    for (const r of vertical) {
      if (r[end].isNode) continue;
      const key = `${r[end].id}:${side(r, end)}`;
      byGroupSide.set(key, [...(byGroupSide.get(key) ?? []), r]);
    }
    for (const list of byGroupSide.values()) {
      const pos = (r: Route) => (end === "from" ? r.sx : r.tx);
      const sorted = [...list].sort((a, b) => pos(a) - pos(b));
      for (let i = 1; i < sorted.length; i++) {
        const prev = sorted[i - 1];
        const cur = sorted[i];
        if (!prev || !cur) continue;
        const need = pos(prev) + SPREAD;
        if (pos(cur) >= need) continue;
        const straight = (r: Route) => Math.abs(r.sx - r.tx) <= 1;
        // Move the arrow that already bends; leave a straight one where it is.
        const [mover, target] = straight(cur) && !straight(prev) ? [prev, pos(cur) - SPREAD] : [cur, need];
        const moved = clamp(target, mover[end]);
        if (end === "from") mover.sx = moved;
        else mover.tx = moved;
      }
    }
  }

  // ---- 4. Lanes: give each jogged or labelled arrow a line in its gap, sharing a line where spans do not meet.
  const slotOf = (r: Route): [number, number] => {
    const lo = Math.min(r.sx, r.tx);
    const hi = Math.max(r.sx, r.tx);
    if (!r.label) return [lo, hi];
    const jogged = hi - lo > 1;
    if (jogged && hi - lo >= r.labelW + 8) return [lo, hi];
    const edge = jogged ? hi : lo;
    if (edge + 8 + r.labelW > WIDTH - MARGIN) return [Math.min(lo, edge - 8 - r.labelW), hi];
    return [lo, Math.max(hi, edge + 8 + r.labelW)];
  };
  const lanesOfGap = new Map<string, { end: number }[]>();
  for (const r of [...vertical].sort((a, b) => slotOf(a)[0] - slotOf(b)[0])) {
    if (Math.abs(r.sx - r.tx) <= 1 && !r.label) continue;
    const [lo, hi] = slotOf(r);
    const lanes = lanesOfGap.get(r.gap) ?? [];
    let lane = lanes.findIndex((l) => l.end + 10 < lo);
    if (lane < 0) {
      lane = lanes.length;
      lanes.push({ end: hi });
    } else lanes[lane] = { end: hi };
    r.lane = lane;
    lanesOfGap.set(r.gap, lanes);
  }
  const inGroupArrows = new Set(vertical.filter((r) => r.gap.startsWith("in:")).map((r) => r.gap));
  const gapHeight = (gap: string, floor = 34) => {
    const n = lanesOfGap.get(gap)?.length ?? 0;
    const base = gap.startsWith("in:") && !inGroupArrows.has(gap) ? GAP_ROW : floor;
    return Math.max(base, 16 + n * LANE);
  };

  // ---- 5. Rows (y): node rows inside groups, group heights, bands and gutters.
  const bandTop: number[] = [];
  const bandHeight: number[] = [];
  const gutterTop: number[] = [];
  const gutterH: number[] = [];
  let y = MARGIN;
  const groupHeight = (g: (typeof placedGroups)[number]) => {
    let h = TITLE_H;
    g.nodeRows.forEach((rh, r) => {
      h += rh;
      if (r < g.nodeRows.length - 1) h += gapHeight(`in:${g.group.id}:${r}`);
    });
    return h + GROUP_PAD;
  };
  data.rows.forEach((_, i) => {
    const h = Math.max(...placedGroups.filter((g) => g.row === i).map(groupHeight), 0);
    bandTop[i] = y;
    bandHeight[i] = h;
    y += h;
    if (i < data.rows.length - 1) {
      gutterTop[i] = y;
      gutterH[i] = gapHeight(`g${i}`);
      y += gutterH[i] ?? 34;
    }
  });
  const height = y + MARGIN;

  const nodes: PlacedNode[] = [];
  const groups: PlacedGroup[] = [];
  const nodeRowTop = new Map<string, number[]>();
  for (const g of placedGroups) {
    const top = bandTop[g.row] ?? 0;
    const e = entities.get(g.group.id);
    if (e) {
      e.box.y = top;
      e.box.h = bandHeight[g.row] ?? 0;
    }
    groups.push({ group: g.group, box: { x: g.x, y: top, w: g.w, h: bandHeight[g.row] ?? 0 } });
    let ny = top + TITLE_H;
    const tops: number[] = [];
    g.nodeRows.forEach((rh, r) => {
      tops.push(ny);
      ny += rh + gapHeight(`in:${g.group.id}:${r}`);
    });
    nodeRowTop.set(g.group.id, tops);
    g.nodes.forEach((node) => {
      const e2 = entities.get(node.id);
      const text = textOf.get(node.id);
      if (!e2 || !text) return;
      e2.box.y = tops[e2.nodeRow] ?? top;
      nodes.push({ node, box: { ...e2.box }, label: text.label, sublabel: text.sublabel });
    });
  }

  // ---- 6. Paths.
  const edges: PlacedEdge[] = routes.map((r) => {
    const { from, to } = r;
    let points: [number, number][];
    let label: PlacedEdge["label"];
    const place = (x: number, baseline: number, anchor: "start" | "middle" | "end") => {
      if (!r.label) return;
      const w = r.labelW;
      const left = anchor === "middle" ? x - w / 2 : anchor === "end" ? x - w : x;
      label = { text: r.label, x, y: baseline, anchor, box: { x: left, y: baseline - 11, w, h: 15 } };
    };
    if (r.kind === "horizontal") {
      const lo = Math.max(from.box.y, to.box.y);
      const hi = Math.min(from.box.y + from.box.h, to.box.y + to.box.h);
      const yy = hi > lo ? (lo + hi) / 2 : from.box.y + from.box.h / 2;
      const right = center(to) > center(from);
      const x1 = right ? from.box.x + from.box.w : from.box.x;
      const x2 = right ? to.box.x : to.box.x + to.box.w;
      points = [
        [x1, yy],
        [x2, yy],
      ];
      place((x1 + x2) / 2, yy - 6, "middle");
    } else {
      const down = r.kind === "down";
      const y1 = down ? from.box.y + from.box.h : from.box.y;
      const y2 = down ? to.box.y : to.box.y + to.box.h;
      const jogged = Math.abs(r.sx - r.tx) > 1;
      let laneY = (y1 + y2) / 2;
      if (r.lane >= 0) {
        const inGroup = r.gap.startsWith("in:");
        const gi = inGroup ? 0 : Number(r.gap.slice(1));
        const top = inGroup ? (nodeRowTop.get(from.group)?.[Math.min(from.nodeRow, to.nodeRow)] ?? 0) + (placedGroups.find((g) => g.group.id === from.group)?.nodeRows[Math.min(from.nodeRow, to.nodeRow)] ?? 0) : (gutterTop[gi] ?? 0);
        laneY = top + 14 + r.lane * LANE;
      }
      points = jogged
        ? [
            [r.sx, y1],
            [r.sx, laneY],
            [r.tx, laneY],
            [r.tx, y2],
          ]
        : [
            [r.sx, y1],
            [r.tx, y2],
          ];
      if (r.label) {
        const lo = Math.min(r.sx, r.tx);
        const hi = Math.max(r.sx, r.tx);
        if (jogged && hi - lo >= r.labelW + 8) place((lo + hi) / 2, laneY - 5, "middle");
        else if ((jogged ? hi : lo) + 8 + r.labelW > WIDTH - MARGIN) place(lo - 8, laneY + 4, "end");
        else place((jogged ? hi : lo) + 8, laneY + 4, "start");
      }
    }
    return { edge: r.edge, points, d: roundedPath(points), ...(label ? { label } : {}) };
  });

  return { width: WIDTH, height, groups, nodes, edges };
}

function roundedPath(points: [number, number][], radius = 7): string {
  const first = points[0];
  if (!first) return "";
  let d = `M${first[0]} ${first[1]}`;
  for (let i = 1; i < points.length; i++) {
    const prev = points[i - 1];
    const cur = points[i];
    const next = points[i + 1];
    if (!prev || !cur) continue;
    if (!next) {
      d += ` L${cur[0]} ${cur[1]}`;
      continue;
    }
    const inLen = Math.hypot(cur[0] - prev[0], cur[1] - prev[1]);
    const outLen = Math.hypot(next[0] - cur[0], next[1] - cur[1]);
    const r = Math.min(radius, inLen / 2, outLen / 2);
    const a: [number, number] = [cur[0] - ((cur[0] - prev[0]) / inLen) * r, cur[1] - ((cur[1] - prev[1]) / inLen) * r];
    const b: [number, number] = [cur[0] + ((next[0] - cur[0]) / outLen) * r, cur[1] + ((next[1] - cur[1]) / outLen) * r];
    d += ` L${a[0]} ${a[1]} Q${cur[0]} ${cur[1]} ${b[0]} ${b[1]}`;
  }
  return d;
}

/** The diagram as text, in reading order: what the screen reader, the narrow-screen list and the search index use. */
export function describeDiagram(data: DiagramData): { groups: { title: string; outside: boolean; nodes: { label: string; sublabel: string | undefined; kind: string }[] }[]; edges: string[] } {
  const names = new Map<string, string>();
  for (const g of data.groups) names.set(g.id, g.title);
  for (const n of data.nodes) names.set(n.id, n.label);
  return {
    groups: data.groups.map((g) => ({
      title: g.title,
      outside: g.outside === true,
      nodes: data.nodes.filter((n) => n.group === g.id).map((n) => ({ label: n.label, sublabel: n.sublabel, kind: n.kind ?? "box" })),
    })),
    edges: data.edges.map((e) => `${names.get(e.from) ?? e.from} → ${names.get(e.to) ?? e.to}${e.label ? `: ${e.label}` : ""}${e.dashed ? " (leaves your machine, only when you ask)" : ""}`),
  };
}
