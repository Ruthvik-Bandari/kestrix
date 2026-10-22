// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { DiagramData } from "./blocks";
import { docPages } from "./content";
import { DiagramView } from "./DiagramView";
import { architectureDiagram, emailFlowDiagram, pluginFlowDiagram } from "./diagrams";
import { describeDiagram, layoutDiagram, WIDTH, type Box } from "./diagramLayout";

afterEach(cleanup);

const all: [string, DiagramData][] = [
  ["architecture", architectureDiagram],
  ["email flow", emailFlowDiagram],
  ["plugin flow", pluginFlowDiagram],
];

const overlaps = (a: Box, b: Box, pad = 0) => a.x < b.x + b.w + pad && b.x < a.x + a.w + pad && a.y < b.y + b.h + pad && b.y < a.y + a.h + pad;

function segmentHitsBox(p: [number, number], q: [number, number], box: Box): boolean {
  const lo: [number, number] = [Math.min(p[0], q[0]), Math.min(p[1], q[1])];
  const hi: [number, number] = [Math.max(p[0], q[0]), Math.max(p[1], q[1])];
  return hi[0] > box.x + 1 && lo[0] < box.x + box.w - 1 && hi[1] > box.y + 1 && lo[1] < box.y + box.h - 1;
}

describe.each(all)("the %s diagram data", (_name, data) => {
  it("has unique ids, and every node, edge and band names something that exists", () => {
    const ids = [...data.groups.map((g) => g.id), ...data.nodes.map((n) => n.id)];
    expect(new Set(ids).size).toBe(ids.length);
    for (const node of data.nodes) expect(data.groups.map((g) => g.id)).toContain(node.group);
    for (const edge of data.edges) {
      expect(ids).toContain(edge.from);
      expect(ids).toContain(edge.to);
    }
    const placed = data.rows.flat().flatMap((cell) => (cell.group ? [cell.group] : []));
    expect([...placed].sort()).toEqual(data.groups.map((g) => g.id).sort());
    for (const row of data.rows) expect(row.reduce((sum, cell) => sum + cell.span, 0)).toBe(12);
  });

  it("is laid out without overlaps: nodes inside their group, labels clear, arrows around the boxes", () => {
    const layout = layoutDiagram(data);
    expect(layout.nodes).toHaveLength(data.nodes.length);
    expect(layout.edges).toHaveLength(data.edges.length);
    for (const { node, box } of layout.nodes) {
      const group = layout.groups.find((g) => g.group.id === node.group);
      expect(group, node.id).toBeDefined();
      expect(box.x).toBeGreaterThanOrEqual((group?.box.x ?? 0) + 1);
      expect(box.x + box.w).toBeLessThanOrEqual((group?.box.x ?? 0) + (group?.box.w ?? 0) - 1);
      expect(box.y + box.h).toBeLessThanOrEqual((group?.box.y ?? 0) + (group?.box.h ?? 0));
    }
    for (const [i, a] of layout.nodes.entries()) for (const b of layout.nodes.slice(i + 1)) expect(overlaps(a.box, b.box), `${a.node.id} and ${b.node.id}`).toBe(false);
    for (const [i, a] of layout.groups.entries()) for (const b of layout.groups.slice(i + 1)) expect(overlaps(a.box, b.box), `${a.group.id} and ${b.group.id}`).toBe(false);

    const labels = layout.edges.flatMap((e) => (e.label ? [{ edge: e, box: e.label.box }] : []));
    expect(labels).toHaveLength(data.edges.filter((e) => e.label).length);
    for (const [i, a] of labels.entries()) {
      expect(a.box.x, a.edge.label?.text).toBeGreaterThanOrEqual(0);
      expect(a.box.x + a.box.w, a.edge.label?.text).toBeLessThanOrEqual(WIDTH);
      for (const n of layout.nodes) expect(overlaps(a.box, n.box), `${a.edge.label?.text} over ${n.node.id}`).toBe(false);
      for (const b of labels.slice(i + 1)) expect(overlaps(a.box, b.box), `${a.edge.label?.text} over ${b.edge.label?.text}`).toBe(false);
    }

    for (const placed of layout.edges) {
      const ends = new Set([placed.edge.from, placed.edge.to]);
      const pts = placed.points;
      for (let i = 1; i < pts.length; i++) {
        const [p, q] = [pts[i - 1], pts[i]];
        if (!p || !q) continue;
        for (const n of layout.nodes) {
          if (ends.has(n.node.id)) continue;
          expect(segmentHitsBox(p, q, n.box), `${placed.edge.from} -> ${placed.edge.to} crosses ${n.node.id}`).toBe(false);
        }
      }
    }
  });
});

describe("DiagramView", () => {
  it.each(all)("draws every node and edge of the %s diagram as real text and paths", (_name, data) => {
    const { container } = render(<DiagramView diagram={data} />);
    const svg = container.querySelector("svg");
    expect(svg?.getAttribute("role")).toBe("img");
    expect(svg?.getAttribute("aria-label")).toContain(data.title);
    for (const node of data.nodes) {
      const first = node.label.split(" ")[0] ?? node.label;
      expect(within(svg as unknown as HTMLElement).getAllByText((text) => text.includes(first)).length, node.id).toBeGreaterThan(0);
    }
    expect(svg?.querySelectorAll("path[marker-end]")).toHaveLength(data.edges.length);
    expect(svg?.querySelectorAll("rect").length).toBe(data.nodes.length + data.groups.length);
  });

  it.each(all)("lists every group, node and edge of the %s diagram in a text description", (_name, data) => {
    const { container } = render(<DiagramView diagram={data} />);
    const description = describeDiagram(data);
    expect(description.edges).toHaveLength(data.edges.length);
    for (const edge of description.edges) expect(screen.getAllByText(edge).length).toBeGreaterThan(0);
    for (const group of data.groups) expect(container.querySelector(`section[aria-label="${group.title}"]`)).not.toBeNull();
    const list = container.querySelector("div.sr-only, div[class*='sr-only']");
    expect(list?.textContent).toContain("→");
    for (const node of data.nodes) expect(list?.textContent).toContain(node.label);
  });

  it("states what leaves the machine in the overview's edge text", () => {
    const edges = describeDiagram(architectureDiagram).edges;
    expect(edges).toContain("Website check → Target website: read-only GETs (leaves your machine, only when you ask)");
    expect(edges).toContain("Server → One shared core: same functions");
  });

  it.each(all)("has no links, images or remote addresses in the %s diagram", (_name, data) => {
    const { container } = render(<DiagramView diagram={data} />);
    expect(container.querySelectorAll("a, img, image, use, foreignObject, script")).toHaveLength(0);
    expect(container.innerHTML).not.toMatch(/https?:\/\/|url\(\s*["']?(?!#)/);
    expect(container.querySelectorAll("[style]")).toHaveLength(0);
  });
});

describe("the diagrams in the documentation", () => {
  const where = (data: DiagramData) =>
    docPages.filter((page) => page.sections.some((s) => s.blocks.some((b) => b.kind === "diagram" && b.diagram === data))).map((page) => page.path);

  it("puts each one on the page it explains", () => {
    expect(where(architectureDiagram).sort()).toEqual(["getting-started/what-is-kestrix", "reference/architecture"]);
    expect(where(emailFlowDiagram)).toEqual(["tools/email/how-it-works"]);
    expect(where(pluginFlowDiagram)).toEqual(["code-security/claude-plugin/hooks"]);
  });
});
