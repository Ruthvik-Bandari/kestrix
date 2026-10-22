// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PRIVACY_PATH, TERMS_PATH } from "../../app/paths";
import { tools } from "../../app/tools";
import { blockText, search, sectionIds } from "./search";
import type { Block } from "./blocks";
import { ancestorPaths, breadcrumbs, docPages, docTree, metaOf, pageAt, readingOrder, resolveDoc } from "./content";
import DocsPage, { sectionLinks } from "./DocsPage";
import { LEGACY_DOC_PATHS, TOOL_DOC_PATH, type TreeNode } from "./model";

function renderDocs(path: string) {
  const router = createMemoryRouter(
    [
      { path: "/docs", element: <DocsPage /> },
      { path: "/docs/*", element: <DocsPage /> },
    ],
    { initialEntries: [path] },
  );
  render(<RouterProvider router={router} />);
  return router;
}

const tree = () => screen.getByRole("navigation", { name: "Documentation" });

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** jsdom has no layout: say whether the sidebar's width query matches. */
function viewport(wide: boolean) {
  vi.stubGlobal("matchMedia", (query: string) => ({ matches: wide, media: query, addEventListener: () => undefined, removeEventListener: () => undefined }));
}

function allNodes(nodes: TreeNode[]): TreeNode[] {
  return nodes.flatMap((node) => [node, ...(node.children ? allNodes(node.children) : [])]);
}

function allBlocks(): { path: string; block: Block }[] {
  return docPages.flatMap((page) => page.sections.flatMap((section) => section.blocks.map((block) => ({ path: page.path, block }))));
}

describe("the documentation tree", () => {
  it("lists every page once, in sections, with the current page marked and its parents open", () => {
    renderDocs("/docs/tools/email/how-it-works");
    const nav = tree();
    expect(within(nav).getAllByText(/^(Getting started|Tools|Code security|Security and trust|Reference)$/).map((n) => n.textContent)).toEqual([
      "Getting started",
      "Tools",
      "Code security",
      "Security and trust",
      "Reference",
    ]);
    expect(within(nav).getByRole("link", { name: "How it works" }).getAttribute("aria-current")).toBe("page");
    expect(within(nav).getByRole("link", { name: "Email check" }).getAttribute("aria-current")).toBeNull();
    const toggle = within(nav).getByRole("button", { name: "Email check: collapse pages" });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    // Another tool's pages are collapsed: their links are not exposed.
    expect(within(nav).getByRole("button", { name: "Web check: expand pages" }).getAttribute("aria-expanded")).toBe("false");
    expect(within(nav).queryByRole("link", { name: "Findings reference", hidden: false })).not.toBeNull();
    // Every page of the tree is a link somewhere in the DOM (collapsed ones are hidden).
    const hrefs = within(nav).getAllByRole("link", { hidden: true }).map((link) => link.getAttribute("href"));
    for (const node of allNodes(docTree.flatMap((group) => group.nodes))) expect(hrefs).toContain(`/docs/${node.path}`);
  });

  it("opens and closes a branch with its disclosure button", () => {
    renderDocs("/docs");
    const button = within(tree()).getByRole("button", { name: "Web check: expand pages" });
    fireEvent.click(button);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(within(tree()).getAllByRole("link", { name: "Using it" }).length).toBeGreaterThan(0);
    fireEvent.click(within(tree()).getByRole("button", { name: "Web check: collapse pages" }));
    expect(within(tree()).getByRole("button", { name: "Web check: expand pages" }).getAttribute("aria-expanded")).toBe("false");
  });

  it("has every page in the tree exactly once and every tree node a page", () => {
    const paths = allNodes(docTree.flatMap((group) => group.nodes)).map((node) => node.path);
    expect(new Set(paths).size).toBe(paths.length);
    expect([...paths].sort()).toEqual(docPages.filter((page) => page.path !== "").map((page) => page.path).sort());
    expect(new Set(docPages.map((page) => page.path)).size).toBe(docPages.length);
  });
});

describe("a page", () => {
  it("shows the home page with every section and no previous link", () => {
    renderDocs("/docs");
    expect(screen.getByRole("heading", { level: 1, name: "Kestrix documentation" })).toBeTruthy();
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual(docTree.map((group) => group.title));
    expect(within(tree()).getByRole("link", { name: "Documentation home" }).getAttribute("aria-current")).toBe("page");
    const pager = screen.getByRole("navigation", { name: "Previous and next pages" });
    expect(within(pager).queryByText("Previous")).toBeNull();
    expect(within(pager).getByText("Next")).toBeTruthy();
  });

  it("shows breadcrumbs, an On this page list that matches its headings, the page type and its sources", () => {
    renderDocs("/docs/tools/email/findings");
    const crumbs = within(screen.getByRole("navigation", { name: "Breadcrumb" })).getAllByRole("listitem");
    expect(crumbs.map((c) => c.textContent)).toEqual(["Docs", "Tools", "Email check", "Findings reference"]);
    expect(within(crumbs[3] as HTMLElement).getByText("Findings reference").getAttribute("aria-current")).toBe("page");
    expect(document.querySelector("p.eyebrow")?.textContent).toBeTruthy();
    expect(screen.getByText(/Content last checked against it on/)).toBeTruthy();
    const toc = screen.getByRole("navigation", { name: "On this page" });
    const headings = screen.getAllByRole("heading", { level: 2 });
    const links = within(toc).getAllByRole("link");
    expect(links.map((l) => l.textContent)).toEqual(headings.map((h) => h.textContent));
    for (const [i, link] of links.entries()) expect(document.getElementById((link.getAttribute("href") ?? "").slice(1))).toBe(headings[i]);
    expect(sectionLinks(pageAt("tools/email/findings") as never).length).toBe(headings.length);
  });

  it("renders findings tables with the id, severity and reason", () => {
    renderDocs("/docs/tools/email/findings");
    const table = screen.getAllByRole("table")[0] as HTMLElement;
    expect(within(table).getByRole("columnheader", { name: "Severity" })).toBeTruthy();
    expect(within(table).getByText((_, el) => el?.tagName === "CODE" && el.textContent === "mail.auth.dmarc_fail")).toBeTruthy();
  });

  it("links previous and next in the order of the tree", () => {
    for (const [i, page] of readingOrder.entries()) {
      cleanup();
      renderDocs(`/docs/${page.path}`);
      const pager = screen.getByRole("navigation", { name: "Previous and next pages" });
      const links = within(pager).getAllByRole("link");
      const expected = [readingOrder[i - 1], readingOrder[i + 1]].filter(Boolean).map((p) => `/docs/${p?.path}`.replace(/\/$/, "") || "/docs");
      expect(links.map((l) => l.getAttribute("href"))).toEqual(expected);
    }
  });

  it("answers an unknown page with a link back to the overview", () => {
    renderDocs("/docs/nope/deeper");
    expect(screen.getByRole("heading", { level: 1, name: "Page not found" })).toBeTruthy();
    expect(screen.getByRole("link", { name: /documentation overview/ }).getAttribute("href")).toBe("/docs");
  });

  it("moves focus to the new page's heading after navigating from the tree", async () => {
    renderDocs("/docs");
    fireEvent.click(within(tree()).getByRole("link", { name: "Installation" }));
    await waitFor(() => {
      expect(document.activeElement).toBe(screen.getByRole("heading", { level: 1, name: "Installation" }));
    });
  });

  it("links nowhere outside the site: no github.com link on any docs page", () => {
    for (const page of docPages) {
      cleanup();
      renderDocs(`/docs/${page.path}`);
      for (const a of screen.getAllByRole("link", { hidden: true })) {
        const href = a.getAttribute("href") ?? "";
        expect(href, `${page.path}: ${href}`).not.toMatch(/github\.com|^https?:/);
      }
    }
  });

  it("has a skip link to the page content", () => {
    renderDocs("/docs/tools/email");
    expect(screen.getByRole("link", { name: "Skip to the page content" }).getAttribute("href")).toBe("#docs-content");
    expect(document.getElementById("docs-content")).not.toBeNull();
  });

  it("opens the tree as a modal drawer and returns focus to its button on Escape", () => {
    renderDocs("/docs/tools/email");
    const open = screen.getByRole("button", { name: "Docs menu" });
    fireEvent.click(open);
    const dialog = screen.getByRole("dialog", { name: "Documentation menu" });
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(within(dialog).getByRole("navigation", { name: "Documentation" })).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(open);
  });
});

describe("old addresses", () => {
  it.each(Object.entries(LEGACY_DOC_PATHS))("sends /docs/%s to its new page", async (old, target) => {
    const router = renderDocs(`/docs/${old}`);
    const to = target === "" ? "/docs" : `/docs/${target}`;
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(to);
    });
    expect(resolveDoc(old).kind).toBe("redirect");
    expect(resolveDoc(target).kind).toBe("page");
  });
});

describe("search", () => {
  it("finds a finding id and shows its page and section", () => {
    const hits = search("dmarc_fail");
    expect(hits[0]?.path).toBe("tools/email/findings");
    expect(hits[0]?.heading).toBe("Authentication (auth)");
    expect(hits[0]?.pageTitle).toBe("Email check: findings reference");
    expect(search("   ")).toEqual([]);
    expect(search("zzzqqqxxx")).toEqual([]);
  });

  it("requires every word and ranks a title match first", () => {
    expect(search("web check limits")[0]?.path).toBe("tools/website/limits");
    expect(search("quickstart")[0]?.path).toBe("getting-started/quickstart");
  });

  it("is operated from the keyboard: / focuses, arrows move, Enter opens, Escape closes", async () => {
    viewport(true);
    const router = renderDocs("/docs");
    const box = screen.getByRole("combobox", { name: "Search the documentation" });
    fireEvent.keyDown(document.body, { key: "/" });
    expect(document.activeElement).toBe(box);
    fireEvent.change(box, { target: { value: "dmarc" } });
    const list = screen.getByRole("listbox", { name: "Search results" });
    const options = within(list).getAllByRole("option");
    expect(options.length).toBeGreaterThan(1);
    expect(box.getAttribute("aria-expanded")).toBe("true");
    expect(options[0]?.getAttribute("aria-selected")).toBe("true");
    expect(box.getAttribute("aria-activedescendant")).toBe(options[0]?.id);
    fireEvent.keyDown(box, { key: "ArrowDown" });
    expect(options[1]?.getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(box, { key: "ArrowUp" });
    fireEvent.keyDown(box, { key: "ArrowUp" });
    expect(options[options.length - 1]?.getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(box, { key: "Escape" });
    expect(screen.queryByRole("listbox")).toBeNull();
    fireEvent.change(box, { target: { value: "dmarc_fail" } });
    fireEvent.keyDown(box, { key: "Enter" });
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/docs/tools/email/findings");
    });
    expect(router.state.location.hash).toMatch(/^#docs-/);
    expect((box as HTMLInputElement).value).toBe("");
  });

  it("opens the drawer on / where the sidebar does not fit, with the search box focused", () => {
    viewport(false);
    renderDocs("/docs");
    fireEvent.keyDown(document.body, { key: "/" });
    const dialog = screen.getByRole("dialog", { name: "Documentation menu" });
    expect(document.activeElement).toBe(within(dialog).getByRole("combobox", { name: "Search the documentation" }));
  });

  it("does not take the / key while you type in a field", () => {
    viewport(true);
    renderDocs("/docs");
    const box = screen.getByRole("combobox", { name: "Search the documentation" });
    box.focus();
    fireEvent.keyDown(box, { key: "/" });
    expect(document.activeElement).toBe(box);
  });

  it("says when nothing matches", () => {
    renderDocs("/docs");
    fireEvent.change(screen.getByRole("combobox", { name: "Search the documentation" }), { target: { value: "zzzqqqxxx" } });
    expect(screen.getByText(/No pages match/)).toBeTruthy();
  });
});

describe("links and content", () => {
  it("resolves every internal link: tree, page lists, see-also, tool links, redirects and search anchors", () => {
    const known = new Set(docPages.map((page) => page.path));
    for (const { path, block } of allBlocks()) {
      if (block.kind === "see") expect(known.has(block.to), `${path} -> ${block.to}`).toBe(true);
      if (block.kind === "pages") for (const target of block.paths) expect(known.has(target), `${path} -> ${target}`).toBe(true);
      if (block.kind === "route") expect([PRIVACY_PATH, TERMS_PATH]).toContain(block.to);
    }
    for (const target of Object.values(TOOL_DOC_PATH)) expect(known.has(target)).toBe(true);
    for (const target of Object.values(LEGACY_DOC_PATHS)) expect(known.has(target)).toBe(true);
    for (const tool of tools) expect(known.has(TOOL_DOC_PATH[tool.page])).toBe(true);
    for (const page of docPages) {
      const ids = sectionIds(page);
      expect(new Set(ids).size, `${page.path} has duplicate heading ids`).toBe(ids.length);
      expect(breadcrumbs(page.path).length > 0 || page.path === "").toBe(true);
      expect(ancestorPaths(page.path).every((a) => known.has(a))).toBe(true);
    }
    for (const q of ["email", "scanner", "tls", "sarif", "quantum", "hosted", "retention"]) {
      for (const hit of search(q, 50)) {
        expect(known.has(hit.path)).toBe(true);
        if (hit.anchor) expect(sectionIds(pageAt(hit.path) as never)).toContain(hit.anchor);
      }
    }
  });

  it("gives every page a type, its source files and a review date, and every tool the same five topic pages", () => {
    for (const page of docPages) {
      const meta = metaOf(page.path);
      expect(["tutorial", "how-to", "reference", "explanation"]).toContain(meta.type);
      expect(meta.source.length).toBeGreaterThan(0);
      expect(meta.reviewed).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
    for (const base of ["email", "website", "forensics", "detection-repair", "bitcoin"]) {
      for (const leaf of ["", "/how-it-works", "/using-it", "/findings", "/limits"]) expect(pageAt(`tools/${base}${leaf}`)).toBeDefined();
    }
  });

  it("does not present pip install of an unpublished package as available", () => {
    for (const { block } of allBlocks()) if (block.kind === "code") expect(block.code).not.toMatch(/^pip install /m);
    renderDocs("/docs/getting-started/installation");
    expect(screen.getByText(/PyPI release pending/)).toBeTruthy();
    expect(screen.getByText(/After the PyPI release you will also be able to run/)).toBeTruthy();
  });

  it("holds no secrets or private keys, and uses reserved example domains in its email and link examples", () => {
    const text = docPages.flatMap((page) => page.sections.flatMap((section) => section.blocks.map(blockText))).join("\n");
    expect(text).not.toMatch(/ghp_[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20}|BEGIN [A-Z ]*PRIVATE KEY|xox[bp]-/);
    const sample = allBlocks().find(({ block }) => block.kind === "code" && block.code.includes("sample.eml <<"));
    expect(sample && sample.block.kind === "code" ? sample.block.code : "").not.toMatch(/@(?!notice\.example|mail\.example)[a-z0-9.-]+\.(com|net|org)/);
  });
});

const doc = (file: string) => readFileSync(resolve(import.meta.dirname, "../../../../docs", file), "utf8");

describe("measured accuracy", () => {
  const corpus = [
    "modules/mail.md",
    "research/mail-benchmark.md",
    "modules/forensics.md",
    "research/linkfile-benchmark.md",
    "benchmarks/cvefixes.md",
    "claude-plugin.md",
  ]
    .map(doc)
    .join("\n");
  const pagesToCheck = [
    "tools/email/limits",
    "tools/forensics/limits",
    "code-security/accuracy",
    "code-security/claude-plugin/verified-behaviour",
    "tools/website/limits",
    "tools/detection-repair/limits",
    "tools/bitcoin/limits",
  ];

  it.each(pagesToCheck)("%s states only percentages and decimals that are in the benchmark docs", (path) => {
    const page = pageAt(path);
    const text = (page?.sections ?? []).flatMap((s) => s.blocks.map(blockText)).join("\n");
    const numbers = [...(text.match(/\d+(?:\.\d+)?%/g) ?? []), ...(text.match(/\d+\.\d+/g) ?? [])];
    for (const n of new Set(numbers)) expect(corpus.includes(n), `${path}: ${n} is not in the benchmark docs`).toBe(true);
  });

  it("says plainly where nothing was measured", () => {
    for (const path of ["tools/website/limits", "tools/detection-repair/limits", "tools/bitcoin/limits"]) {
      const text = (pageAt(path)?.sections ?? []).flatMap((s) => s.blocks.map(blockText)).join(" ");
      expect(text).toMatch(/Not measured/);
    }
  });

  it("gives the locked-test numbers of the email check and the code scanner exactly", () => {
    renderDocs("/docs/tools/email/limits");
    expect(screen.getByText("61.2% (54.0–69.3)")).toBeTruthy();
    expect(screen.getByText("1.2% (0.7–2.0)")).toBeTruthy();
    cleanup();
    renderDocs("/docs/code-security/accuracy");
    expect(screen.getByText("4.4% [2.4, 6.6]")).toBeTruthy();
    expect(screen.getByText(/The locked test is spent/)).toBeTruthy();
  });
});
