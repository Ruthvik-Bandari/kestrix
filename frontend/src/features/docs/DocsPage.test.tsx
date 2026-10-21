// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { describe, expect, it } from "vitest";
import { tools } from "../../app/tools";
import { docPages } from "./content";
import DocsPage, { sectionLinks } from "./DocsPage";

function renderDocs(path: string) {
  const router = createMemoryRouter(
    [
      { path: "/docs", element: <DocsPage /> },
      { path: "/docs/:slug", element: <DocsPage /> },
    ],
    { initialEntries: [path] },
  );
  render(<RouterProvider router={router} />);
  return router;
}

function docsNav() {
  return screen.getByRole("navigation", { name: "Documentation" });
}

describe("DocsPage", () => {
  it("opens on the overview with every page in the navigation", () => {
    renderDocs("/docs");
    expect(screen.getByRole("heading", { level: 1, name: "Kestrix documentation" })).toBeTruthy();
    const links = within(docsNav()).getAllByRole("link");
    expect(links.map((link) => link.textContent)).toEqual(docPages.map((page) => page.nav));
    expect(within(docsNav()).getByRole("link", { name: "Overview" }).getAttribute("aria-current")).toBe("page");
    expect(within(docsNav()).getByRole("link", { name: "Code scanner" }).getAttribute("href")).toBe("/docs/code");
  });

  it("lists every tool on the overview from the one tool list, and links the landing page", () => {
    renderDocs("/docs");
    const section = screen.getByRole("heading", { level: 2, name: "Seven tools" }).closest("section") as HTMLElement;
    const links = within(section).getAllByRole("link");
    expect(links.map((link) => link.textContent)).toEqual(tools.map((tool) => tool.name));
    expect(links.map((link) => link.getAttribute("href"))).toEqual(tools.map((tool) => `/docs/${tool.page}`));
    for (const tool of tools) expect(within(section).getByText(`: ${tool.summary}`, { exact: false })).toBeTruthy();
    expect(screen.getByRole("link", { name: /on the home page/ }).getAttribute("href")).toBe("/welcome");
  });

  it("shows a tool page with its sections and marks it current", () => {
    renderDocs("/docs/code");
    expect(screen.getByRole("heading", { level: 1, name: "Code scanner" })).toBeTruthy();
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual([
      "What it is",
      "How it works",
      "How it helps",
      "Typical uses",
      "Limits",
      "Install and use",
    ]);
    // The install-and-use guide is the same one the guide page shows, nested one level down.
    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual([
      "Requirements",
      "Install",
      "Check it works",
      "Step by step",
      "Example output",
      "Troubleshooting",
    ]);
    expect(screen.getByText(/No findings is not proof of security/)).toBeTruthy();
    expect(within(docsNav()).getByRole("link", { name: "Code scanner" }).getAttribute("aria-current")).toBe("page");
    expect(within(docsNav()).getByRole("link", { name: "Overview" }).getAttribute("aria-current")).toBeNull();
  });

  it("navigates between pages from the left navigation", async () => {
    const router = renderDocs("/docs/code");
    fireEvent.click(within(docsNav()).getByRole("link", { name: "Claude Code plugin" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/docs/claude-plugin");
    });
    expect(screen.getByRole("heading", { level: 1, name: "Claude Code plugin" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "The Stop gate (opt-in)" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: /^Copy command: / }).length).toBeGreaterThan(0);
  });

  it("covers every pip-package topic on the packages page", () => {
    renderDocs("/docs/packages");
    for (const name of ["Install", "Configuration", "pre-commit", "GitHub Action", "pytest"]) {
      expect(screen.getByRole("heading", { level: 2, name })).toBeTruthy();
    }
  });

  it("lists every section in an On this page navigation whose links target the article's h2 ids", () => {
    for (const path of ["/docs", "/docs/code", "/docs/packages", "/docs/claude-plugin"]) {
      const { unmount } = render(<></>);
      unmount();
      renderDocs(path);
      const toc = screen.getByRole("navigation", { name: "On this page" });
      const links = within(toc).getAllByRole("link");
      const headings = screen.getAllByRole("heading", { level: 2 });
      expect(links.map((link) => link.textContent)).toEqual(headings.map((h) => h.textContent));
      for (const [index, link] of links.entries()) {
        const id = (link.getAttribute("href") ?? "").replace(/^#/, "");
        expect(id).not.toBe("");
        expect(document.getElementById(id)).toBe(headings[index]);
      }
      cleanup();
    }
    expect(sectionLinks(docPages[0] as (typeof docPages)[number]).length).toBeGreaterThan(1);
  });

  it("does not present pip install of an unpublished package as available", () => {
    for (const page of docPages) {
      for (const section of page.sections) {
        for (const block of section.blocks) {
          if (block.kind === "code") expect(block.code).not.toMatch(/^pip install /m);
        }
      }
    }
    renderDocs("/docs/packages");
    expect(screen.getByText(/PyPI release pending/)).toBeTruthy();
    expect(screen.getByText(/After the PyPI release you will also be able to run/)).toBeTruthy();
    const commands = screen.getAllByRole("button", { name: /^Copy command: / }).map((b) => b.getAttribute("aria-label"));
    expect(commands).toContain('Copy command: uv tool install "git+https://github.com/Ruthvik-Bandari/kestrix"');
    for (const label of commands) expect(label).not.toMatch(/: pip install/);
  });

  it("answers an unknown page with a link back to the overview", () => {
    renderDocs("/docs/nope");
    expect(screen.getByRole("heading", { level: 1, name: "Page not found" })).toBeTruthy();
    expect(screen.getByRole("link", { name: /documentation overview/ }).getAttribute("href")).toBe("/docs");
  });
});
