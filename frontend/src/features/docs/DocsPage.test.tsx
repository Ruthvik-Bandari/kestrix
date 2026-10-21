// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { describe, expect, it } from "vitest";
import { docPages } from "./content";
import DocsPage from "./DocsPage";

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

  it("shows a tool page with its sections and marks it current", () => {
    renderDocs("/docs/code");
    expect(screen.getByRole("heading", { level: 1, name: "Code scanner" })).toBeTruthy();
    for (const name of ["What it is", "How it works", "How it helps", "Typical uses", "Limits", "A real example result"]) {
      expect(screen.getByRole("heading", { level: 2, name })).toBeTruthy();
    }
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

  it("answers an unknown page with a link back to the overview", () => {
    renderDocs("/docs/nope");
    expect(screen.getByRole("heading", { level: 1, name: "Page not found" })).toBeTruthy();
    expect(screen.getByRole("link", { name: /documentation overview/ }).getAttribute("href")).toBe("/docs");
  });
});
