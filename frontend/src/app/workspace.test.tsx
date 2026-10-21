// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { onSignInRequired } from "../lib/api";
import { setMode } from "../lib/mode";
import { fakeServer, HOSTED_HEALTH, SIGNED_IN } from "../test/fakeServer";
import { createRoutes } from "./router";

const NOW = 1_792_000_000;
const ITEMS = [
  { id: "r-mail-1", tool: "mail", created_at: NOW, verdict: "malicious", findings: 7 },
  { id: "r-web-1", tool: "webcheck", created_at: NOW - 60, verdict: "B", findings: 3 },
  { id: "r-url-1", tool: "forensics_url", created_at: NOW - 120, verdict: "high", findings: 1 },
  { id: "r-file-1", tool: "forensics_file", created_at: NOW - 180, verdict: "none", findings: 0 },
  { id: "r-mail-2", tool: "mail", created_at: NOW - 240, verdict: "clean", findings: 0 },
  { id: "r-mail-3", tool: "mail", created_at: NOW - 300, verdict: "suspicious", findings: 2 },
];

function historyPage(enabled = true, items: typeof ITEMS = ITEMS) {
  return { enabled, retention_days: 30, page: 1, per_page: 20, total: items.length, items };
}

function renderApp(path: string) {
  const router = createMemoryRouter(createRoutes(), { initialEntries: [path] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

function local(extra: Parameters<typeof fakeServer>[0] = {}) {
  setMode("local");
  return fakeServer({ "GET /api/health": { body: { status: "ok", version: "0.1.0", modules: [] } }, ...extra });
}

function hosted(extra: Parameters<typeof fakeServer>[0] = {}) {
  setMode("hosted");
  return fakeServer({
    "GET /api/health": { body: HOSTED_HEALTH },
    "GET /api/auth/me": { body: SIGNED_IN },
    ...extra,
  });
}

async function recent() {
  const heading = await screen.findByRole("heading", { level: 2, name: "Recent results" });
  const section = heading.closest("section");
  if (!section) throw new Error("no recent results section");
  return section;
}

beforeAll(() => {
  Element.prototype.scrollIntoView = () => undefined;
});

afterEach(() => {
  vi.unstubAllGlobals();
  onSignInRequired(null);
  setMode("local");
  document.body.style.overflow = "";
});

describe("Home", () => {
  it("asks what to check, names the mode, and offers file and link as two separate actions", async () => {
    local({ "GET /api/history": { body: historyPage(true, []) } });
    renderApp("/");
    expect(await screen.findByRole("heading", { level: 1, name: "What would you like to check?" })).toBeTruthy();
    expect(screen.getByText("Local workspace · runs on this computer")).toBeTruthy();
    expect(screen.getByRole("link", { name: /Choose an .eml file/ }).getAttribute("href")).toBe("/mail");
    expect(screen.getByRole("link", { name: /Enter an address/ }).getAttribute("href")).toBe("/webcheck");
    expect(screen.getByRole("link", { name: "Inspect a file" }).getAttribute("href")).toBe("/forensics");
    expect(screen.getByRole("link", { name: "Inspect a link" }).getAttribute("href")).toBe("/forensics?tab=url");
  });

  it("uses the hosted paths and wording on the hosted service", async () => {
    hosted({ "GET /api/history": { body: historyPage(true, []) } });
    renderApp("/app");
    expect(await screen.findByText("Hosted workspace")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Inspect a link" }).getAttribute("href")).toBe("/app/forensics?tab=url");
    expect(screen.getByRole("heading", { name: "Checks run on Kestrix's server" })).toBeTruthy();
  });

  it("shows a loading placeholder, then the newest five saved results with a link to each and View all", async () => {
    local({ "GET /api/history": { body: historyPage() } });
    renderApp("/");
    expect(await screen.findByRole("status", { name: "Loading recent results" })).toBeTruthy();
    const section = await recent();
    const table = await within(section).findByRole("table");
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Tool", "Result", "Findings", "Time"]);
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(5);
    expect(rows[0]?.textContent).toContain("Email check");
    expect(rows[0]?.textContent).toContain("Malicious");
    expect(rows[0]?.textContent).toContain("7 findings");
    expect(within(rows[0] as HTMLElement).getByRole("link").getAttribute("href")).toBe("/history/r-mail-1");
    expect(rows[1]?.textContent).toContain("Grade B");
    expect(within(section).getByRole("link", { name: "View all (6)" }).getAttribute("href")).toBe("/history");
  });

  it("explains first use without claiming zero threats, and offers a task", async () => {
    local({ "GET /api/history": { body: historyPage(true, []) } });
    renderApp("/");
    const section = await recent();
    expect(await within(section).findByText("No saved results yet")).toBeTruthy();
    expect(section.textContent).not.toMatch(/no threats|all clear|safe/i);
    expect(within(section).getByRole("link", { name: /Check an email/ }).getAttribute("href")).toBe("/mail");
  });

  it("says history is off and links to Settings", async () => {
    local({ "GET /api/history": { body: historyPage(false, []) } });
    renderApp("/");
    const section = await recent();
    expect(await within(section).findByText("History is off")).toBeTruthy();
    expect(within(section).getByRole("link", { name: "Turn it on in Settings" }).getAttribute("href")).toBe("/settings");
    expect(within(section).queryByRole("table")).toBeNull();
  });

  it("shows a fetch failure with a retry that loads the results", async () => {
    let calls = 0;
    local({
      "GET /api/history": () => {
        calls += 1;
        return calls === 1 ? { status: 500, body: { reason: "internal", detail: "boom" } } : { body: historyPage() };
      },
    });
    renderApp("/");
    const section = await recent();
    expect(await within(section).findByRole("alert")).toBeTruthy();
    fireEvent.click(within(section).getByRole("button", { name: "Try again" }));
    expect(await within(section).findByRole("table")).toBeTruthy();
  });

  it("lists the other tools with mode-correct labels", async () => {
    local({ "GET /api/history": { body: historyPage(true, []) } });
    renderApp("/");
    const heading = await screen.findByRole("heading", { name: "Advanced and developer tools" });
    const list = within(heading.closest("section") as HTMLElement);
    expect(list.getByRole("link", { name: /^Detection repair Runs here$/ })).toBeTruthy();
    expect(list.getByRole("link", { name: /^Code scanner Guide$/ })).toBeTruthy();
  });
});

describe("navigation rail", () => {
  it("groups the tools and marks guides per mode", async () => {
    hosted({ "GET /api/history": { body: historyPage(true, []) } });
    renderApp("/app");
    const nav = (await screen.findAllByRole("navigation", { name: "Main" }))[0] as HTMLElement;
    expect(within(nav).getByRole("link", { name: "Overview" }).getAttribute("aria-current")).toBe("page");
    expect(within(nav).getByRole("link", { name: "Detection repair Local guide" })).toBeTruthy();
    expect(within(nav).getByRole("link", { name: "Bitcoin Local guide" })).toBeTruthy();
    expect(within(nav).getByRole("link", { name: "Code scanner Guide" })).toBeTruthy();
    expect(within(nav).getByRole("link", { name: "Claude integration Guide" })).toBeTruthy();
    expect(within(nav).getByRole("link", { name: "Email" }).getAttribute("href")).toBe("/app/mail");
    expect(screen.getAllByRole("link", { name: "Docs and help" })[0]?.getAttribute("href")).toBe("/app/docs");
  });

  it("does not label live tools as guides locally", async () => {
    local({ "GET /api/history": { body: historyPage(true, []) } });
    renderApp("/");
    const nav = (await screen.findAllByRole("navigation", { name: "Main" }))[0] as HTMLElement;
    expect(within(nav).getByRole("link", { name: "Detection repair" })).toBeTruthy();
    expect(within(nav).getByRole("link", { name: "Bitcoin" })).toBeTruthy();
    expect(within(nav).queryByText("Local guide")).toBeNull();
    expect(within(nav).getByRole("link", { name: "Code scanner Guide" })).toBeTruthy();
  });
});

describe("mobile drawer", () => {
  it("opens as a modal menu, closes on Escape and returns focus to the button", async () => {
    local({ "GET /api/history": { body: historyPage(true, []) } });
    renderApp("/");
    const button = await screen.findByRole("button", { name: "Menu" });
    expect(button.getAttribute("aria-expanded")).toBe("false");
    button.focus();
    fireEvent.click(button);
    const dialog = await screen.findByRole("dialog", { name: "Menu" });
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.body.style.overflow).toBe("hidden");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(button);
    expect(document.body.style.overflow).toBe("");
  });

  it("reaches every page and closes when a link is chosen", async () => {
    local({ "GET /api/history": { body: historyPage(true, []) } });
    const router = renderApp("/");
    fireEvent.click(await screen.findByRole("button", { name: "Menu" }));
    const nav = within(await screen.findByRole("dialog", { name: "Menu" }));
    const hrefs = nav.getAllByRole("link").map((link) => link.getAttribute("href"));
    for (const path of ["/", "/mail", "/webcheck", "/forensics", "/detect", "/bitcoin", "/code", "/claude-plugin", "/history", "/settings", "/docs", "/privacy", "/terms"]) {
      expect(hrefs).toContain(path);
    }
    fireEvent.click(nav.getByRole("link", { name: "Settings" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/settings");
    });
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
