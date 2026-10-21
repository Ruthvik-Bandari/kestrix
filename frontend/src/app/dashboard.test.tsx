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

const LOCAL_HEALTH = { status: "ok", version: "0.1.0", modules: [] };
const TILES = [
  "Email check",
  "Web check",
  "File & link forensics",
  "Detection repair",
  "Code scanner",
  "Claude Code plugin",
  "Bitcoin quantum risk",
];

const NOW = 1_792_000_000;
const ITEMS = [
  { id: "r-mail-1", tool: "mail", created_at: NOW, verdict: "malicious", findings: 7 },
  { id: "r-web-1", tool: "webcheck", created_at: NOW - 60, verdict: "B", findings: 3 },
  { id: "r-url-1", tool: "forensics_url", created_at: NOW - 120, verdict: "high", findings: 4 },
];
const MAIL_REPORT = {
  generated_by: "Kestrix",
  schema_version: 1,
  notice: "Offline heuristic analysis of one saved message.",
  sha256: "a".repeat(64),
  subject: "URGENT: Updated bank details",
  from_address: "billing@n0rthbank-secure.example",
  verdict: "malicious",
  heuristic_score: 100,
  findings: [
    {
      id: "mail.sender.display_name_brand",
      analyzer: "sender",
      severity: "high",
      title: "Display name uses a protected name from another domain",
      explanation: "The display name claims a protected brand.",
      evidence: "Northbank Billing",
    },
  ],
  counts: { parts: 2, links: 1, attachments: 1, text_truncated: false, links_truncated: false },
};

function historyPage(enabled = true, items = ITEMS) {
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

function hosted(extra: Parameters<typeof fakeServer>[0] = {}, me: unknown = SIGNED_IN) {
  setMode("hosted");
  return fakeServer({
    "GET /api/health": { body: HOSTED_HEALTH },
    "GET /api/auth/me": { body: me },
    "GET /api/auth/providers": { body: { providers: ["google"] } },
    ...extra,
  });
}

function local(extra: Parameters<typeof fakeServer>[0] = {}) {
  setMode("local");
  return fakeServer({ "GET /api/health": { body: LOCAL_HEALTH }, ...extra });
}

async function launcher() {
  const heading = await screen.findByRole("heading", { level: 2, name: "Tools" });
  const section = heading.closest("section");
  if (!section) throw new Error("no launcher");
  return section;
}

beforeAll(() => {
  // jsdom has no layout: the report views scroll themselves into view.
  Element.prototype.scrollIntoView = () => undefined;
});

afterEach(() => {
  vi.unstubAllGlobals();
  onSignInRequired(null);
  setMode("local");
});

describe("home launcher", () => {
  it("shows every tool, and only the tools, as a named link without badges in local mode", async () => {
    local();
    renderApp("/");
    const grid = await launcher();
    const links = within(grid).getAllByRole("link");
    expect(links.map((link) => link.textContent)).toEqual(TILES);
    expect(within(grid).getByRole("link", { name: "Code scanner" }).getAttribute("href")).toBe("/code");
    expect(within(grid).queryByText("Run locally")).toBeNull();
  });

  it("marks the local-only tools Run locally on the hosted service", async () => {
    hosted();
    renderApp("/app");
    const grid = await launcher();
    for (const name of ["Detection repair", "Code scanner", "Claude Code plugin", "Bitcoin quantum risk"]) {
      expect(within(grid).getByRole("link", { name: `${name} Run locally` })).toBeTruthy();
    }
    for (const name of ["Email check", "Web check", "File & link forensics"]) {
      expect(within(grid).getByRole("link", { name }).getAttribute("href")).toMatch(/^\/app\//);
    }
  });

  it.each([
    ["Bitcoin quantum risk", "/app/bitcoin"],
    ["Detection repair", "/app/detect"],
    ["Code scanner", "/app/code"],
    ["Claude Code plugin", "/app/claude-plugin"],
  ])("opens a guide with no live controls for %s on the hosted service", async (name, path) => {
    hosted();
    const router = renderApp("/app");
    fireEvent.click(within(await launcher()).getByRole("link", { name: `${name} Run locally` }));
    expect(await screen.findByRole("heading", { level: 1, name })).toBeTruthy();
    expect(router.state.location.pathname).toBe(path);
    expect(screen.queryAllByRole("textbox")).toHaveLength(0);
    expect(screen.queryAllByRole("combobox")).toHaveLength(0);
    expect(document.querySelector("input[type=file], form, button[type=submit]")).toBeNull();
    expect(screen.getAllByRole("button", { name: /^Copy command/ }).length).toBeGreaterThan(0);
  });
});

describe("local mode runs the tools", () => {
  it("serves the live Bitcoin scanner with its summary and a link to the docs, not a second guide", async () => {
    local();
    renderApp("/bitcoin");
    expect(await screen.findByRole("heading", { level: 1, name: "Bitcoin quantum risk" })).toBeTruthy();
    expect(screen.getAllByRole("textbox").length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Read the docs" }).getAttribute("href")).toBe("/docs/bitcoin");
    expect(screen.queryByRole("heading", { name: "Troubleshooting" })).toBeNull();
  });

  it("serves the live detection repair page", async () => {
    local({ "GET /api/detect/engine": { body: { reachable: false, version: null, pinned_version: "8.19.3", pinned: false, image: "x" } } });
    renderApp("/detect");
    expect(await screen.findByRole("heading", { level: 1, name: "Detection repair" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Read the docs" }).getAttribute("href")).toBe("/docs/detect");
  });
});

describe("recent results", () => {
  it("lists results newest first with a tool, a time and a verdict chip", async () => {
    hosted({ "GET /api/history": { body: historyPage() } });
    renderApp("/app/history");
    const list = await screen.findByRole("list", { name: "Saved results, newest first" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(3);
    expect(rows[0]?.textContent).toContain("Email check");
    expect(rows[0]?.textContent).toContain("Malicious");
    expect(rows[1]?.textContent).toContain("Grade B");
    expect(rows[2]?.textContent).toContain("Link check");
    expect(rows[0]?.querySelector("time")?.getAttribute("dateTime")).toBe(new Date(NOW * 1000).toISOString());
    expect(within(rows[0] as HTMLElement).getByRole("link").getAttribute("href")).toBe("/app/history/r-mail-1");
  });

  it("opens a saved report with the tool's own report view", async () => {
    hosted({ "GET /api/history/r-mail-1": { body: { ...ITEMS[0], report: MAIL_REPORT } } });
    renderApp("/app/history/r-mail-1");
    expect(await screen.findByRole("heading", { level: 1, name: "Email check" })).toBeTruthy();
    expect(screen.getByText("Display name uses a protected name from another domain")).toBeTruthy();
    expect(screen.getByText("URGENT: Updated bank details")).toBeTruthy();
  });

  it("says when a saved report is gone", async () => {
    hosted({ "GET /api/history/nope": { status: 404, body: { reason: "not_found", detail: "no such result" } } });
    renderApp("/app/history/nope");
    expect(await screen.findByRole("heading", { name: "Result not found" })).toBeTruthy();
  });

  it("deletes one result after a confirmation, with the CSRF token", async () => {
    const { calls } = hosted({
      "GET /api/history": { body: historyPage() },
      "DELETE /api/history/r-web-1": { status: 204 },
    });
    renderApp("/app/history");
    const del = await screen.findByRole("button", { name: /^Delete the Web check result from/ });
    fireEvent.click(del);
    const dialog = screen.getByRole("dialog", { name: "Delete this result?" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    fireEvent.click(del);
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    const deletion = calls.find((c) => c.method === "DELETE");
    expect(deletion?.path).toBe("/api/history/r-web-1");
    expect(deletion?.headers.get("X-CSRF-Token")).toBe("csrf-token-1");
  });

  it("deletes everything after a confirmation", async () => {
    const { calls } = hosted({ "GET /api/history": { body: historyPage() }, "DELETE /api/history": { status: 204 } });
    renderApp("/app/history");
    fireEvent.click(await screen.findByRole("button", { name: "Delete all" }));
    const dialog = screen.getByRole("dialog", { name: "Delete all results?" });
    expect(dialog.textContent).toContain("3 saved results");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete all" }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === "DELETE" && c.path === "/api/history")).toBe(true);
    });
  });

  it("deletes from the detail page and returns to the list", async () => {
    const { calls } = hosted({
      "GET /api/history": { body: historyPage(true, []) },
      "GET /api/history/r-mail-1": { body: { ...ITEMS[0], report: MAIL_REPORT } },
      "DELETE /api/history/r-mail-1": { status: 204 },
    });
    const router = renderApp("/app/history/r-mail-1");
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/app/history");
    });
    expect(calls.some((c) => c.method === "DELETE" && c.path === "/api/history/r-mail-1")).toBe(true);
    expect(await screen.findByText("No results yet")).toBeTruthy();
  });

  it("works the same in local mode, without a CSRF header", async () => {
    const { calls } = local({ "GET /api/history": { body: historyPage() }, "DELETE /api/history": { status: 204 } });
    renderApp("/history");
    fireEvent.click(await screen.findByRole("button", { name: "Delete all" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete all" }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === "DELETE")).toBe(true);
    });
    expect(calls.find((c) => c.method === "DELETE")?.headers.get("X-CSRF-Token")).toBeNull();
  });
});

describe("history setting", () => {
  it("turns history off only after confirming that saved reports are deleted", async () => {
    const { calls } = hosted({
      "GET /api/history": { body: historyPage() },
      "PUT /api/settings/history": (call) => ({ body: call.body }),
    });
    renderApp("/app/settings");
    const toggle = await screen.findByRole("switch", { name: "Keep my reports for 30 days" });
    expect((toggle as HTMLInputElement).checked).toBe(true);
    // Hosted settings have no Anthropic key.
    expect(screen.queryByText("Anthropic API key")).toBeNull();
    fireEvent.click(toggle);
    const dialog = screen.getByRole("dialog", { name: "Turn off history?" });
    expect(dialog.textContent).toContain("3 saved reports will be deleted");
    fireEvent.click(within(dialog).getByRole("button", { name: "Keep history on" }));
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    fireEvent.click(toggle);
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Turn off and delete" }));
    await waitFor(() => {
      expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ enabled: false });
    });
    expect(calls.find((c) => c.method === "PUT")?.headers.get("X-CSRF-Token")).toBe("csrf-token-1");
  });

  it("turns history back on without a confirmation", async () => {
    const { calls } = local({
      "GET /api/history": { body: historyPage(false, []) },
      "GET /api/settings": { body: { anthropic_key_configured: false } },
      "PUT /api/settings/history": (call) => ({ body: call.body }),
    });
    renderApp("/settings");
    const toggle = await screen.findByRole("switch", { name: "Keep my reports for 30 days" });
    expect((toggle as HTMLInputElement).checked).toBe(false);
    fireEvent.click(toggle);
    await waitFor(() => {
      expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ enabled: true });
    });
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("landing header", () => {
  it("gives a signed-out visitor Log in and Sign up in the header, and no dashboard button or auth form", async () => {
    hosted({}, { signed_in: false });
    renderApp("/");
    await screen.findByRole("heading", { level: 1, name: "See the risk. Understand the evidence." });
    const header = screen.getAllByRole("banner")[0] as HTMLElement;
    expect((await within(header).findByRole("link", { name: "Log in" })).getAttribute("href")).toBe("/signin");
    expect(within(header).getByRole("link", { name: "Sign up" }).getAttribute("href")).toBe("/signin?intent=signup");
    expect(screen.queryByRole("tablist")).toBeNull();
    expect(screen.queryAllByRole("link", { name: /open workbench|open the dashboard/i })).toHaveLength(0);
  });

  it("gives a signed-in visitor Open workbench in the header and the hero", async () => {
    hosted();
    renderApp("/");
    const header = screen.getAllByRole("banner")[0] as HTMLElement;
    expect((await within(header).findByRole("link", { name: /open workbench/i })).getAttribute("href")).toBe("/app");
    expect(await screen.findAllByRole("link", { name: /open workbench/i })).toHaveLength(3);
    expect(screen.queryByRole("link", { name: "Log in" })).toBeNull();
    expect(screen.queryByRole("tablist")).toBeNull();
  });
});
