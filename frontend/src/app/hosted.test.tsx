// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { browser } from "../lib/browser";
import { setMode } from "../lib/mode";
import { fakeServer, HOSTED_HEALTH, SIGNED_IN } from "../test/fakeServer";
import { onSignInRequired } from "../lib/api";
import { createRoutes } from "./router";
import { redirectOnSignInRequired } from "./session";

function renderApp(path: string) {
  const router = createMemoryRouter(createRoutes(), { initialEntries: [path] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  redirectOnSignInRequired(router, client);
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

function hostedServer(me: unknown = SIGNED_IN, extra: Parameters<typeof fakeServer>[0] = {}) {
  setMode("hosted");
  return fakeServer({
    "GET /api/health": { body: HOSTED_HEALTH },
    "GET /api/auth/me": { body: me },
    "GET /api/auth/providers": { body: { providers: ["google", "github"] } },
    ...extra,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  onSignInRequired(null);
});

describe("hosted routing", () => {
  it("shows the landing page at / with Sign in and the dashboard under /app", async () => {
    hostedServer({ signed_in: false });
    renderApp("/");
    expect(await screen.findByRole("heading", { level: 1, name: "Kestrix" })).toBeTruthy();
    expect(screen.getAllByRole("link", { name: "Sign in" })[0]?.getAttribute("href")).toBe("/signin");
    for (const link of screen.getAllByRole("link", { name: /open the dashboard/i })) {
      expect(link.getAttribute("href")).toBe("/app");
    }
  });

  it("labels local-only chapters on the landing page", async () => {
    hostedServer({ signed_in: false });
    renderApp("/");
    await screen.findByRole("heading", { level: 1, name: "Kestrix" });
    // Detection repair and Bitcoin
    expect(screen.getAllByText("Available in the desktop app")).toHaveLength(2);
  });

  it("sends signed-out visitors from /app pages to /signin and back", async () => {
    hostedServer({ signed_in: false });
    const router = renderApp("/app/mail?x=1");
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/signin");
    });
    expect(router.state.location.search).toBe(`?next=${encodeURIComponent("/app/mail?x=1")}`);
    const google = await screen.findByRole("link", { name: "Continue with Google" });
    expect(google.getAttribute("href")).toBe(`/api/auth/login/google?next=${encodeURIComponent("/app/mail?x=1")}`);
  });

  it("lists the enabled providers on /signin, defaulting next to /app", async () => {
    hostedServer({ signed_in: false }, { "GET /api/auth/providers": { body: { providers: ["github"] } } });
    renderApp("/signin?next=//evil.example");
    const github = await screen.findByRole("link", { name: "Continue with GitHub" });
    expect(github.getAttribute("href")).toBe("/api/auth/login/github?next=%2Fapp");
    expect(screen.queryByRole("link", { name: /google/i })).toBeNull();
    expect(screen.getByText(/analyzed and never stored/i)).toBeTruthy();
    // The same Log in / Sign up card as the landing page.
    expect(screen.getByRole("tab", { name: "Log in" }).getAttribute("aria-selected")).toBe("true");
    fireEvent.click(screen.getByRole("tab", { name: "Sign up" }));
    expect(screen.getByRole("link", { name: "Privacy notice" }).getAttribute("href")).toBe("/privacy");
    expect(screen.getByRole("link", { name: "Terms of use" }).getAttribute("href")).toBe("/terms");
  });

  it("redirects /welcome to / keeping the sign-in failure, and the banner can be dismissed", async () => {
    hostedServer({ signed_in: false });
    const router = renderApp("/welcome?signin=failed");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Sign-in didn’t complete. Please try again.");
    expect(router.state.location.pathname).toBe("/");
    fireEvent.click(within(alert).getByRole("button", { name: "Dismiss" }));
    await waitFor(() => {
      expect(screen.queryByRole("alert")).toBeNull();
    });
    expect(router.state.location.search).toBe("");
  });

  it("shows only the hosted modules to a signed-in user", async () => {
    hostedServer();
    renderApp("/app");
    const nav = (await screen.findAllByRole("navigation", { name: "Main" }))[0];
    if (!nav) throw new Error("no main navigation");
    const labels = within(nav)
      .getAllByRole("link")
      .map((link) => link.textContent);
    expect(labels).toEqual(["Overview", "Web check", "Forensics", "Email check", "About Kestrix"]);
    expect(within(nav).getByRole("link", { name: "Email check" }).getAttribute("href")).toBe("/app/mail");
    const cards = await screen.findAllByRole("heading", { level: 3 });
    expect(cards.map((h) => h.textContent)).toEqual(["Web check", "Forensics", "Email check"]);
    expect(screen.getAllByText("ada@mail.example").length).toBeGreaterThan(0);
  });

  it("goes to /signin when the session ends mid-use (401 sign_in_required)", async () => {
    hostedServer(SIGNED_IN, {
      "POST /api/forensics/url": { status: 401, body: { reason: "sign_in_required", detail: "sign in to use this feature" } },
    });
    const router = renderApp("/app/forensics?tab=url");
    const field = await screen.findByRole("textbox");
    fireEvent.change(field, { target: { value: "http://paypa1-login.example.top/verify" } });
    fireEvent.submit(field.closest("form") as HTMLFormElement);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/signin");
    });
    expect(router.state.location.search).toBe(`?next=${encodeURIComponent("/app/forensics?tab=url")}`);
  });

  it.each(["/app/detect", "/app/bitcoin", "/app/settings"])("does not serve %s", async (path) => {
    hostedServer();
    renderApp(path);
    expect(await screen.findByRole("heading", { level: 1, name: "Page not found" })).toBeTruthy();
  });

  it("renders the legal pages with the draft banner", async () => {
    hostedServer({ signed_in: false });
    renderApp("/privacy");
    expect(await screen.findByRole("heading", { level: 1, name: "Privacy notice" })).toBeTruthy();
    expect(screen.getByText("Draft — to be reviewed by the owner before launch. Not legal advice.")).toBeTruthy();
  });
});

describe("account menu", () => {
  it("deletes the account only after DELETE is typed, then reloads the home page with a confirmation", async () => {
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    const { calls } = hostedServer(SIGNED_IN, { "DELETE /api/auth/account": { status: 204 } });
    renderApp("/app");
    fireEvent.click((await screen.findAllByRole("button", { name: "Delete account" }))[0] as HTMLElement);
    const dialog = screen.getByRole("dialog", { name: "Delete your account?" });
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    const confirm = within(dialog).getByRole<HTMLButtonElement>("button", { name: "Delete account" });
    const input = within(dialog).getByLabelText("Type DELETE to confirm");
    expect(document.activeElement).toBe(input);
    fireEvent.change(input, { target: { value: "delete" } });
    expect(confirm.disabled).toBe(true);
    fireEvent.submit(input.closest("form") as HTMLFormElement);
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    fireEvent.change(input, { target: { value: "DELETE" } });
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith("/?account=deleted");
    });
    const deletion = calls.find((c) => c.method === "DELETE");
    expect(deletion?.path).toBe("/api/auth/account");
    expect(deletion?.headers.get("X-CSRF-Token")).toBe("csrf-token-1");
  });

  it("confirms the deletion on the landing page", async () => {
    hostedServer({ signed_in: false });
    renderApp("/?account=deleted");
    expect((await screen.findByRole("status")).textContent).toContain("Your account and all its sessions were deleted.");
  });

  it("keeps focus inside the dialog", async () => {
    hostedServer();
    renderApp("/app");
    fireEvent.click((await screen.findAllByRole("button", { name: "Delete account" }))[0] as HTMLElement);
    const dialog = screen.getByRole("dialog");
    const input = within(dialog).getByLabelText("Type DELETE to confirm");
    const cancel = within(dialog).getByRole("button", { name: "Cancel" });
    cancel.focus();
    // The disabled Delete button is skipped, so Cancel is last: Tab wraps to the input.
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(input);
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(cancel);
  });

  it("closes the dialog on Escape without deleting", async () => {
    const { calls } = hostedServer();
    renderApp("/app");
    fireEvent.click((await screen.findAllByRole("button", { name: "Delete account" }))[0] as HTMLElement);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
  });

  it("signs out with the CSRF token and goes home", async () => {
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    const { calls } = hostedServer(SIGNED_IN, { "POST /api/auth/logout": { status: 204 } });
    renderApp("/app/mail");
    fireEvent.click((await screen.findAllByRole("button", { name: "Sign out" }))[0] as HTMLElement);
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith("/");
    });
    expect(calls.find((c) => c.path === "/api/auth/logout")?.headers.get("X-CSRF-Token")).toBe("csrf-token-1");
  });
});

describe("local routing is unchanged", () => {
  it("keeps the dashboard at / and every module", async () => {
    fakeServer({ "GET /api/health": { body: { status: "ok", version: "0.1.0", modules: [] } } });
    renderApp("/");
    const nav = (await screen.findAllByRole("navigation", { name: "Main" }))[0];
    if (!nav) throw new Error("no main navigation");
    expect(within(nav).getAllByRole("link").map((link) => link.textContent)).toEqual([
      "Overview",
      "Detection repair",
      "Web check",
      "Forensics",
      "Email check",
      "Bitcoin quantum risk",
      "Settings",
      "About Kestrix",
    ]);
    expect(within(nav).getByRole("link", { name: "About Kestrix" }).getAttribute("href")).toBe("/welcome");
    expect(screen.queryByRole("button", { name: "Sign out" })).toBeNull();
  });
});
