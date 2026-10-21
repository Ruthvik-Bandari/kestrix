// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRoutes } from "../../app/router";
import { setMode } from "../../lib/mode";
import { fakeServer, HOSTED_HEALTH, SIGNED_IN } from "../../test/fakeServer";

function renderHosted(path: string, me: unknown = { signed_in: false }, providers = ["google", "github"]) {
  setMode("hosted");
  fakeServer({
    "GET /api/health": { body: HOSTED_HEALTH },
    "GET /api/auth/me": { body: me },
    "GET /api/auth/providers": { body: { providers } },
  });
  const router = createMemoryRouter(createRoutes(), { initialEntries: [path] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

async function card() {
  const tablist = await screen.findByRole("tablist", { name: "Log in or sign up" });
  return tablist.closest("section") as HTMLElement;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("landing hero auth card", () => {
  it("is on the hosted landing page with Log in selected and only the enabled providers", async () => {
    renderHosted("/", { signed_in: false }, ["github"]);
    const section = await card();
    expect(within(section).getByRole("heading", { level: 2, name: "Use Kestrix in your browser" })).toBeTruthy();
    expect(within(section).getByRole("tab", { name: "Log in" }).getAttribute("aria-selected")).toBe("true");
    const github = await within(section).findByRole("link", { name: "Continue with GitHub" });
    expect(github.getAttribute("href")).toBe("/api/auth/login/github?next=%2Fapp");
    expect(within(section).queryByText(/google/i)).toBeNull();
    // The rest of the story is still there.
    expect(screen.getByRole("heading", { level: 1, name: "Kestrix" })).toBeTruthy();
    expect(screen.getAllByText("Available in the desktop app")).toHaveLength(2);
  });

  it("is a keyboard-accessible tablist", async () => {
    renderHosted("/");
    const section = await card();
    const login = within(section).getByRole("tab", { name: "Log in" });
    const signup = within(section).getByRole("tab", { name: "Sign up" });
    const panel = within(section).getByRole("tabpanel");
    expect(login.getAttribute("aria-controls")).toBe(panel.id);
    expect(panel.getAttribute("aria-labelledby")).toBe(login.id);
    expect([login.tabIndex, signup.tabIndex]).toEqual([0, -1]);
    login.focus();
    fireEvent.keyDown(login, { key: "ArrowRight" });
    expect(signup.getAttribute("aria-selected")).toBe("true");
    expect(document.activeElement).toBe(signup);
    expect([login.tabIndex, signup.tabIndex]).toEqual([-1, 0]);
    expect(within(section).getByRole("tabpanel").getAttribute("aria-labelledby")).toBe(signup.id);
    fireEvent.keyDown(signup, { key: "ArrowRight" }); // wraps around
    expect(document.activeElement).toBe(login);
    fireEvent.keyDown(login, { key: "End" });
    expect(document.activeElement).toBe(signup);
    fireEvent.keyDown(signup, { key: "Home" });
    expect(login.getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(login, { key: "ArrowLeft" });
    expect(signup.getAttribute("aria-selected")).toBe("true");
  });

  it("keeps Sign up disabled until the terms are accepted, then passes intent=signup", async () => {
    renderHosted("/");
    const section = await card();
    await within(section).findByRole("link", { name: "Continue with Google" });
    fireEvent.click(within(section).getByRole("tab", { name: "Sign up" }));
    const checkbox = within(section).getByRole<HTMLInputElement>("checkbox", {
      name: "I agree to the Terms of use and have read the Privacy notice",
    });
    expect(checkbox.required).toBe(true);
    expect(checkbox.checked).toBe(false);
    expect(within(section).getByRole("link", { name: "Terms of use" }).getAttribute("href")).toBe("/terms");
    expect(within(section).getByRole("link", { name: "Privacy notice" }).getAttribute("href")).toBe("/privacy");
    for (const name of ["Continue with Google", "Continue with GitHub"]) {
      expect(within(section).getByRole<HTMLButtonElement>("button", { name }).disabled).toBe(true);
      expect(within(section).queryByRole("link", { name })).toBeNull();
    }
    fireEvent.click(checkbox);
    expect(within(section).getByRole("link", { name: "Continue with Google" }).getAttribute("href")).toBe(
      "/api/auth/login/google?next=%2Fapp&intent=signup",
    );
    fireEvent.click(checkbox);
    expect(within(section).getByRole<HTMLButtonElement>("button", { name: "Continue with Google" }).disabled).toBe(true);
    // Log in never needs the checkbox and never sends intent=signup.
    fireEvent.click(within(section).getByRole("tab", { name: "Log in" }));
    expect(within(section).getByRole("link", { name: "Continue with Google" }).getAttribute("href")).toBe("/api/auth/login/google?next=%2Fapp");
  });

  it("offers the dashboard instead to a signed-in visitor", async () => {
    renderHosted("/", SIGNED_IN);
    const greeting = await screen.findByRole("heading", { level: 2, name: "Welcome back" });
    const section = greeting.closest("section") as HTMLElement;
    expect(within(section).getByText("Ada Lovelace")).toBeTruthy();
    expect(within(section).getByRole("link", { name: /open the dashboard/i }).getAttribute("href")).toBe("/app");
    expect(screen.queryByRole("tablist")).toBeNull();
    expect(screen.queryByRole("link", { name: /continue with/i })).toBeNull();
  });

  it("is not shown by a local dashboard", async () => {
    fakeServer({ "GET /api/health": { body: { status: "ok", version: "0.1.0", modules: [] } } });
    const router = createMemoryRouter(createRoutes(), { initialEntries: ["/welcome"] });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    await screen.findByRole("heading", { level: 1, name: "Kestrix" });
    expect(screen.queryByRole("tablist")).toBeNull();
  });
});

describe("welcome note for an account created through Log in", () => {
  it("shows once on the dashboard with the terms link, and can be dismissed", async () => {
    const router = renderHosted("/app/mail?welcome=created", SIGNED_IN);
    const note = (await screen.findByText("Welcome, account created.")).closest("[role=status]") as HTMLElement;
    expect(within(note).getByRole("link", { name: "Terms of use" }).getAttribute("href")).toBe("/terms");
    fireEvent.click(within(note).getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText(/account created/)).toBeNull();
    expect(router.state.location.search).toBe("");
  });
});
