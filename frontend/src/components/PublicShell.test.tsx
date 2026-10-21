// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRoutes } from "../app/router";
import { setMode } from "../lib/mode";
import { fakeServer, HOSTED_HEALTH, SIGNED_IN } from "../test/fakeServer";

function renderAt(path: string, hosted: boolean, me: unknown) {
  setMode(hosted ? "hosted" : "local");
  fakeServer({
    "GET /api/health": { body: HOSTED_HEALTH },
    "GET /api/auth/me": { body: me },
    "GET /api/auth/providers": { body: { providers: ["google"] } },
  });
  const router = createMemoryRouter(createRoutes(), { initialEntries: [path] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("public shell header", () => {
  it("offers Log in and Sign up on a legal page when hosted and signed out, like the landing header", async () => {
    renderAt("/privacy", true, { signed_in: false });
    const header = await screen.findByRole("banner");
    const login = await within(header).findByRole("link", { name: "Log in" });
    expect(login.getAttribute("href")).toBe("/signin");
    expect(within(header).getByRole("link", { name: "Sign up" }).getAttribute("href")).toBe("/signin?intent=signup");
  });

  it("shows the dashboard instead once signed in", async () => {
    renderAt("/terms", true, SIGNED_IN);
    const header = await screen.findByRole("banner");
    expect(await within(header).findByRole("link", { name: /open workbench/i })).toBeTruthy();
    expect(within(header).queryByRole("link", { name: "Sign up" })).toBeNull();
  });
});
