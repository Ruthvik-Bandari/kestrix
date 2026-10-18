// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import OverviewPage from "./OverviewPage";

describe("OverviewPage", () => {
  it("shows the modules as plain glass cards, with no pointer tilt", () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(() => new Promise<Response>(() => undefined));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <OverviewPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const cards = screen.getAllByRole("heading", { level: 3 }).map((h) => h.closest(".glass"));
    expect(cards).toHaveLength(5);
    cards.forEach((card) => {
      expect(card).toBeTruthy();
    });
    expect(container.querySelector("[data-tilt], .tilt, .tilt-sheen")).toBeNull();
  });
});
