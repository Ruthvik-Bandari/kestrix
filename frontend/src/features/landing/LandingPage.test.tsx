// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { dashboardPath, landingPath } from "../../app/paths";
import { REPO_URL } from "../../lib/site";
import { chapters } from "./content";
import LandingPage from "./LandingPage";
import { FINDINGS_SHOWN } from "./parts";
import { emailSample } from "./samples";

function mockMedia(matching: string[]) {
  vi.spyOn(window, "matchMedia").mockImplementation(
    (query: string) =>
      ({
        matches: matching.includes(query),
        media: query,
        onchange: null,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        addListener: () => undefined,
        removeListener: () => undefined,
        dispatchEvent: () => false,
      }) as MediaQueryList,
  );
}

function renderLanding(props: { signInUrl?: string | null } = {}) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[landingPath()]}>
        <LandingPage {...props} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function compareRoot(toggle: HTMLElement): HTMLElement {
  const root = toggle.closest<HTMLElement>("[data-compare]");
  if (!root) throw new Error("comparison root missing");
  return root;
}

describe("LandingPage", () => {
  it("shows the wordmark, the headline and the calls to action", () => {
    renderLanding();
    expect(screen.getByRole("heading", { level: 1, name: "Kestrix" })).toBeTruthy();
    expect(screen.getByText("Same inbox. Same file. Two endings.")).toBeTruthy();
    const open = screen.getAllByRole("link", { name: /open the dashboard/i });
    expect(open.length).toBeGreaterThan(1);
    open.forEach((link) => {
      expect(link.getAttribute("href")).toBe(dashboardPath());
    });
    expect(screen.getByRole("link", { name: /start the story/i }).getAttribute("href")).toBe(`#${chapters[0]?.id ?? ""}`);
  });

  it("renders every chapter with its comparison and real output", () => {
    renderLanding();
    expect(chapters).toHaveLength(6);
    for (const chapter of chapters) {
      const heading = screen.getByRole("heading", { level: 2, name: chapter.title });
      const section = heading.closest("section");
      if (!section) throw new Error(`${chapter.id} section missing`);
      expect(within(section).getByRole("group", { name: /^Compare / })).toBeTruthy();
      expect(within(section).getByRole("group", { name: "Without Kestrix" })).toBeTruthy();
      expect(within(section).getByRole("group", { name: "With Kestrix" })).toBeTruthy();
      expect(within(section).getByText(`samples/${chapter.sample.name}.json`)).toBeTruthy();
    }
    expect(screen.getByRole("heading", { level: 2, name: "Run it yourself." })).toBeTruthy();
    expect(screen.getByText("pip install kestrix")).toBeTruthy();
    expect(screen.getByText(/coming soon/i)).toBeTruthy();
  });

  it("toggles every comparison from the keyboard-operable buttons", () => {
    renderLanding();
    const toggles = screen.getAllByRole("group", { name: /^Compare / });
    expect(toggles).toHaveLength(6);
    for (const toggle of toggles) {
      const root = compareRoot(toggle);
      const withButton = within(toggle).getByRole("button", { name: "With Kestrix" });
      const withoutButton = within(toggle).getByRole("button", { name: "Without Kestrix" });
      expect(root.dataset.side).toBe("without");
      expect(withoutButton.getAttribute("aria-pressed")).toBe("true");
      withButton.focus();
      expect(document.activeElement).toBe(withButton);
      fireEvent.click(withButton); // Enter and Space on a focused native button dispatch click
      expect(root.dataset.side).toBe("with");
      expect(withButton.getAttribute("aria-pressed")).toBe("true");
      fireEvent.click(withoutButton);
      expect(root.dataset.side).toBe("without");
    }
  });

  it("drives every comparison with the slider on fine pointers", () => {
    mockMedia(["(pointer: fine) and (min-width: 640px)"]);
    renderLanding();
    const sliders = screen.getAllByRole("slider");
    expect(sliders).toHaveLength(6);
    for (const slider of sliders) {
      const root = compareRoot(slider);
      fireEvent.pointerDown(slider);
      fireEvent.change(slider, { target: { value: "80" } });
      fireEvent.pointerUp(slider);
      expect(root.dataset.side).toBe("with");
      expect(slider.getAttribute("aria-valuetext")).toBe("80% with Kestrix, 20% without");
      fireEvent.change(slider, { target: { value: "10" } });
      expect(root.dataset.side).toBe("without");
    }
  });

  it("shows exactly the sample's findings in the email's Kestrix view", () => {
    renderLanding();
    const section = screen.getByRole("heading", { level: 2, name: chapters[0]?.title ?? "" }).closest("section");
    if (!section) throw new Error("email section missing");
    const withView = within(section).getByRole("group", { name: "With Kestrix" });
    const titles = () =>
      within(within(withView).getByRole("list", { name: "Email findings" }))
        .getAllByRole("listitem")
        .map((item) => item.querySelector("[data-finding-title]")?.textContent);
    const all = emailSample.report.findings.map((f) => f.title);
    // The most severe few first, so both states of the scene stay about as tall.
    expect(titles()).toEqual(all.slice(0, FINDINGS_SHOWN));
    const more = within(withView).getByRole("button", { name: `Show all ${String(all.length)} findings` });
    expect(more.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(more);
    expect(more.getAttribute("aria-expanded")).toBe("true");
    expect(titles()).toEqual(all);
    expect(within(withView).getByText(emailSample.report.verdict)).toBeTruthy();
    expect(within(withView).getByText(`${String(emailSample.report.findings.length)} reasons`, { exact: false })).toBeTruthy();
  });

  it("shows both states statically, without a fake cursor, under reduced motion", () => {
    mockMedia(["(prefers-reduced-motion: reduce)", "(pointer: fine) and (min-width: 640px)"]);
    const { container } = renderLanding();
    expect(container.querySelectorAll('[data-compare="static"]')).toHaveLength(6);
    expect(container.querySelectorAll('[data-compare="interactive"]')).toHaveLength(0);
    expect(screen.queryAllByRole("slider")).toHaveLength(0);
    expect(screen.queryAllByTestId("fake-cursor")).toHaveLength(0);
    expect(screen.getAllByRole("group", { name: "With Kestrix" })).toHaveLength(6);
  });

  it("animates the fake cursor only in the visible Without state", () => {
    renderLanding();
    expect(screen.getAllByTestId("fake-cursor").length).toBeGreaterThan(0);
  });

  it("keeps the attribution and the repository link in the footer", () => {
    renderLanding();
    const footer = screen.getByRole("contentinfo");
    expect(within(footer).getByText("Kestrix by Ruthvik Bandari")).toBeTruthy();
    expect(within(footer).getByRole("link", { name: "GitHub repository" }).getAttribute("href")).toBe(REPO_URL);
  });

  it("shows Sign in only when a sign-in URL is configured", () => {
    const view = renderLanding();
    expect(screen.queryByRole("link", { name: "Sign in" })).toBeNull();
    view.unmount();
    renderLanding({ signInUrl: "/auth/sign-in" });
    expect(screen.getAllByRole("link", { name: "Sign in" })[0]?.getAttribute("href")).toBe("/auth/sign-in");
  });
});
