// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { dashboardPath, landingPath, PRIVACY_PATH, SIGNIN_PATH, SIGNUP_PATH } from "../../app/paths";
import { setMode } from "../../lib/mode";
import { REPO_URL } from "../../lib/site";
import { fakeServer, HOSTED_HEALTH, SIGNED_IN } from "../../test/fakeServer";
import LandingPage from "./LandingPage";
import { emailSample } from "./samples";

afterEach(() => {
  setMode("local");
  vi.unstubAllGlobals();
});

function renderLanding() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[landingPath()]}>
        <LandingPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function renderHosted(signedIn: boolean) {
  setMode("hosted");
  fakeServer({
    "GET /api/health": { body: HOSTED_HEALTH },
    "GET /api/auth/me": { body: signedIn ? SIGNED_IN : { signed_in: false } },
    "GET /api/auth/providers": { body: { providers: ["google", "github"] } },
  });
  return renderLanding();
}

function row(name: string): HTMLElement {
  const link = screen.getByRole("link", { name: new RegExp(`^${name}`) });
  return link;
}

describe("LandingPage in local mode", () => {
  it("states the proposition and has one workbench action in the header and the hero", () => {
    renderLanding();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("See the risk. Understand the evidence.");
    const header = screen.getByRole("banner");
    expect(within(header).getByRole("link", { name: /open workbench/i }).getAttribute("href")).toBe(dashboardPath());
    const hero = screen.getByRole("heading", { level: 1 }).closest("section");
    if (!hero) throw new Error("hero missing");
    expect(within(hero).getByRole("link", { name: /open workbench/i }).getAttribute("href")).toBe(dashboardPath());
    expect(within(hero).getByRole("link", { name: "Explore an example" }).getAttribute("href")).toBe("#example");
    expect(document.getElementById("example")).not.toBeNull();
    expect(screen.queryByRole("link", { name: /log in|sign up|get started/i })).toBeNull();
    expect(screen.queryByRole("tablist")).toBeNull();
  });

  it("links the public logo to the landing page", () => {
    renderLanding();
    expect(screen.getByRole("link", { name: "Kestrix home" }).getAttribute("href")).toBe(landingPath());
  });

  it("shows the report card from the bundled sample, labelled synthetic", () => {
    renderLanding();
    const card = screen.getByRole("article", { name: "Example email report" });
    const { report, message } = emailSample;
    expect(within(card).getByText("Malicious")).toBeTruthy();
    expect(within(card).getByText(String(report.findings.length))).toBeTruthy();
    expect(within(card).getByText(message.subject)).toBeTruthy();
    expect(within(card).getByText(`From ${message.from_address}`)).toBeTruthy();
    const items = within(within(card).getByRole("list", { name: "Top findings" })).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    for (const [index, item] of items.entries()) {
      expect(within(item).getByText(report.findings[index]?.title ?? "")).toBeTruthy();
      expect(within(item).getByText("High")).toBeTruthy();
    }
    expect(within(card).getByText("5 high · 4 medium · 3 other")).toBeTruthy();
    expect(within(card).getByText("Synthetic example")).toBeTruthy();
    expect(screen.getByText("Synthetic example · actual analyzer output")).toBeTruthy();
  });

  it("groups the tools and labels each one for local mode", () => {
    renderLanding();
    const everyday = screen.getByRole("list", { name: "Everyday checks" });
    const deeper = screen.getByRole("list", { name: "For deeper investigation" });
    expect(within(everyday).getAllByRole("listitem")).toHaveLength(3);
    expect(within(deeper).getAllByRole("listitem")).toHaveLength(3);
    const expected: [string, string, string][] = [
      ["Email", "mail", "In the workbench"],
      ["Website", "webcheck", "In the workbench"],
      ["File & link", "forensics", "In the workbench"],
      ["Detection repair", "detect", "In the workbench"],
      ["Code & Claude", "code", "Setup guide"],
      ["Bitcoin", "bitcoin", "In the workbench"],
    ];
    for (const [name, page, label] of expected) {
      const link = row(name);
      expect(link.getAttribute("href")).toBe(dashboardPath(page));
      expect(within(link).getByText(label)).toBeTruthy();
    }
  });

  it("explains input, evidence and decision once each", () => {
    renderLanding();
    const steps = within(screen.getByRole("heading", { level: 2, name: /less guesswork/i }).closest("section") ?? document.body)
      .getAllByRole("listitem");
    expect(steps).toHaveLength(3);
    expect(steps.map((s) => s.querySelector("h3")?.textContent)).toEqual([
      "Bring one thing to check",
      "Read what was found",
      "Decide what comes next",
    ]);
  });

  it("splits the data handling between running locally and the hosted workspace", () => {
    renderLanding();
    const section = screen.getByRole("heading", { level: 2, name: /choose the setup/i }).closest("section");
    if (!section) throw new Error("trust section missing");
    expect(within(section).getByRole("heading", { level: 3, name: /run locally/i })).toBeTruthy();
    expect(within(section).getByRole("heading", { level: 3, name: /hosted workspace/i })).toBeTruthy();
    expect(within(section).getByText(/raw uploads are not stored/i)).toBeTruthy();
    expect(within(section).getByText(/heuristics, not probabilities/i)).toBeTruthy();
    expect(within(section).getByRole("link", { name: /privacy notice/i }).getAttribute("href")).toBe(PRIVACY_PATH);
  });

  it("does not present an unpublished PyPI package as installable", () => {
    renderLanding();
    expect(screen.queryByText("pip install kestrix")).toBeNull();
    expect(screen.getByText(/PyPI release pending/i)).toBeTruthy();
    // A git install has no built dashboard, so the landing shows the from-source build that does.
    expect(screen.getByText(/npm --prefix frontend run build/)).toBeTruthy();
    expect(screen.getByText(new RegExp(`git clone ${REPO_URL.replace(/[.]/g, "\\.")}`))).toBeTruthy();
  });

  it("keeps the attribution, docs, repository and license links in the footer, once", () => {
    renderLanding();
    const footer = screen.getByRole("contentinfo");
    expect(within(footer).getByText("Kestrix by Ruthvik Bandari")).toBeTruthy();
    expect(screen.getAllByText(/Ruthvik Bandari/)).toHaveLength(1);
    expect(within(footer).getByRole("link", { name: "GitHub repository" }).getAttribute("href")).toBe(REPO_URL);
    expect(within(footer).getByRole("link", { name: "Documentation" }).getAttribute("href")).toBe("/docs");
    expect(within(footer).getByRole("link", { name: "License (Apache-2.0)" })).toBeTruthy();
    expect(within(footer).getByRole("link", { name: "Privacy" }).getAttribute("href")).toBe(PRIVACY_PATH);
    expect(within(footer).getByRole("link", { name: "Terms" })).toBeTruthy();
  });

  it("makes no unsupported claims", () => {
    const { container } = renderLanding();
    const text = container.textContent;
    expect(text).not.toMatch(/contained|guarantee|certified|accuracy|customers|real-time|monitoring/i);
  });
});

describe("LandingPage mobile menu", () => {
  it("opens with the same destinations, closes on Escape and returns focus to the button", () => {
    renderLanding();
    const button = screen.getByRole("button", { name: "Menu" });
    const menu = document.getElementById(button.getAttribute("aria-controls") ?? "");
    if (!menu) throw new Error("menu missing");
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(menu.hidden).toBe(true);
    fireEvent.click(button);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(menu.hidden).toBe(false);
    const links = within(menu).getAllByRole("link");
    expect(links.map((l) => l.textContent)).toEqual(["Tools", "Example", "Privacy", "Docs"]);
    expect(links.map((l) => l.getAttribute("href"))).toEqual(["#tools", "#example", PRIVACY_PATH, dashboardPath("docs")]);
    links[0]?.focus();
    fireEvent.keyDown(links[0] ?? menu, { key: "Escape" });
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(menu.hidden).toBe(true);
    expect(document.activeElement).toBe(button);
  });

  it("closes when a link is chosen", () => {
    renderLanding();
    const button = screen.getByRole("button", { name: "Menu" });
    fireEvent.click(button);
    const menu = document.getElementById(button.getAttribute("aria-controls") ?? "");
    if (!menu) throw new Error("menu missing");
    fireEvent.click(within(menu).getByRole("link", { name: "Privacy" }));
    expect(button.getAttribute("aria-expanded")).toBe("false");
  });
});

describe("LandingPage on the hosted service", () => {
  it("offers Log in, Sign up and Get started while signed out, and no dashboard shortcut", async () => {
    renderHosted(false);
    const header = screen.getByRole("banner");
    expect((await within(header).findByRole("link", { name: "Log in" })).getAttribute("href")).toBe(SIGNIN_PATH);
    expect(within(header).getByRole("link", { name: "Sign up" }).getAttribute("href")).toBe(SIGNUP_PATH);
    const hero = screen.getByRole("heading", { level: 1 }).closest("section");
    if (!hero) throw new Error("hero missing");
    expect(within(hero).getByRole("link", { name: /get started/i }).getAttribute("href")).toBe(SIGNUP_PATH);
    expect(screen.queryByRole("link", { name: /open workbench/i })).toBeNull();
    expect(screen.queryByRole("tablist")).toBeNull();
  });

  it("sends a signed-in visitor to the workbench from the header and the hero", async () => {
    renderHosted(true);
    const header = screen.getByRole("banner");
    const open = await within(header).findByRole("link", { name: /open workbench/i });
    expect(open.getAttribute("href")).toBe("/app");
    expect(within(header).queryByRole("link", { name: "Log in" })).toBeNull();
    const hero = screen.getByRole("heading", { level: 1 }).closest("section");
    if (!hero) throw new Error("hero missing");
    expect((await within(hero).findByRole("link", { name: /open workbench/i })).getAttribute("href")).toBe("/app");
    expect(within(hero).queryByRole("link", { name: /get started/i })).toBeNull();
  });

  it("labels each tool for the hosted service", async () => {
    renderHosted(false);
    await screen.findByRole("link", { name: "Log in" });
    const expected: [string, string, string][] = [
      ["Email", "mail", "In your browser"],
      ["Website", "webcheck", "In your browser"],
      ["File & link", "forensics", "In your browser"],
      ["Detection repair", "detect", "Run locally"],
      ["Code & Claude", "code", "Setup guide"],
      ["Bitcoin", "bitcoin", "Run locally"],
    ];
    for (const [name, page, label] of expected) {
      const link = row(name);
      expect(link.getAttribute("href")).toBe(`/app/${page}`);
      expect(within(link).getByText(label)).toBeTruthy();
    }
  });

  it("links the public docs page, not the private repository", async () => {
    renderHosted(false);
    await screen.findByRole("link", { name: "Log in" });
    expect(within(screen.getByRole("banner")).getByRole("link", { name: "Docs" }).getAttribute("href")).toBe("/docs");
    expect(within(screen.getByRole("contentinfo")).getByRole("link", { name: "Documentation" }).getAttribute("href")).toBe("/docs");
  });
});
