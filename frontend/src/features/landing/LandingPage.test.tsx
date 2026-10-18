// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { DASHBOARD_PATH, LANDING_PATH } from "../../app/paths";
import { REPO_URL } from "../../lib/site";
import LandingPage from "./LandingPage";

function renderLanding(props: { signInUrl?: string | null } = {}) {
  return render(
    <MemoryRouter initialEntries={[LANDING_PATH]}>
      <LandingPage {...props} />
    </MemoryRouter>,
  );
}

const featureNames = ["Email check", "Web check", "Forensics", "Detection repair", "Bitcoin quantum risk"];

describe("LandingPage", () => {
  it("shows the wordmark, the promise and both hero calls to action", () => {
    renderLanding();
    expect(screen.getByRole("heading", { level: 1, name: "Kestrix" })).toBeTruthy();
    expect(screen.getByText("A security workbench that explains every answer. Runs on your computer.")).toBeTruthy();
    const open = screen.getAllByRole("link", { name: /open the dashboard/i });
    expect(open.length).toBeGreaterThan(0);
    open.forEach((link) => {
      expect(link.getAttribute("href")).toBe(DASHBOARD_PATH);
    });
    const how = screen.getAllByRole("link", { name: "How it works" });
    expect(how.some((link) => link.getAttribute("href") === "#how-it-works")).toBe(true);
    expect(document.getElementById("how-it-works")).toBeTruthy();
  });

  it("presents all five features", () => {
    renderLanding();
    const list = screen.getByRole("heading", { name: /five tools/i }).closest("section");
    if (!list) throw new Error("features section missing");
    for (const name of featureNames) {
      expect(within(list).getByRole("heading", { level: 3, name })).toBeTruthy();
    }
    expect(within(list).getAllByText("Protects you from")).toHaveLength(5);
  });

  it("explains each module's flow from input to verdict", () => {
    renderLanding();
    const section = document.getElementById("how-it-works")?.closest("section");
    if (!section) throw new Error("how-it-works section missing");
    for (const name of featureNames) {
      expect(within(section).getByRole("heading", { level: 3, name })).toBeTruthy();
    }
    expect(within(section).getAllByText("Explained verdict")).toHaveLength(5);
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
