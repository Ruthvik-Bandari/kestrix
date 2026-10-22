// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it } from "vitest";
import { TOOL_PAGES } from "../app/tools";
import { SiteFooter } from "./PublicShell";
import { DocsRoutes } from "../test/docsRoutes";
import { ToolHeader } from "../features/tools/ToolHeader";
import { railCopy } from "../features/tools/frame";
import { setMode } from "../lib/mode";
import type { HistoryItem, HistoryPage } from "../lib/types";
import { toolPageClient } from "../test/fakeServer";
import { StageProvider, StepRail, stageOf, useReportStage, type ToolStage } from "./toolframe";

afterEach(() => {
  setMode("local");
});

function Reporter({ stage }: { stage: ToolStage }) {
  useReportStage(stage);
  return null;
}

function renderHeader(stage: ToolStage, history?: HistoryPage) {
  return render(
    <QueryClientProvider client={toolPageClient(history)}>
      <MemoryRouter>
        <StageProvider>
          <ToolHeader page="mail" />
          <Reporter stage={stage} />
        </StageProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function steps() {
  return within(screen.getByRole("list", { name: "Progress" })).getAllByRole("listitem");
}

describe("stageOf", () => {
  it("reads the page's real state", () => {
    expect(stageOf({ ready: false, pending: false, failed: false, done: false })).toBe("input");
    expect(stageOf({ ready: true, pending: false, failed: false, done: false })).toBe("ready");
    expect(stageOf({ ready: true, pending: true, failed: false, done: false })).toBe("running");
    expect(stageOf({ ready: true, pending: false, failed: false, done: true })).toBe("result");
    expect(stageOf({ ready: true, pending: false, failed: true, done: false })).toBe("error");
  });
});

describe("step rail", () => {
  it.each([
    ["input", 0, "Choose an .eml file"],
    ["ready", 0, "Ready: run it when you are"],
    ["running", 1, "Checking…"],
    ["result", 2, "Your call, with the evidence in the report"],
    ["error", 0, "The check failed. Your input is still filled in."],
  ] as const)("%s: step %i is current", (stage, current, hint) => {
    render(<StepRail stage={stage} copy={railCopy.mail} />);
    const items = steps();
    expect(items).toHaveLength(3);
    items.forEach((item, index) => {
      expect(item.getAttribute("aria-current")).toBe(index === current ? "step" : null);
    });
    expect(screen.getAllByText(hint).length).toBeGreaterThan(0);
  });

  it("marks finished steps as done in text, not by colour alone", () => {
    render(<StepRail stage="result" copy={railCopy.mail} />);
    expect(steps()[0]?.textContent).toContain("done");
    expect(steps()[2]?.textContent).toContain("current step");
    expect(steps()[2]?.textContent).not.toContain("done");
  });

  it("follows the stage a page's layout reports to the header band", () => {
    renderHeader("running");
    expect(steps()[1]?.getAttribute("aria-current")).toBe("step");
  });
});

function item(over: Partial<HistoryItem>): HistoryItem {
  return { id: "r1", tool: "mail", created_at: Math.floor(Date.now() / 1000) - 7200, verdict: "malicious", findings: 4, ...over };
}

function page(items: HistoryItem[], over: Partial<HistoryPage> = {}): HistoryPage {
  return { enabled: true, retention_days: 30, page: 1, per_page: 20, total: items.length, items, ...over };
}

describe("history stats strip", () => {
  it("shows this tool's real saved reports: count, latest verdict, time and links", () => {
    renderHeader("input", page([item({ id: "new" }), item({ id: "web", tool: "webcheck", verdict: "A" }), item({ id: "old", verdict: "clean" })]));
    const strip = screen.getByRole("complementary", { name: "Your saved reports for this tool" });
    expect(within(strip).getByText("2")).toBeTruthy();
    expect(within(strip).getByText("reports")).toBeTruthy();
    expect(within(strip).getByText("Malicious")).toBeTruthy();
    expect(within(strip).getByText("2 h ago")).toBeTruthy();
    expect(within(strip).getByRole("link", { name: "Open the last report" }).getAttribute("href")).toBe("/history/new");
    expect(within(strip).getByRole("link", { name: "All results" }).getAttribute("href")).toBe("/history");
  });

  it("says N+ when only the newest page of a longer history was read", () => {
    renderHeader("input", page([item({})], { total: 55 }));
    expect(screen.getByText("1+")).toBeTruthy();
  });

  it("is hidden when history is off", () => {
    renderHeader("input", page([item({})], { enabled: false }));
    expect(screen.queryByRole("complementary", { name: /saved reports/i })).toBeNull();
  });

  it("is hidden when nothing is saved for this tool", () => {
    renderHeader("input", page([]));
    expect(screen.queryByRole("complementary", { name: /saved reports/i })).toBeNull();
    renderHeader("input", page([item({ tool: "webcheck", verdict: "B" })]));
    expect(screen.queryByRole("complementary", { name: /saved reports/i })).toBeNull();
  });
});

describe("documentation links stay inside the app", () => {
  function docLinks(): string[] {
    return screen
      .getAllByRole("link")
      .filter((a) => /docs|documentation/i.test(a.textContent))
      .map((a) => a.getAttribute("href") ?? "");
  }

  it.each(TOOL_PAGES)("%s: the header's Read the docs link is an in-app path", (tool) => {
    render(
      <MemoryRouter>
        <ToolHeader page={tool} guide />
      </MemoryRouter>,
    );
    const links = docLinks();
    expect(links.length).toBeGreaterThan(0);
    for (const href of links) {
      expect(href).toMatch(/^\//);
      expect(href).not.toContain("github.com");
    }
  });

  it("the footer's Documentation link is in-app and its repository link says Source code", () => {
    render(
      <MemoryRouter>
        <SiteFooter />
      </MemoryRouter>,
    );
    for (const href of docLinks()) expect(href).toBe("/docs");
    expect(screen.getByRole("link", { name: "Source code" }).getAttribute("href")).toContain("github.com");
  });

  it("the hosted-service page links nowhere outside the app (only the reporting and reference pages link to the repository)", () => {
    render(
      <MemoryRouter initialEntries={["/docs/getting-started/hosted-service"]}>
        <DocsRoutes />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { level: 1, name: "The hosted service" })).toBeTruthy();
    for (const a of screen.getAllByRole("link")) expect(a.getAttribute("href") ?? "").not.toContain("github.com");
  });
});
