// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { CliGuide } from "./CliGuide";
import { GuidePage } from "./GuidePage";
import { GUIDE_TOOLS, guides } from "./guides";

const SECTIONS = ["What it is and how it helps", "Requirements", "Install", "Step by step", "Example output", "Troubleshooting"];

describe("GuidePage", () => {
  it.each(GUIDE_TOOLS)("%s: a guide with copyable commands and no live controls", (tool) => {
    const { container } = render(
      <MemoryRouter>
        <GuidePage tool={tool} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { level: 1, name: guides[tool].name })).toBeTruthy();
    expect(screen.getByText("Run locally")).toBeTruthy();
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual(SECTIONS);
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(container.querySelector("form, input, textarea, select, button[type=submit]")).toBeNull();
    const buttons = screen.getAllByRole("button");
    expect(buttons.length).toBeGreaterThan(0);
    for (const button of buttons) expect(button.getAttribute("aria-label")).toMatch(/^Copy (command|snippet): /);
    for (const install of guides[tool].install) {
      expect(screen.getByRole("button", { name: `Copy command: ${install.command}` })).toBeTruthy();
    }
    expect(screen.getByRole("link", { name: /documentation/ }).getAttribute("href")).toBe(`/docs/${guides[tool].docsSlug}`);
  });

  it("installs the right package for each tool", () => {
    expect(guides.code.install[0]?.command).toBe("pip install kestrix-scan");
    expect(guides["claude-plugin"].install[0]?.command).toBe("pip install kestrix-scan");
    expect(guides.detect.install[0]?.command).toBe("pip install kestrix");
    expect(guides.bitcoin.install.map((i) => i.command)).toContain('pip install "kestrix[ai]"');
  });
});

describe("CliGuide", () => {
  it("is collapsed by default", () => {
    const { container } = render(
      <MemoryRouter>
        <CliGuide tool="bitcoin" />
      </MemoryRouter>,
    );
    const details = container.querySelector("details");
    expect(details).toBeTruthy();
    expect(details?.open).toBe(false);
    expect(screen.getByText("How to use it from the command line")).toBeTruthy();
    expect(screen.getAllByRole("heading", { level: 3, hidden: true }).map((h) => h.textContent)).toEqual(SECTIONS);
  });
});
