// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { TOOL_PAGES, toolFor, tools } from "../../app/tools";
import type { DocSection } from "../docs/blocks";
import { docPages } from "../docs/content";
import { toolContent, type LocalGuide } from "./content";
import { examples } from "./examples";
import { GuidePage } from "./GuidePage";

const SECTIONS = ["Requirements", "Install", "Step by step", "Example output", "Troubleshooting"];

function referenceText(sections: DocSection[]): string[] {
  return sections.flatMap((section) =>
    section.blocks.flatMap((block) => {
      switch (block.kind) {
        case "p":
          return [block.text];
        case "list":
        case "steps":
          return block.items;
        case "code":
          return [block.code];
        default:
          return [];
      }
    }),
  );
}

function guideText(guide: LocalGuide): string[] {
  return [
    ...guide.requirements,
    ...guide.install.flatMap((item) => [item.command, item.note ?? ""]),
    ...guide.steps.flatMap((step) => [step.title, step.detail ?? "", step.command ?? ""]),
    ...guide.troubleshooting.flatMap((item) => [item.problem, item.fix]),
  ].filter(Boolean);
}

describe("tool content, defined once", () => {
  it("has one entry per tool, each with a summary, reference sections, a guide and a real example", () => {
    expect(Object.keys(toolContent).sort()).toEqual([...TOOL_PAGES].sort());
    expect(new Set(tools.map((tool) => tool.name)).size).toBe(tools.length);
    for (const tool of tools) {
      const content = toolContent[tool.page];
      expect(tool.summary.length).toBeGreaterThan(40);
      expect(content.reference.length).toBeGreaterThan(0);
      for (const list of [content.local.requirements, content.local.install, content.local.steps, content.local.troubleshooting]) {
        expect(list.length).toBeGreaterThan(0);
      }
      expect(examples[tool.page].text.length).toBeGreaterThan(0);
    }
  });

  it.each(TOOL_PAGES)("%s: no sentence is written in both the reference and the guide, or repeats the summary", (page) => {
    const reference = referenceText(toolContent[page].reference);
    const guide = guideText(toolContent[page].local);
    expect(reference.filter((text) => guide.includes(text))).toEqual([]);
    expect([...reference, ...guide]).not.toContain(toolFor(page).summary);
  });

  it("builds every tool's docs page from the same name, summary and guide", () => {
    for (const tool of tools) {
      const doc = docPages.find((page) => page.slug === tool.page);
      expect(doc?.title).toBe(tool.name);
      expect(doc?.lede).toBe(tool.summary);
      expect(doc?.sections).toBe(toolContent[tool.page].reference);
      expect(doc?.tool).toBe(tool.page);
    }
  });

  it("installs the right package for each tool", () => {
    expect(toolContent.code.local.install[0]?.command).toBe("pip install kestrix-scan");
    expect(toolContent["claude-plugin"].local.install[0]?.command).toBe("pip install kestrix-scan");
    expect(toolContent.detect.local.install[0]?.command).toBe("pip install kestrix");
    expect(toolContent.bitcoin.local.install.map((i) => i.command)).toContain('pip install "kestrix[ai]"');
  });
});

describe("GuidePage", () => {
  it.each(TOOL_PAGES)("%s: a guide with copyable commands, no live controls and a link to the docs", (page) => {
    const { container } = render(
      <MemoryRouter>
        <GuidePage tool={page} />
      </MemoryRouter>,
    );
    const tool = toolFor(page);
    expect(screen.getByRole("heading", { level: 1, name: tool.name })).toBeTruthy();
    expect(screen.getByText(tool.summary)).toBeTruthy();
    expect(screen.getByText("Run locally")).toBeTruthy();
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual(SECTIONS);
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(container.querySelector("form, input, textarea, select, button[type=submit]")).toBeNull();
    const buttons = screen.getAllByRole("button");
    expect(buttons.length).toBeGreaterThan(0);
    for (const button of buttons) expect(button.getAttribute("aria-label")).toMatch(/^Copy (command|snippet): /);
    for (const install of toolContent[page].local.install) {
      expect(screen.getByRole("button", { name: `Copy command: ${install.command}` })).toBeTruthy();
    }
    expect(screen.getByRole("link", { name: "Read the docs" }).getAttribute("href")).toBe(`/docs/${page}`);
  });
});
