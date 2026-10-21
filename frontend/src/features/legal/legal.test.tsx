// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { DRAFT_BANNER, privacy, terms, type LegalDoc } from "./content";
import PrivacyPage from "./PrivacyPage";
import TermsPage from "./TermsPage";

/** docs/legal/*-draft.md must carry exactly the text the pages show. */
function toMarkdown(doc: LegalDoc): string {
  const out = [`# ${doc.title} (draft)`, `> ${DRAFT_BANNER}`, `_${doc.updated}_`, ...doc.intro];
  for (const section of doc.sections) {
    out.push(`## ${section.heading}`);
    for (const block of section.blocks) out.push("p" in block ? block.p : block.ul.map((item) => `- ${item}`).join("\n"));
  }
  return `${out.join("\n\n")}\n`;
}

const DOCS = resolve(import.meta.dirname, "../../../../docs/legal");

describe("legal pages", () => {
  it.each([
    ["Privacy notice", PrivacyPage],
    ["Terms of use", TermsPage],
  ])("%s shows the draft banner and the attribution", (title, Page) => {
    render(
      <MemoryRouter>
        <Page />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { level: 1, name: title })).toBeTruthy();
    expect(screen.getByRole("note").textContent).toBe("Draft — to be reviewed by the owner before launch. Not legal advice.");
    expect(screen.getByText("Kestrix by Ruthvik Bandari")).toBeTruthy();
    const footer = within(screen.getByRole("contentinfo"));
    expect(footer.getByRole("link", { name: "Privacy" }).getAttribute("href")).toBe("/privacy");
    expect(footer.getByRole("link", { name: "Terms" }).getAttribute("href")).toBe("/terms");
  });

  it.each([
    ["Privacy notice", PrivacyPage],
    ["Terms of use", TermsPage],
  ])("%s has an On this page list that targets every h2", (_title, Page) => {
    render(
      <MemoryRouter>
        <Page />
      </MemoryRouter>,
    );
    const links = within(screen.getByRole("navigation", { name: "On this page" })).getAllByRole("link");
    const headings = screen.getAllByRole("heading", { level: 2 });
    expect(links.map((link) => link.textContent)).toEqual(headings.map((h) => h.textContent));
    for (const [index, link] of links.entries()) {
      expect(document.getElementById((link.getAttribute("href") ?? "").replace(/^#/, ""))).toBe(headings[index]);
    }
  });

  it.each([
    ["privacy-draft.md", privacy],
    ["terms-draft.md", terms],
  ])("docs/legal/%s matches the page text", (file, doc) => {
    expect(readFileSync(resolve(DOCS, file), "utf8")).toBe(toMarkdown(doc));
  });
});
