// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen } from "@testing-library/react";
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
    expect(screen.getByRole("link", { name: "Privacy" }).getAttribute("href")).toBe("/privacy");
    expect(screen.getByRole("link", { name: "Terms" }).getAttribute("href")).toBe("/terms");
  });

  it.each([
    ["privacy-draft.md", privacy],
    ["terms-draft.md", terms],
  ])("docs/legal/%s matches the page text", (file, doc) => {
    expect(readFileSync(resolve(DOCS, file), "utf8")).toBe(toMarkdown(doc));
  });
});
