// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it } from "vitest";
import { setMode } from "../lib/mode";
import { DataNote } from "./DataNote";

function renderNote() {
  return render(
    <MemoryRouter>
      <DataNote subject="The file" />
    </MemoryRouter>,
  );
}

afterEach(() => {
  setMode("local");
});

describe("DataNote", () => {
  it("says a local check never leaves the computer", () => {
    setMode("local");
    renderNote();
    expect(screen.getByText("The file is checked on this computer and never leaves it.")).toBeTruthy();
    expect(screen.queryByRole("link")).toBeNull();
  });

  it("says a hosted check goes to Kestrix's server, is never stored, and links the privacy notice", () => {
    setMode("hosted");
    renderNote();
    expect(screen.getByText(/The file is checked on Kestrix's server and never stored/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Privacy notice" }).getAttribute("href")).toBe("/privacy");
  });
});
