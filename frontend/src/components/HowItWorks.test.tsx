// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { HowItWorks, type HowItWorksContent } from "./HowItWorks";

const content: HowItWorksContent = {
  id: "sample",
  name: "Sample check",
  purpose: "Explains a sample.",
  steps: ["First step", "Second step", "Third step"],
  usefulWhen: ["When testing"],
  doesNot: ["It does not send anything"],
};

function toggle() {
  return screen.getByRole("button", { name: /how sample check works/i });
}

describe("HowItWorks", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("is open on the first visit and lists the steps and limits", () => {
    render(<HowItWorks content={content} />);
    expect(toggle().getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByText("Second step")).toBeTruthy();
    expect(screen.getByText("It does not send anything")).toBeTruthy();
  });

  it("collapses and expands, and remembers the choice per page", () => {
    const first = render(<HowItWorks content={content} />);
    fireEvent.click(toggle());
    expect(toggle().getAttribute("aria-expanded")).toBe("false");
    const body = document.getElementById(toggle().getAttribute("aria-controls") ?? "");
    expect(body?.hidden).toBe(true);
    expect(localStorage.getItem("kestrix-how-sample")).toBe("closed");
    first.unmount();

    render(<HowItWorks content={content} />);
    expect(toggle().getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle());
    expect(toggle().getAttribute("aria-expanded")).toBe("true");
    expect(localStorage.getItem("kestrix-how-sample")).toBe("open");
  });

  it("keeps state separate for each page", () => {
    localStorage.setItem("kestrix-how-other", "closed");
    render(<HowItWorks content={content} />);
    expect(toggle().getAttribute("aria-expanded")).toBe("true");
  });
});
