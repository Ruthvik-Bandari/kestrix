// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { BackgroundWords } from "./BackgroundWords";

describe("BackgroundWords", () => {
  it("is decorative: hidden from assistive technology and never focusable", () => {
    render(<BackgroundWords />);
    const field = screen.getByTestId("background-words");
    expect(field.getAttribute("aria-hidden")).toBe("true");
    expect(field.querySelectorAll(".bg-word").length).toBe(16);
    expect(field.querySelector("a, button, input, [tabindex]")).toBeNull();
  });
});
