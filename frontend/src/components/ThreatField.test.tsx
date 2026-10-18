// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ThreatField } from "./ThreatField";

describe("ThreatField", () => {
  it("is decorative and renders even where canvas drawing is unavailable", () => {
    render(<ThreatField />);
    const canvas = screen.getByTestId("threat-field");
    expect(canvas.tagName).toBe("CANVAS");
    expect(canvas.getAttribute("aria-hidden")).toBe("true");
    expect(canvas.getAttribute("tabindex")).toBe("-1");
  });
});
