// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { HoloGlobe } from "./HoloGlobe";

describe("HoloGlobe", () => {
  it("is decorative: hidden from assistive technology and out of the tab order", () => {
    render(<HoloGlobe />);
    const globe = screen.getByTestId("holo-globe");
    expect(globe.getAttribute("aria-hidden")).toBe("true");
    const canvas = globe.querySelector("canvas");
    expect(canvas?.getAttribute("tabindex")).toBe("-1");
  });
});
