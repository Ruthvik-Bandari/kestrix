// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CodeRain } from "./CodeRain";

function mockMotion(reduce: boolean) {
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => ({ matches: reduce, addEventListener: () => undefined, removeEventListener: () => undefined })),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("CodeRain", () => {
  it("renders nothing and schedules no animation when the visitor prefers reduced motion", () => {
    mockMotion(true);
    const raf = vi.fn(() => 1);
    vi.stubGlobal("requestAnimationFrame", raf);
    const { container } = render(<CodeRain />);
    expect(container.firstChild).toBeNull();
    expect(screen.queryByTestId("code-rain")).toBeNull();
    expect(raf).not.toHaveBeenCalled();
  });

  it("is a decorative, non-interactive layer otherwise, and stops its loop on unmount", () => {
    mockMotion(false);
    const cancel = vi.fn();
    vi.stubGlobal("requestAnimationFrame", vi.fn(() => 7));
    vi.stubGlobal("cancelAnimationFrame", cancel);
    const context = {
      setTransform: vi.fn(),
      clearRect: vi.fn(),
      fillText: vi.fn(),
    };
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(context as unknown as CanvasRenderingContext2D);
    const { unmount } = render(<CodeRain />);
    const layer = screen.getByTestId("code-rain");
    expect(layer.getAttribute("aria-hidden")).toBe("true");
    expect(layer.className).toContain("pointer-events-none");
    unmount();
    expect(cancel).toHaveBeenCalledWith(7);
  });
});
