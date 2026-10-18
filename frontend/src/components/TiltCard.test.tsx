// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TiltCard } from "./TiltCard";

function mockMedia(matching: string[]) {
  vi.spyOn(window, "matchMedia").mockImplementation(
    (query: string) =>
      ({
        matches: matching.includes(query),
        media: query,
        onchange: null,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        addListener: () => undefined,
        removeListener: () => undefined,
        dispatchEvent: () => false,
      }) as MediaQueryList,
  );
}

function renderCard() {
  render(
    <TiltCard>
      <p>Card body</p>
    </TiltCard>,
  );
  const card = screen.getByText("Card body").parentElement;
  if (!card) throw new Error("card missing");
  vi.spyOn(card, "getBoundingClientRect").mockReturnValue({
    left: 0,
    top: 0,
    width: 200,
    height: 100,
    right: 200,
    bottom: 100,
    x: 0,
    y: 0,
    toJSON: () => ({}),
  });
  return card;
}

describe("TiltCard", () => {
  it("tilts toward a fine pointer", () => {
    mockMedia([]);
    const card = renderCard();
    expect(card.dataset.tilt).toBe("on");
    fireEvent.pointerMove(card, { clientX: 200, clientY: 0, pointerType: "mouse" });
    expect(card.style.getPropertyValue("--ry")).toBe("5.00deg");
    expect(card.style.getPropertyValue("--rx")).toBe("5.00deg");
  });

  it("does not tilt when reduced motion is requested", () => {
    mockMedia(["(prefers-reduced-motion: reduce)"]);
    const card = renderCard();
    expect(card.dataset.tilt).toBe("off");
    expect(card.classList.contains("tilt")).toBe(false);
    fireEvent.pointerMove(card, { clientX: 200, clientY: 0, pointerType: "mouse" });
    expect(card.style.getPropertyValue("--ry")).toBe("");
  });

  it("does not tilt for coarse (touch) pointers", () => {
    mockMedia(["(pointer: coarse)"]);
    const card = renderCard();
    expect(card.dataset.tilt).toBe("off");
  });
});
