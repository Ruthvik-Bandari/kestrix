// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
import { cancelRefresh, setCsrfToken } from "../lib/api";
import { setMode } from "../lib/mode";

afterEach(() => {
  cleanup();
  // Hosted-mode tests switch the mode and hold a CSRF token; every test starts local.
  setMode("local");
  setCsrfToken(null);
  cancelRefresh();
});

// jsdom implements neither matchMedia nor canvas drawing; the decorative background needs both.
if (typeof window.matchMedia !== "function") {
  window.matchMedia = (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }) as MediaQueryList;
}
HTMLCanvasElement.prototype.getContext = (() => null) as typeof HTMLCanvasElement.prototype.getContext;
