// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { dashboardPath, landingPath, pageAvailable, safeNext, signInPath } from "../app/paths";
import { isHosted, modeFromHealth, setMode } from "./mode";

describe("mode detection", () => {
  it("is hosted only when /api/health says so", () => {
    expect(modeFromHealth({ status: "ok", version: "0.1.0", modules: [] })).toBe("local");
    expect(modeFromHealth({ status: "ok", mode: "hosted" })).toBe("hosted");
    expect(modeFromHealth({ mode: "something-else" })).toBe("local");
    expect(modeFromHealth(null)).toBe("local");
  });

  it("starts local", () => {
    expect(isHosted()).toBe(false);
  });
});

describe("paths", () => {
  it("keeps the local layout: dashboard at /, landing at /welcome, every page", () => {
    expect(dashboardPath()).toBe("/");
    expect(dashboardPath("mail")).toBe("/mail");
    expect(dashboardPath("/forensics?tab=url")).toBe("/forensics?tab=url");
    expect(landingPath()).toBe("/welcome");
    expect(pageAvailable("detect")).toBe(true);
    expect(pageAvailable("bitcoin/migration/p2pk")).toBe(true);
  });

  it("moves the dashboard under /app and drops local-only pages when hosted", () => {
    setMode("hosted");
    expect(dashboardPath()).toBe("/app");
    expect(dashboardPath("mail")).toBe("/app/mail");
    expect(landingPath()).toBe("/");
    for (const page of ["detect", "detect?tab=custom", "bitcoin"]) expect(pageAvailable(page)).toBe(false);
    for (const page of ["webcheck", "forensics", "mail", "settings", "history", "docs"]) expect(pageAvailable(page)).toBe(true);
  });

  it("only returns to same-origin paths after sign-in", () => {
    expect(safeNext("/app/mail?x=1")).toBe("/app/mail?x=1");
    for (const bad of ["//evil.example", "https://evil.example", "/\\evil.example", "/a b", "app", "", null]) {
      expect(safeNext(bad)).toBeNull();
    }
    expect(signInPath("/app/mail")).toBe("/signin?next=%2Fapp%2Fmail");
    expect(signInPath("//evil.example")).toBe("/signin");
  });
});
