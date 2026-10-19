// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeServer, SIGNED_IN } from "../test/fakeServer";
import { api, ApiError, onSignInRequired, setCsrfToken } from "./api";
import { setMode } from "./mode";

const URL_REPORT = { url: "https://a.example", findings: [] };

afterEach(() => {
  vi.unstubAllGlobals();
  onSignInRequired(null);
});

describe("CSRF header", () => {
  it("is sent on state-changing requests in hosted mode, with the token from /api/auth/me", async () => {
    setMode("hosted");
    const { calls } = fakeServer({ "GET /api/auth/me": { body: SIGNED_IN }, "POST /api/forensics/url": { body: URL_REPORT } });
    await api.me();
    await api.analyzeUrl("https://a.example");
    await api.health().catch(() => undefined);
    const post = calls.find((c) => c.method === "POST");
    expect(post?.headers.get("X-CSRF-Token")).toBe("csrf-token-1");
    for (const get of calls.filter((c) => c.method === "GET")) expect(get.headers.has("X-CSRF-Token")).toBe(false);
  });

  it("is never sent by a local dashboard", async () => {
    setCsrfToken("left-over-token");
    const { calls } = fakeServer({ "POST /api/forensics/url": { body: URL_REPORT } });
    await api.analyzeUrl("https://a.example");
    expect(calls[0]?.headers.has("X-CSRF-Token")).toBe(false);
  });

  it("is cleared after sign-out", async () => {
    setMode("hosted");
    const { calls } = fakeServer({
      "GET /api/auth/me": { body: SIGNED_IN },
      "POST /api/auth/logout": { status: 204 },
      "POST /api/forensics/url": { status: 401, body: { reason: "sign_in_required", detail: "sign in" } },
    });
    await api.me();
    await api.logout();
    expect(calls[1]?.headers.get("X-CSRF-Token")).toBe("csrf-token-1");
    await api.analyzeUrl("https://a.example").catch(() => undefined);
    expect(calls[2]?.headers.has("X-CSRF-Token")).toBe(false);
  });
});

describe("hosted error handling", () => {
  it("asks for sign-in on 401 sign_in_required", async () => {
    setMode("hosted");
    const handler = vi.fn();
    onSignInRequired(handler);
    fakeServer({ "POST /api/mail/analyze": { status: 401, body: { reason: "sign_in_required", detail: "sign in to use this feature" } } });
    const error = await api.analyzeMail(new File(["x"], "m.eml"), { protectedDomains: [], trustedAuthservId: "" }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("refreshes the token and retries once after 403 csrf_failed", async () => {
    setMode("hosted");
    let tries = 0;
    const { calls } = fakeServer({
      "GET /api/auth/me": () => ({ body: { ...SIGNED_IN, csrf_token: `token-${calls.filter((c) => c.path === "/api/auth/me").length}` } }),
      "POST /api/forensics/url": (call) => {
        tries += 1;
        return call.headers.get("X-CSRF-Token") === "token-2"
          ? { body: URL_REPORT }
          : { status: 403, body: { reason: "csrf_failed", detail: "missing or invalid X-CSRF-Token header" } };
      },
    });
    await api.me();
    await expect(api.analyzeUrl("https://a.example")).resolves.toEqual(URL_REPORT);
    expect(tries).toBe(2);
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      "GET /api/auth/me",
      "POST /api/forensics/url",
      "GET /api/auth/me",
      "POST /api/forensics/url",
    ]);
  });

  it("gives up after one retry", async () => {
    setMode("hosted");
    const { calls } = fakeServer({
      "GET /api/auth/me": { body: SIGNED_IN },
      "POST /api/forensics/url": { status: 403, body: { reason: "csrf_failed", detail: "missing or invalid X-CSRF-Token header" } },
    });
    const error = await api.analyzeUrl("https://a.example").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).reason).toBe("csrf_failed");
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(2);
  });

  it("does not retry other 403s", async () => {
    setMode("hosted");
    const { calls } = fakeServer({
      "POST /api/webcheck": { status: 403, body: { reason: "target_not_allowed", detail: "private address" } },
    });
    await api.webcheckHosted("https://10.0.0.1").catch(() => undefined);
    expect(calls).toHaveLength(1);
  });

  it("keeps the server's detail and Retry-After on 429", async () => {
    setMode("hosted");
    fakeServer({
      "POST /api/webcheck": {
        status: 429,
        body: { reason: "rate_limited", detail: "too many requests; try again in 1200 seconds" },
        headers: { "Retry-After": "1200" },
      },
    });
    const error = (await api.webcheckHosted("https://a.example").catch((e: unknown) => e)) as ApiError;
    expect(error.reason).toBe("rate_limited");
    expect(error.detail).toBe("too many requests; try again in 1200 seconds");
    expect(error.retryAfter).toBe(1200);
  });
});
