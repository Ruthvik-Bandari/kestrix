// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fakeServer, SIGNED_IN } from "../test/fakeServer";
import { api, ApiError, MIN_REFRESH_DELAY_MS, onSignInRequired, REFRESH_LEAD_MS } from "./api";
import { setMode } from "./mode";

const URL_REPORT = { url: "https://a.example", findings: [] };
const EXPIRED = { status: 401, body: { reason: "token_expired", detail: "your sign-in needs refreshing" } };
const nowS = () => Math.floor(Date.now() / 1000);

function visibility(state: DocumentVisibilityState) {
  vi.spyOn(document, "visibilityState", "get").mockReturnValue(state);
}

beforeEach(() => {
  setMode("hosted");
  visibility("visible");
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
  onSignInRequired(null);
});

/** A server whose access token is expired until the first refresh. */
function expiringServer(extra: Parameters<typeof fakeServer>[0] = {}) {
  let refreshed = false;
  const server = fakeServer({
    "GET /api/auth/me": { body: SIGNED_IN },
    "POST /api/auth/refresh": () => {
      refreshed = true;
      return { body: { access_expires_at: nowS() + 900 } };
    },
    "POST /api/forensics/url": () => (refreshed ? { body: URL_REPORT } : EXPIRED),
    ...extra,
  });
  return server;
}

describe("refresh on 401 token_expired", () => {
  it("refreshes with the CSRF token, then retries the request once", async () => {
    const { calls } = expiringServer();
    await api.me();
    await expect(api.analyzeUrl("https://a.example")).resolves.toEqual(URL_REPORT);
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      "GET /api/auth/me",
      "POST /api/forensics/url",
      "POST /api/auth/refresh",
      "POST /api/forensics/url",
    ]);
    expect(calls[2]?.headers.get("X-CSRF-Token")).toBe("csrf-token-1");
  });

  it("is single-flight: concurrent requests share one refresh", async () => {
    const { calls } = expiringServer();
    await api.me();
    const results = await Promise.all([api.analyzeUrl("https://a.example"), api.analyzeUrl("https://b.example"), api.analyzeUrl("https://c.example")]);
    expect(results).toEqual([URL_REPORT, URL_REPORT, URL_REPORT]);
    expect(calls.filter((c) => c.path === "/api/auth/refresh")).toHaveLength(1);
    expect(calls.filter((c) => c.path === "/api/forensics/url")).toHaveLength(6);
  });

  it("serializes refreshes across tabs with the Web Locks API", async () => {
    const lock = vi.fn((_name: string, callback: () => Promise<boolean>) => callback());
    Object.defineProperty(navigator, "locks", { value: { request: lock }, configurable: true });
    try {
      expiringServer();
      await api.me();
      await api.analyzeUrl("https://a.example");
    } finally {
      Reflect.deleteProperty(navigator, "locks");
    }
    expect(lock).toHaveBeenCalledTimes(1);
    expect(lock.mock.calls[0]?.[0]).toBe("kestrix-token-refresh");
  });

  it("retries only once: a second token_expired goes to sign-in", async () => {
    const handler = vi.fn();
    onSignInRequired(handler);
    const { calls } = fakeServer({
      "GET /api/auth/me": { body: SIGNED_IN },
      "POST /api/auth/refresh": { body: { access_expires_at: nowS() + 900 } },
      "POST /api/forensics/url": EXPIRED,
    });
    await api.me();
    const error = (await api.analyzeUrl("https://a.example").catch((e: unknown) => e)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.reason).toBe("token_expired");
    expect(calls.filter((c) => c.path === "/api/auth/refresh")).toHaveLength(1);
    expect(calls.filter((c) => c.path === "/api/forensics/url")).toHaveLength(2);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("goes to sign-in without retrying when the refresh is refused", async () => {
    const handler = vi.fn();
    onSignInRequired(handler);
    const { calls } = fakeServer({
      "GET /api/auth/me": { body: SIGNED_IN },
      "POST /api/auth/refresh": { status: 401, body: { reason: "sign_in_required", detail: "sign in again" } },
      "POST /api/forensics/url": EXPIRED,
    });
    await api.me();
    await expect(api.analyzeUrl("https://a.example")).rejects.toBeInstanceOf(ApiError);
    expect(calls.filter((c) => c.path === "/api/forensics/url")).toHaveLength(1);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("does not refresh for sign_in_required", async () => {
    const { calls } = fakeServer({
      "POST /api/forensics/url": { status: 401, body: { reason: "sign_in_required", detail: "sign in" } },
    });
    await api.analyzeUrl("https://a.example").catch(() => undefined);
    expect(calls.map((c) => c.path)).toEqual(["/api/forensics/url"]);
  });
});

describe("a page opened after the access token lapsed", () => {
  it("refreshes with the CSRF token from /api/auth/me, then reads who is signed in", async () => {
    let refreshed = false;
    const { calls } = fakeServer({
      "GET /api/auth/me": () => ({ body: refreshed ? SIGNED_IN : { signed_in: false, refreshable: true, csrf_token: "csrf-token-1" } }),
      "POST /api/auth/refresh": () => {
        refreshed = true;
        return { body: { access_expires_at: nowS() + 900 } };
      },
    });
    await expect(api.me()).resolves.toEqual(SIGNED_IN);
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /api/auth/me", "POST /api/auth/refresh", "GET /api/auth/me"]);
    expect(calls[1]?.headers.get("X-CSRF-Token")).toBe("csrf-token-1");
  });
});

describe("proactive refresh", () => {
  function timedServer() {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    return fakeServer({
      "GET /api/auth/me": () => ({ body: { ...SIGNED_IN, access_expires_at: nowS() + 900 } }),
      "POST /api/auth/refresh": () => ({ body: { access_expires_at: nowS() + 900 } }),
      "POST /api/auth/logout": { status: 204 },
    });
  }
  const refreshes = (calls: { path: string }[]) => calls.filter((c) => c.path === "/api/auth/refresh").length;

  it("refreshes about a minute before the access token expires, then again for the next one", async () => {
    const { calls } = timedServer();
    await api.me();
    await vi.advanceTimersByTimeAsync(900_000 - REFRESH_LEAD_MS - 1_000);
    expect(refreshes(calls)).toBe(0);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(refreshes(calls)).toBe(1);
    await vi.advanceTimersByTimeAsync(900_000 - REFRESH_LEAD_MS);
    expect(refreshes(calls)).toBe(2);
  });

  it("waits while the tab is hidden and refreshes when it is shown", async () => {
    const { calls } = timedServer();
    await api.me();
    visibility("hidden");
    await vi.advanceTimersByTimeAsync(900_000);
    expect(refreshes(calls)).toBe(0);
    visibility("visible");
    document.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(0);
    expect(refreshes(calls)).toBe(1);
  });

  it("never schedules closer than the minimum delay, even with a skewed clock", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const { calls } = fakeServer({ "GET /api/auth/me": { body: { ...SIGNED_IN, access_expires_at: nowS() - 3600 } } });
    await api.me();
    await vi.advanceTimersByTimeAsync(MIN_REFRESH_DELAY_MS - 1);
    expect(refreshes(calls)).toBe(0);
  });

  it("stops after sign-out", async () => {
    const { calls } = timedServer();
    await api.me();
    await api.logout();
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(refreshes(calls)).toBe(0);
  });
});
