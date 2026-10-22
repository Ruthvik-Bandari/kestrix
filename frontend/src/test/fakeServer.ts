// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient } from "@tanstack/react-query";
import { vi } from "vitest";
import { keys } from "../lib/queries";
import type { HistoryPage } from "../lib/types";

export interface Call {
  method: string;
  path: string;
  headers: Headers;
  body: unknown;
}

type Reply = { status?: number; body?: unknown; headers?: Record<string, string> };
type Route = (call: Call) => Reply | undefined;

/** A fake `fetch`: each route answers by "METHOD /path" (query string ignored); every call is recorded. */
export function fakeServer(routes: Record<string, Reply | Route>) {
  const calls: Call[] = [];
  const fetchMock = vi.fn((input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(input instanceof Request ? input.url : input.toString(), "https://kestrix.test");
    const method = (init.method ?? "GET").toUpperCase();
    const call: Call = {
      method,
      path: url.pathname + url.search,
      headers: new Headers(init.headers),
      body: typeof init.body === "string" ? JSON.parse(init.body) : init.body,
    };
    calls.push(call);
    const route = routes[`${method} ${url.pathname}`];
    const reply = (typeof route === "function" ? route(call) : route) ?? { status: 404, body: { reason: "not_found", detail: url.pathname } };
    const status = reply.status ?? 200;
    return Promise.resolve(
      new Response(status === 204 ? null : JSON.stringify(reply.body ?? {}), { status, headers: reply.headers ?? {} }),
    );
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

export const HOSTED_HEALTH = {
  status: "ok",
  version: "0.1.0",
  mode: "hosted",
  modules: ["forensics", "webcheck", "mail"],
};

export const SIGNED_IN = {
  signed_in: true,
  user: { display_name: "Ada Lovelace", email: "ada@mail.example", provider: "google" },
  csrf_token: "csrf-token-1",
  access_expires_at: Math.floor(Date.now() / 1000) + 900,
};

/**
 * A query client for the tool-page tests with the saved-results query already answered ("history is
 * off"), so the header's history strip makes no request and a test sees only the calls it cares about.
 * Pass `history` to show saved reports in that strip.
 */
export function toolPageClient(history: HistoryPage = { enabled: false, retention_days: 30, page: 1, per_page: 20, total: 0, items: [] }): QueryClient {
  const client = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false }, mutations: { retry: false } } });
  client.setQueryData(keys.historyPage(1), history);
  return client;
}
