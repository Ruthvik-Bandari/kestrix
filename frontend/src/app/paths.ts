// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { isHosted } from "../lib/mode";

/*
 * Every app path, for both modes. Locally the dashboard is at "/" and the landing page at
 * "/welcome"; on the hosted service (ADR 0004) the landing page is "/" and the dashboard
 * moves under "/app". The router, sidebar, landing and page links all ask here.
 */

export const SIGNIN_PATH = "/signin";
export const PRIVACY_PATH = "/privacy";
export const TERMS_PATH = "/terms";

/** Dashboard pages the hosted service does not serve (their APIs answer 404 there). */
export const LOCAL_ONLY_PAGES = ["detect", "bitcoin", "settings"] as const;

/**
 * Where the public landing page lives. In hosted mode this becomes "/" and the dashboard
 * moves; change it here and the router, sidebar link and landing links follow.
 */
export function landingPath(): string {
  return isHosted() ? "/" : "/welcome";
}

/** The dashboard home (overview). */
function dashboardBase(): string {
  return isHosted() ? "/app" : "";
}

/** A dashboard page path such as "mail", wherever the dashboard is mounted. */
export function dashboardPath(page = ""): string {
  const tail = page.replace(/^\/+/, "");
  if (!tail) return dashboardBase() || "/";
  return `${dashboardBase()}/${tail}`;
}

/** Whether a dashboard page (its first path segment, such as "bitcoin") is served in this mode. */
export function pageAvailable(page: string): boolean {
  const first = page.replace(/^\/+/, "").split(/[/?#]/, 1)[0] ?? "";
  return !isHosted() || !(LOCAL_ONLY_PAGES as readonly string[]).includes(first);
}

const MAX_NEXT = 512;

/**
 * A same-origin path to return to after sign-in, or null. Mirrors `safe_next` in
 * server/auth.py, which re-checks it: no "//host", backslashes, whitespace or control characters.
 */
export function safeNext(value: string | null | undefined): string | null {
  if (!value || value.length > MAX_NEXT || !value.startsWith("/") || value.startsWith("//")) return null;
  if (value.includes("\\")) return null;
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    if (code <= 32 || code === 127) return null;
  }
  return value;
}

/** The sign-in page, remembering where to return. */
export function signInPath(next?: string | null): string {
  const target = safeNext(next);
  return target ? `${SIGNIN_PATH}?next=${encodeURIComponent(target)}` : SIGNIN_PATH;
}
