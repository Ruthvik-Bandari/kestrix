// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { isHosted } from "./mode";
import type {
  CaseManifest,
  DetectReport,
  EngineStatus,
  FileReport,
  GuardianResult,
  Health,
  MailOptions,
  Me,
  Providers,
  MailReport,
  MigrationPlan,
  ParsedRule,
  PublicTestnet,
  RunBody,
  ScanResult,
  Settings,
  SiteKind,
  UrlReport,
  WebReport,
} from "./types";

/** Every failed request becomes an ApiError carrying the server's `{reason, detail}`. */
export class ApiError extends Error {
  readonly status: number;
  readonly reason: string;
  readonly detail: string;
  /** Seconds from a 429's `Retry-After` header, when the server sent one. */
  readonly retryAfter: number | null;

  constructor(status: number, reason: string, detail: string, retryAfter: number | null = null) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.reason = reason;
    this.detail = detail;
    this.retryAfter = retryAfter;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** FastAPI request-validation errors arrive as `{detail: [{loc, msg}]}`. */
function validationDetail(items: unknown[]): string {
  const messages = items.flatMap((item) => {
    if (!isRecord(item) || typeof item.msg !== "string") return [];
    const loc = Array.isArray(item.loc) ? item.loc.filter((p) => p !== "body").join(".") : "";
    return [loc ? `${loc}: ${item.msg}` : item.msg];
  });
  return messages.join("; ") || "The request was not valid.";
}

function retryAfter(response: Response): number | null {
  const value = response.headers.get("Retry-After");
  return value && /^\d+$/.test(value) ? Number(value) : null;
}

async function toError(response: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // Non-JSON error page; fall through to the generic message.
  }
  if (isRecord(body)) {
    if (typeof body.reason === "string") {
      const detail = typeof body.detail === "string" ? body.detail : body.reason;
      return new ApiError(response.status, body.reason, detail, retryAfter(response));
    }
    if (Array.isArray(body.detail)) {
      return new ApiError(response.status, "invalid_request", validationDetail(body.detail));
    }
    if (typeof body.detail === "string") {
      return new ApiError(response.status, "http_error", body.detail);
    }
  }
  return new ApiError(response.status, "http_error", `The server answered ${response.status} ${response.statusText}`.trim());
}

/*
 * Hosted mode only (ADR 0004): the session's CSRF token, from GET /api/auth/me, goes out as
 * `X-CSRF-Token` on every state-changing request. A local server never hands one out, so local
 * requests carry no such header.
 */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
let csrfToken: string | null = null;
let signInRequired: (() => void) | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

/** Called when the hosted server answers 401 `sign_in_required` (main.tsx sends the user to /signin). */
export function onSignInRequired(handler: (() => void) | null): void {
  signInRequired = handler;
}

async function send(path: string, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (typeof init.body === "string") headers.set("Content-Type", "application/json");
  const method = (init.method ?? "GET").toUpperCase();
  if (isHosted() && csrfToken && !SAFE_METHODS.has(method)) headers.set("X-CSRF-Token", csrfToken);
  try {
    return await fetch(path, { ...init, headers });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(
      0,
      "network_error",
      isHosted()
        ? "Could not reach Kestrix. Check your connection and try again."
        : "Could not reach the Kestrix server. Check that `kestrix dashboard` is still running.",
    );
  }
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response = await send(path, init);
  if (!response.ok && isHosted() && response.status === 403) {
    const error = await toError(response);
    if (error.reason !== "csrf_failed") throw error;
    // The token went stale (signed in again in another tab, say): fetch a fresh one and retry once.
    await api.me().catch(() => undefined);
    response = await send(path, init);
  }
  if (!response.ok) {
    const error = await toError(response);
    if (error.status === 401 && error.reason === "sign_in_required") signInRequired?.();
    throw error;
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const post = <T>(path: string, body: unknown): Promise<T> =>
  request<T>(path, { method: "POST", body: JSON.stringify(body) });

export const api = {
  health: () => request<Health>("/api/health"),

  providers: () => request<Providers>("/api/auth/providers"),
  me: async () => {
    const me = await request<Me>("/api/auth/me");
    setCsrfToken(me.signed_in ? me.csrf_token : null);
    return me;
  },
  logout: async () => {
    await request<undefined>("/api/auth/logout", { method: "POST" });
    setCsrfToken(null);
  },
  deleteAccount: async () => {
    await request<undefined>("/api/auth/account", { method: "DELETE" });
    setCsrfToken(null);
  },

  settings: () => request<Settings>("/api/settings"),
  setAnthropicKey: (key: string | null) =>
    request<undefined>("/api/settings/anthropic-key", { method: "PUT", body: JSON.stringify({ key }) }),

  engine: () => request<EngineStatus>("/api/detect/engine"),
  cases: () => request<CaseManifest[]>("/api/detect/cases"),
  runCase: (id: string) => post<DetectReport>(`/api/detect/cases/${encodeURIComponent(id)}/run`, {}),
  parseRule: (rule: string) => post<ParsedRule>("/api/detect/parse", { rule }),
  runRule: (body: RunBody) => post<DetectReport>("/api/detect/run", body),

  webcheck: (url: string, allowPrivate: boolean, siteType: SiteKind | null = null) =>
    post<WebReport>("/api/webcheck", { url, allow_private: allowPrivate, site_type: siteType }),
  /** The hosted service's body: public targets only, with the user's authorization confirmation. */
  webcheckHosted: (url: string, siteType: SiteKind | null = null) =>
    post<WebReport>("/api/webcheck", { url, site_type: siteType, authorized: true }),

  analyzeFile: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<FileReport>("/api/forensics/file", { method: "POST", body: form });
  },
  analyzeUrl: (url: string) => post<UrlReport>("/api/forensics/url", { url }),

  analyzeMail: (file: File, options: MailOptions) => {
    const form = new FormData();
    form.append("file", file);
    const params = new URLSearchParams();
    for (const domain of options.protectedDomains) params.append("protected_domain", domain);
    if (options.trustedAuthservId) params.append("trusted_authserv_id", options.trustedAuthservId);
    const query = params.toString();
    return request<MailReport>(`/api/mail/analyze${query ? `?${query}` : ""}`, { method: "POST", body: form });
  },

  bitcoinScan: (addresses: string[], lookupChain: boolean, testnet: PublicTestnet) =>
    post<ScanResult>("/api/bitcoin/scan", { addresses, lookup_chain: lookupChain, testnet }),
  migration: (addressType: string) =>
    request<MigrationPlan>(`/api/bitcoin/migration/${encodeURIComponent(addressType)}`),
  guardian: (message: string) => post<GuardianResult>("/api/bitcoin/guardian", { message }),
};
