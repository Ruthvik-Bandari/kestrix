import type {
  CaseManifest,
  DetectReport,
  EngineStatus,
  FileReport,
  GuardianResult,
  Health,
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

  constructor(status: number, reason: string, detail: string) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.reason = reason;
    this.detail = detail;
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
      return new ApiError(response.status, body.reason, detail);
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

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (typeof init.body === "string") headers.set("Content-Type", "application/json");
  let response: Response;
  try {
    response = await fetch(path, { ...init, headers });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(
      0,
      "network_error",
      "Could not reach the Kestrix server. Check that `kestrix dashboard` is still running.",
    );
  }
  if (!response.ok) throw await toError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const post = <T>(path: string, body: unknown): Promise<T> =>
  request<T>(path, { method: "POST", body: JSON.stringify(body) });

export const api = {
  health: () => request<Health>("/api/health"),
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

  analyzeFile: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<FileReport>("/api/forensics/file", { method: "POST", body: form });
  },
  analyzeUrl: (url: string) => post<UrlReport>("/api/forensics/url", { url }),

  bitcoinScan: (addresses: string[], lookupChain: boolean, testnet: PublicTestnet) =>
    post<ScanResult>("/api/bitcoin/scan", { addresses, lookup_chain: lookupChain, testnet }),
  migration: (addressType: string) =>
    request<MigrationPlan>(`/api/bitcoin/migration/${encodeURIComponent(addressType)}`),
  guardian: (message: string) => post<GuardianResult>("/api/bitcoin/guardian", { message }),
};
