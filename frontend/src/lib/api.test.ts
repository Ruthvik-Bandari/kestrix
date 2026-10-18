import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, request } from "./api";

function respond(status: number, body: unknown, statusText = "") {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  vi.stubGlobal(
    "fetch",
    vi.fn(() =>
      Promise.resolve(
        new Response(status === 204 ? null : text, { status, statusText }),
      ),
    ),
  );
}

async function failure(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("expected the request to fail");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client error paths", () => {
  it("surfaces the server's {reason, detail}", async () => {
    respond(503, {
      reason: "ai_key_missing",
      detail: "no Anthropic API key is configured",
    });
    const error = await failure(api.guardian("is my address safe?"));
    expect(error.status).toBe(503);
    expect(error.reason).toBe("ai_key_missing");
    expect(error.detail).toBe("no Anthropic API key is configured");
  });

  it("flattens FastAPI validation errors into one readable detail", async () => {
    respond(422, {
      detail: [
        { loc: ["body", "url"], msg: "Field required", type: "missing" },
      ],
    });
    const error = await failure(api.webcheck("", false));
    expect(error.reason).toBe("invalid_request");
    expect(error.detail).toBe("url: Field required");
  });

  it("handles a non-JSON error body", async () => {
    respond(502, "<html>Bad gateway</html>", "Bad Gateway");
    const error = await failure(request("/api/health"));
    expect(error.reason).toBe("http_error");
    expect(error.detail).toContain("502");
  });

  it("reports a network failure as network_error with a hint", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))),
    );
    const error = await failure(api.health());
    expect(error.status).toBe(0);
    expect(error.reason).toBe("network_error");
    expect(error.detail).toMatch(/kestrix dashboard/);
  });

  it("maps a 413 from the body-size guard", async () => {
    respond(413, {
      reason: "input_too_large",
      detail: "request body exceeds 1048576 bytes",
    });
    const error = await failure(api.bitcoinScan(["bc1q"], false, "testnet4"));
    expect(error.status).toBe(413);
    expect(error.reason).toBe("input_too_large");
  });

  it("returns undefined for 204 No Content", async () => {
    respond(204, "");
    await expect(api.setAnthropicKey(null)).resolves.toBeUndefined();
  });

  it("sends JSON with the right method and content type", async () => {
    const fetchMock = vi.fn(() => Promise.resolve(Response.json({ ok: true })));
    vi.stubGlobal("fetch", fetchMock);
    await api.webcheck("https://example.com", true);
    const [path, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(path).toBe("/api/webcheck");
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("Content-Type")).toBe(
      "application/json",
    );
    expect(JSON.parse(init.body as string)).toEqual({
      url: "https://example.com",
      allow_private: true,
      site_type: null,
    });
  });
});
