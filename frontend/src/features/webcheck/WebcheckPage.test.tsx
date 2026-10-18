// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import WebcheckPage, { NOTICE } from "./WebcheckPage";

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <WebcheckPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("web check authorization gate", () => {
  it("keeps Scan disabled until the user confirms authorization", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    const scan = screen.getByRole<HTMLButtonElement>("button", {
      name: /scan/i,
    });
    expect(screen.getByText(NOTICE)).toBeTruthy();

    fireEvent.change(screen.getByLabelText(/website address/i), {
      target: { value: "example.com" },
    });
    expect(scan.disabled).toBe(true);

    fireEvent.submit(scan.closest("form") as HTMLFormElement);
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /i own this site or am authorized/i,
      }),
    );
    expect(scan.disabled).toBe(false);
  });

  it("stays disabled with authorization but no URL", () => {
    renderPage();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /i own this site or am authorized/i,
      }),
    );
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: /scan/i }).disabled,
    ).toBe(true);
  });

  it("sends the URL (with https:// added) once authorized", async () => {
    const fetchMock = vi.fn(() => new Promise<Response>(() => undefined));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    fireEvent.change(screen.getByLabelText(/website address/i), {
      target: { value: "example.com" },
    });
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /i own this site or am authorized/i,
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: /scan/i }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
    const [, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(JSON.parse(init.body as string)).toEqual({
      url: "https://example.com",
      allow_private: false,
      site_type: null,
    });
  });
});

describe("site profile", () => {
  it("sends a declared site type and shows the profile and weighed findings", async () => {
    const report = {
      notice: NOTICE,
      requested_url: "https://site.test/",
      final_url: "https://site.test/",
      status_code: 200,
      headers_checked: true,
      redirect_chain: [],
      tls: {
        host: "site.test",
        status: "ok",
        detail: null,
        protocol: "TLSv1.3",
        issuer: null,
        not_after: null,
        days_remaining: null,
      },
      grade: "A",
      score: 96,
      findings: [
        {
          id: "csp.missing",
          severity: "low",
          baseline_severity: "medium",
          title: "Content-Security-Policy missing",
          explanation: "x",
          recommendation: "y",
          evidence: null,
          context:
            "Medium on sites with logins or sessions; low here, a static site (no forms).",
        },
      ],
      timings: { total_ms: 1, http_ms: 1, tls_ms: 0 },
      profile: {
        kind: "static",
        detected: "static",
        declared: null,
        reasons: ["no forms, cookies or API calls on this page"],
        evidence: {
          html: true,
          forms: 0,
          post_forms: 0,
          password_fields: 0,
          input_fields: 0,
          cookies: 0,
          scripts_inline: 1,
          scripts_external: 2,
          third_party_script_hosts: [],
          iframes: 0,
          api_markers: 0,
        },
      },
    };
    const fetchMock = vi.fn(() =>
      Promise.resolve(new Response(JSON.stringify(report), { status: 200 })),
    );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("matchMedia", () => ({ matches: true }));
    Element.prototype.scrollIntoView = vi.fn();
    renderPage();
    fireEvent.change(screen.getByLabelText(/website address/i), {
      target: { value: "site.test" },
    });
    fireEvent.change(screen.getByLabelText(/what is this site/i), {
      target: { value: "dynamic" },
    });
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /i own this site or am authorized/i,
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: /scan/i }));
    expect(await screen.findByText("Static site")).toBeTruthy();
    expect(
      screen.getByText(/Weighed for this site/).parentElement?.textContent,
    ).toMatch(/low here, a static site/);
    const [, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    const body = JSON.parse(init.body as string) as {
      site_type: string | null;
    };
    expect(body.site_type).toBe("dynamic");
  });
});
