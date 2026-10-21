// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setMode } from "../../lib/mode";
import type { WebReport } from "../../lib/types";
import WebcheckPage, { HOSTED_NOTICE_PAGE, HOSTED_NOTICE_SITE, NOTICE_PAGE, NOTICE_SITE } from "./WebcheckPage";

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <WebcheckPage />
      </MemoryRouter>
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
      name: /^scan/i,
    });
    expect(screen.getByText(NOTICE_SITE)).toBeTruthy();

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
      screen.getByRole<HTMLButtonElement>("button", { name: /^scan/i }).disabled,
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
    fireEvent.click(screen.getByRole("button", { name: /^scan/i }));
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
      scope: "site",
    });
  });
});

describe("site profile", () => {
  it("sends a declared site type and shows the profile and weighed findings", async () => {
    const report = {
      notice: NOTICE_SITE,
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
      scope: "site",
      profile: {
        kind: "static",
        detected: "static",
        declared: null,
        reasons: ["None of the 3 pages checked has a form, a cookie or an API call"],
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
    fireEvent.click(screen.getByRole("button", { name: /^scan/i }));
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

describe("web check on the hosted service", () => {
  it("requires the authorization checkbox, hides private targets and sends authorized: true", async () => {
    setMode("hosted");
    const bodies: string[] = [];
    const fetchMock = vi.fn((_: RequestInfo | URL, init?: RequestInit) => {
      if (typeof init?.body === "string") bodies.push(init.body);
      return Promise.resolve(
        new Response(JSON.stringify({ reason: "rate_limited", detail: "too many requests; try again in 1200 seconds" }), {
          status: 429,
          headers: { "Retry-After": "1200" },
        }),
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(screen.getByText(HOSTED_NOTICE_SITE)).toBeTruthy();
    expect(screen.queryByRole("checkbox", { name: /private and local/i })).toBeNull();
    const scan = screen.getByRole<HTMLButtonElement>("button", { name: /^scan/i });
    fireEvent.change(screen.getByLabelText(/website address/i), { target: { value: "example.com" } });
    expect(scan.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /^I own this website or am authorized to test it/ }));
    fireEvent.click(scan);
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
    const body: unknown = JSON.parse(bodies[0] ?? "null");
    expect(body).toEqual({ url: "https://example.com", site_type: null, scope: "site", authorized: true });
    // A 429 shows the server's detail and when to retry.
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Too many requests for now");
    expect(alert.textContent).toContain("too many requests; try again in 1200 seconds");
    expect(alert.textContent).toContain("You can try again in about 20 minutes.");
  });
});

function webReport(extra: Partial<WebReport> = {}): WebReport {
  return {
    notice: NOTICE_PAGE,
    requested_url: "https://site.test/",
    final_url: "https://site.test/",
    status_code: 200,
    headers_checked: true,
    redirect_chain: [],
    tls: { host: "site.test", status: "ok", detail: null, protocol: "TLSv1.3", issuer: null, not_after: null, days_remaining: null },
    grade: "C",
    score: 72,
    findings: [
      { id: "csp.missing", severity: "low", baseline_severity: "low", title: "Content-Security-Policy missing", explanation: "No CSP.", recommendation: "Add a CSP header.", evidence: null, context: null },
      { id: "hsts.missing", severity: "high", baseline_severity: "high", title: "HSTS missing", explanation: "No HSTS.", recommendation: "Send Strict-Transport-Security.", evidence: "no header", context: null },
    ],
    timings: { total_ms: 1, http_ms: 1, tls_ms: 0 },
    profile: null,
    ...extra,
  };
}

function scanSite(target = "site.test") {
  fireEvent.change(screen.getByLabelText(/website address/i), { target: { value: target } });
  fireEvent.click(screen.getByRole("checkbox", { name: /i own this site or am authorized/i }));
  fireEvent.click(screen.getByRole("button", { name: /^scan/i }));
}

describe("web check result", () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn();
    vi.stubGlobal("matchMedia", () => ({ matches: false }));
  });

  it("opens with the grade, lists failed checks first with fixes, and filters them", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(webReport()))));
    renderPage();
    scanSite();
    const heading = await screen.findByRole("heading", { level: 2, name: "Grade C" });
    await waitFor(() => {
      expect(document.activeElement).toBe(heading);
    });
    const titles = [...document.querySelectorAll("li > details > summary")].map((n) => n.textContent);
    expect(titles[0]).toContain("HSTS missing");
    expect(titles[1]).toContain("Content-Security-Policy missing");
    expect(screen.getByText("Send Strict-Transport-Security.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /^Low\s*1$/ }));
    expect(screen.queryByText("HSTS missing")).toBeNull();
    expect(screen.getByRole("button", { name: /^Low\s*1$/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("says when the analysis was partial", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(webReport({ headers_checked: false, findings: [] })))));
    renderPage();
    scanSite();
    expect(await screen.findByText("Partial analysis")).toBeTruthy();
    expect(screen.getByText(/headers were not checked/i)).toBeTruthy();
  });

  it("keeps the address and authorization after a failed connection and retries", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ reason: "target_unreachable", detail: "connection refused" }, { status: 502 }))
      .mockResolvedValueOnce(Response.json(webReport()));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    scanSite("down.test");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Couldn't reach that address");
    expect(screen.getByRole<HTMLInputElement>("textbox", { name: /website address/i }).value).toBe("down.test");
    expect(screen.getByRole<HTMLInputElement>("checkbox", { name: /i own this site/i }).checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { level: 2, name: "Grade C" })).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("keeps the authorization checkbox and notice visible, with optional settings collapsed", () => {
    renderPage();
    expect(screen.getByText(NOTICE_SITE)).toBeTruthy();
    const details = screen.getByText("Optional settings").closest("details");
    expect(details?.open).toBe(false);
    expect(details?.contains(screen.getByRole("checkbox", { name: /i own this site/i }))).toBe(false);
  });
});


describe("whole-site scope", () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn();
    vi.stubGlobal("matchMedia", () => ({ matches: false }));
  });

  it("defaults to the whole site, shows the notice for the chosen scope and sends it", async () => {
    const fetchMock = vi.fn(() => new Promise<Response>(() => undefined));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(screen.getByRole<HTMLInputElement>("radio", { name: /whole site \(up to 50 pages\)/i }).checked).toBe(true);
    expect(screen.getByText(NOTICE_SITE)).toBeTruthy();
    expect(NOTICE_SITE).toContain("up to 50 read-only GET requests");
    fireEvent.click(screen.getByRole("radio", { name: /just this page/i }));
    expect(screen.getByText(NOTICE_PAGE)).toBeTruthy();
    expect(screen.queryByText(NOTICE_SITE)).toBeNull();
    scanSite("site.test");
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect((JSON.parse(init.body as string) as { scope: string }).scope).toBe("page");
  });

  it("keeps the hosted wording for each scope", () => {
    setMode("hosted");
    renderPage();
    expect(screen.getByText(HOSTED_NOTICE_SITE).textContent).toContain("Kestrix's server, not your computer");
    fireEvent.click(screen.getByRole("radio", { name: /just this page/i }));
    expect(screen.getByText(HOSTED_NOTICE_PAGE).textContent).toContain("Kestrix's server, not your computer");
  });

  it("shows an indeterminate state naming the host while pages are checked", async () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => undefined)));
    renderPage();
    scanSite("https://portfolio.test/");
    expect((await screen.findAllByText("Checking up to 50 pages on portfolio.test…")).length).toBeGreaterThan(0);
    expect(document.querySelector("[role=progressbar]")).toBeNull(); // no invented percentage
  });

  const siteReport = (): WebReport =>
    webReport({
      scope: "site",
      requests_sent: 9,
      links_skipped: 3,
      limits_reached: ["page_cap"],
      pages: [
        { path: "/", found_via: "start", outcome: "checked", status_code: 200, kind: "static", finding_ids: ["csp.missing"], detail: null },
        { path: "/blog", found_via: "sitemap", outcome: "checked", status_code: 200, kind: "static", finding_ids: [], detail: null },
        { path: "/admin/login", found_via: "probe", outcome: "checked", status_code: 200, kind: "dynamic", finding_ids: [], detail: null },
        { path: "/login", found_via: "probe", outcome: "http_error", status_code: 404, kind: null, finding_ids: [], detail: null },
        { path: "/go", found_via: "link", outcome: "redirects_off_site", status_code: 302, kind: null, finding_ids: [], detail: "redirects to other.example (not followed)" },
      ],
      profile: {
        kind: "dynamic",
        detected: "dynamic",
        declared: null,
        decided_by: "/admin/login",
        reasons: ["/admin/login has a password field"],
        evidence: { html: true, forms: 1, post_forms: 1, password_fields: 1, input_fields: 2, cookies: 0, scripts_inline: 0, scripts_external: 0, third_party_script_hosts: [], iframes: 0, api_markers: 0 },
      },
      findings: [
        { id: "csp.missing", severity: "medium", title: "Content-Security-Policy missing", explanation: "No CSP.", recommendation: "Add a CSP header.", evidence: null, context: null, pages: ["/", "/blog", "/admin/login"], pages_total: 25 },
      ],
    });

  it("lists the pages checked, what failed and which limit was hit", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(siteReport()))));
    renderPage();
    scanSite();
    expect(await screen.findByRole("heading", { name: "Pages checked" })).toBeTruthy();
    const rows = [...document.querySelectorAll("section[aria-labelledby=pages-title] tbody tr")].map((r) => r.textContent);
    expect(rows).toHaveLength(5);
    expect(rows[2]).toContain("/admin/login");
    expect(rows[2]).toContain("Login address tried");
    expect(rows[3]).toContain("404");
    expect(rows[4]).toContain("Redirects off-site, not followed");
    expect(rows[4]).toContain("redirects to other.example (not followed)");
    expect(screen.getByText(/3 pages checked of 5 pages requested · 9 requests sent/)).toBeTruthy();
    expect(screen.getByText(/Stopped at the 50-page limit/)).toBeTruthy();
    expect(screen.getByText(/3 links not followed/)).toBeTruthy();
    // The profile names the page that made the site dynamic.
    expect(screen.getByText("/admin/login", { selector: "span.font-mono" })).toBeTruthy();
    expect(screen.getByText("/admin/login has a password field.")).toBeTruthy();
  });

  it("shows how many pages each finding was seen on, with the paths in a disclosure", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(siteReport()))));
    renderPage();
    scanSite();
    const summary = await screen.findByText("On 25 pages");
    const details = summary.closest("details") as HTMLDetailsElement;
    expect(details.open).toBe(false);
    expect([...details.querySelectorAll("li")].map((li) => li.textContent)).toEqual(["/", "/blog", "/admin/login", "and 22 more"]);
  });

  it("renders a report saved before whole-site scans, as a single page", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(webReport()))));
    renderPage();
    scanSite();
    expect(await screen.findByRole("heading", { level: 2, name: "Grade C" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Pages checked" })).toBeNull();
    expect(screen.queryByText(/On \d+ pages?/)).toBeNull();
    expect(screen.getByText(/Only this page was checked/)).toBeTruthy();
  });
});
