// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MailReport, MailVerdict } from "../../lib/types";
import MailPage, { parseDomains } from "./MailPage";
import { verdictMeta } from "./MailReportView";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <MailPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function report(extra: Partial<MailReport> = {}): MailReport {
  return {
    generated_by: "Kestrix by Ruthvik Bandari",
    schema_version: 1,
    notice: "Offline heuristic analysis of one saved message.",
    sha256: "a".repeat(64),
    subject: "Invoice overdue",
    from_address: "billing@paypa1.com",
    verdict: "malicious",
    heuristic_score: 85,
    findings: [
      {
        id: "mail.lookalike.domain",
        analyzer: "lookalike",
        severity: "high",
        title: "From domain is a look-alike of paypal.com",
        explanation: "The name differs from paypal.com by a look-alike character.",
        evidence: "from domain paypa1.com vs protected domain paypal.com",
      },
      {
        id: "mail.intent.payment_change",
        analyzer: "intent",
        severity: "medium",
        title: "Asks for a payment or a change of bank details",
        explanation: "Confirm any new bank details by phone.",
        evidence: "bank details have changed",
      },
      {
        id: "mail.auth.spf_softfail",
        analyzer: "auth",
        severity: "low",
        title: "SPF soft-failed",
        explanation: "Forwarding often causes this.",
        evidence: "authserv-id mx.example.net: spf=softfail",
      },
    ],
    counts: { parts: 3, links: 2, attachments: 0, text_truncated: false, links_truncated: false },
    ...extra,
  };
}

function eml(): File {
  return new File(["From: a@example.com\r\nSubject: hi\r\n\r\nbody"], "message.eml", { type: "message/rfc822" });
}

function chooseFile(file = eml()) {
  fireEvent.change(screen.getByLabelText(/choose an \.eml file/i), { target: { files: [file] } });
}

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("email check page", () => {
  it("says the check stays on this computer, links the docs and explains how to save an .eml", () => {
    renderPage();
    expect(screen.getByRole("heading", { name: "Email check" })).toBeTruthy();
    expect(screen.getByText(/checked on this computer and never leaves it/i)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Read the docs" }).getAttribute("href")).toBe("/docs/mail");
    expect(screen.getByText("Download message")).toBeTruthy();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: /check message/i }).disabled).toBe(true);
  });

  it("uploads the file with protected domains and authserv-id, then shows the report", async () => {
    const fetchMock = vi.fn(() => Promise.resolve(Response.json(report())));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    chooseFile();
    expect(screen.getByText("message.eml")).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/protected domains/i), { target: { value: "PayPal.com, example-bank.com paypal.com" } });
    fireEvent.change(screen.getByLabelText(/trusted authserv-id/i), { target: { value: " mx.google.com " } });
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));

    expect(await screen.findByText(verdictMeta.malicious.title)).toBeTruthy();
    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe(
      "/api/mail/analyze?protected_domain=paypal.com&protected_domain=example-bank.com&trusted_authserv_id=mx.google.com",
    );
    expect(init.method).toBe("POST");
    expect((init.body as FormData).get("file")).toBeInstanceOf(File);

    expect(screen.getByText("Heuristic score, not a probability")).toBeTruthy();
    expect(screen.getByText("85")).toBeTruthy();
    const high = screen.getByRole("region", { name: /high/i });
    expect(within(high).getByText("From domain is a look-alike of paypal.com")).toBeTruthy();
    expect(within(high).getByText("from domain paypa1.com vs protected domain paypal.com")).toBeTruthy();
    expect(screen.getByRole("region", { name: /medium/i }).textContent).toContain("bank details have changed");
    expect(screen.getByRole("region", { name: /low/i }).textContent).toContain("SPF soft-failed");
    expect(screen.getByText("Raw JSON")).toBeTruthy();
  });

  it("sends no query string when no options are given", async () => {
    const fetchMock = vi.fn(() => Promise.resolve(Response.json(report({ verdict: "clean", findings: [] }))));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    expect(await screen.findByText(verdictMeta.clean.title)).toBeTruthy();
    expect(screen.getAllByText(/not that the message is safe/i).length).toBeGreaterThan(0);
    const [path] = fetchMock.mock.calls[0] as unknown as [string];
    expect(path).toBe("/api/mail/analyze");
  });

  it.each<MailVerdict>(["clean", "suspicious", "malicious", "insufficient_evidence"])(
    "labels the %s verdict in words, not color alone",
    async (verdict) => {
      vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(report({ verdict })))));
      renderPage();
      chooseFile();
      fireEvent.click(screen.getByRole("button", { name: /check message/i }));
      expect(await screen.findByText(verdictMeta[verdict].title)).toBeTruthy();
      expect(screen.getAllByText(verdictMeta[verdict].label).length).toBeGreaterThan(0);
    },
  );

  it("shows the server's {reason, detail} on an error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          Response.json({ reason: "invalid_input", detail: "input is not an email message" }, { status: 400 }),
        ),
      ),
    );
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("input is not an email message");
    expect(alert.textContent).toContain("reason: invalid_input");
  });

  it("refuses more than 20 protected domains without calling the server", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    chooseFile();
    const many = Array.from({ length: 21 }, (_, i) => `d${i.toString()}.example`).join(", ");
    fireEvent.change(screen.getByLabelText(/protected domains/i), { target: { value: many } });
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    expect((await screen.findByRole("alert")).textContent).toContain("Too many protected domains");
    await waitFor(() => {
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  it("refuses a message over the size limit before uploading", () => {
    renderPage();
    const big = eml();
    Object.defineProperty(big, "size", { value: 26 * 1024 * 1024 });
    chooseFile(big);
    expect(screen.getByRole("alert").textContent).toContain("too large");
    expect(screen.getByRole<HTMLButtonElement>("button", { name: /check message/i }).disabled).toBe(true);
  });
});

describe("parseDomains", () => {
  it("splits on commas and spaces, lower-cases and removes duplicates", () => {
    expect(parseDomains(" A.com,b.com  a.com,,\nc.com ")).toEqual(["a.com", "b.com", "c.com"]);
    expect(parseDomains("   ")).toEqual([]);
  });
});
