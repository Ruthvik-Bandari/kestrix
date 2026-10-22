// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toolPageClient } from "../../test/fakeServer";
import type { MailReport, MailVerdict } from "../../lib/types";
import MailPage, { parseDomains } from "./MailPage";
import { verdictMeta } from "./MailReportView";

function renderPage() {
  const client = toolPageClient();
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
    expect(screen.getByRole("link", { name: "Read the docs" }).getAttribute("href")).toBe("/docs/tools/email");
    expect(screen.getByText("Download message")).toBeTruthy();
    expect(screen.getByText(/An \.eml file, up to 25 MB/)).toBeTruthy();
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

    expect(screen.getAllByText(/not a probability/i).length).toBeGreaterThan(0);
    expect(screen.getByText("85 / 100")).toBeTruthy();
    expect(screen.getByText("From domain is a look-alike of paypal.com")).toBeTruthy();
    expect(screen.getByText("from domain paypa1.com vs protected domain paypal.com")).toBeTruthy();
    expect(screen.getByText("Asks for a payment or a change of bank details")).toBeTruthy();
    expect(screen.getByText("SPF soft-failed")).toBeTruthy();
    expect(screen.getByText("Raw JSON")).toBeTruthy();
  });

  it("shows only the metadata the report has in a Message panel", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(report()))));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    await screen.findByRole("heading", { level: 2, name: "Malicious" });
    const panel = screen.getByRole("heading", { name: "Message" }).closest("aside") as HTMLElement;
    expect(within(panel).getByText("Invoice overdue")).toBeTruthy();
    expect(within(panel).getByText("billing@paypa1.com")).toBeTruthy();
    expect(within(panel).getByText("a".repeat(64))).toBeTruthy();
    expect(within(panel).getByText("3 MIME parts, 2 links, 0 attachments")).toBeTruthy();
    expect(within(panel).queryByText("Reply-To")).toBeNull();
    expect(within(panel).queryByText("Date")).toBeNull();
  });

  it("moves focus to the result heading when the result arrives", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(report()))));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    const heading = await screen.findByRole("heading", { level: 2, name: "Malicious" });
    await waitFor(() => {
      expect(document.activeElement).toBe(heading);
    });
  });

  it("filters findings by severity with truthful counts", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(report()))));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    await screen.findByRole("heading", { level: 2, name: "Malicious" });
    const filters = screen.getByRole("group", { name: /filter findings by severity/i });
    const all = within(filters).getByRole("button", { name: /^All\s*3$/ });
    const high = within(filters).getByRole("button", { name: /^High\s*1$/ });
    expect(within(filters).getByRole("button", { name: /^Medium\s*1$/ })).toBeTruthy();
    expect(within(filters).getByRole("button", { name: /^Low\s*1$/ })).toBeTruthy();
    expect(within(filters).queryByRole("button", { name: /^Info/ })).toBeNull();
    expect(all.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getAllByRole("listitem").filter((li) => li.querySelector(":scope > details")).length).toBe(3);

    fireEvent.click(high);
    expect(high.getAttribute("aria-pressed")).toBe("true");
    expect(all.getAttribute("aria-pressed")).toBe("false");
    expect(screen.getByText("From domain is a look-alike of paypal.com")).toBeTruthy();
    expect(screen.queryByText("SPF soft-failed")).toBeNull();
    expect(screen.getByText("Showing 1 of 3 findings")).toBeTruthy();

    fireEvent.click(all);
    expect(screen.getByText("SPF soft-failed")).toBeTruthy();
  });

  it("lists findings most severe first, each in a native disclosure", async () => {
    const unordered = report();
    unordered.findings = [...unordered.findings].reverse();
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(unordered))));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    await screen.findByRole("heading", { level: 2, name: "Malicious" });
    const titles = [...document.querySelectorAll("li > details > summary")].map((n) => n.textContent);
    expect(titles[0]).toContain("look-alike");
    expect(titles[1]).toContain("bank details");
    expect(titles[2]).toContain("SPF soft-failed");
  });

  it("renders a clean verdict as 'No checks fired', not as safe", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(report({ verdict: "clean", findings: [] })))));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    expect(await screen.findByRole("heading", { level: 2, name: "No checks fired" })).toBeTruthy();
    expect(screen.getAllByText(/not that the message is safe/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/No findings\. None of the checks fired/)).toBeTruthy();
    expect(screen.queryByText(/^Clean$/)).toBeNull();
  });

  it("explains a verdict that several low findings decided together", async () => {
    const reason = "Three low findings from two analyzers together: plain HTTP links, a generated host, an outdated mailer.";
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(report({ verdict: "suspicious", verdict_reason: reason })))));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    expect(await screen.findByText(reason)).toBeTruthy();
  });

  it("renders insufficient evidence as undecided, not as success", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(report({ verdict: "insufficient_evidence", findings: [] })))));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    expect(await screen.findByRole("heading", { level: 2, name: "Insufficient evidence" })).toBeTruthy();
    expect(screen.getByText(/this is not a clean result/i)).toBeTruthy();
    expect(screen.getByText(/no verdict either way/i)).toBeTruthy();
  });

  it("labels the suggested next step as advice", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(Response.json(report()))));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    const next = await screen.findByRole("region", { name: "Suggested next step" });
    expect(next.textContent).toContain("Nothing has been done for you");
    expect(next.textContent).toContain(verdictMeta.malicious.next);
  });

  it("keeps the chosen file and options after an error and retries with them", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ reason: "busy", detail: "try again shortly" }, { status: 503 }))
      .mockResolvedValueOnce(Response.json(report()));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    chooseFile();
    fireEvent.change(screen.getByLabelText(/protected domains/i), { target: { value: "example.com" } });
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("try again shortly");
    await waitFor(() => {
      expect(document.activeElement?.contains(alert)).toBe(true);
    });
    expect(screen.getByText("message.eml")).toBeTruthy();
    expect(screen.getByRole<HTMLInputElement>("textbox", { name: /protected domains/i }).value).toBe("example.com");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { level: 2, name: "Malicious" })).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, second] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect((second.body as FormData).get("file")).toBeInstanceOf(File);
  });

  it("refuses an Outlook .msg file without calling the server", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    chooseFile(new File(["x"], "invoice.msg", { type: "application/vnd.ms-outlook" }));
    expect(screen.getByRole("alert").textContent).toContain("Outlook .msg files can't be checked");
    expect(screen.getByRole<HTMLButtonElement>("button", { name: /check message/i }).disabled).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("describes the pending task while the check runs", async () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => undefined)));
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    expect((await screen.findAllByRole("status")).some((n) => /links are not visited/i.test(n.textContent))).toBe(true);
  });

  it("sends no query string when no options are given", async () => {
    const fetchMock = vi.fn(() => Promise.resolve(Response.json(report({ verdict: "clean", findings: [] }))));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: /check message/i }));
    expect(await screen.findByRole("heading", { level: 2, name: verdictMeta.clean.label })).toBeTruthy();
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
      expect(screen.getByRole("heading", { level: 2, name: verdictMeta[verdict].label })).toBeTruthy();
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
