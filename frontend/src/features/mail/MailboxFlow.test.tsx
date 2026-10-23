// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setMode } from "../../lib/mode";
import type { MailReport, MailboxStatus } from "../../lib/types";
import { fakeServer, toolPageClient } from "../../test/fakeServer";
import MailConnectPage from "./MailConnectPage";
import MailPage from "./MailPage";

const STATUS: MailboxStatus = {
  notice: "Connecting contacts Google or Microsoft.",
  providers: [
    {
      provider: "gmail",
      label: "Gmail",
      configured: true,
      connected: true,
      account: "ada@gmail.example",
      scope: "https://www.googleapis.com/auth/gmail.readonly",
      hosts: ["accounts.google.com"],
      register_redirect_uri: null,
    },
    {
      provider: "outlook",
      label: "Outlook / Microsoft 365",
      configured: false,
      connected: false,
      account: null,
      scope: "https://graph.microsoft.com/Mail.Read",
      hosts: ["graph.microsoft.com"],
      register_redirect_uri: "http://localhost/mail/connect",
    },
  ],
};

const REPORT: MailReport = {
  generated_by: "Kestrix by Ruthvik Bandari",
  schema_version: 1,
  notice: "Offline heuristic analysis of one saved message.",
  sha256: "b".repeat(64),
  subject: "Invoice overdue",
  from_address: "billing@paypa1.com",
  verdict: "suspicious",
  heuristic_score: 15,
  findings: [
    {
      id: "mail.sender.reply_to_mismatch",
      analyzer: "sender",
      severity: "medium",
      title: "Replies go to a different domain than the sender",
      explanation: "A reply would not reach the sender.",
      evidence: "From domain example.com; Reply-To domain other.example",
    },
  ],
  counts: { parts: 1, links: 0, attachments: 0, text_truncated: false, links_truncated: false },
};

function renderAt(url: string) {
  return render(
    <QueryClientProvider client={toolPageClient()}>
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route path="/mail" element={<MailPage />} />
          <Route path="/mail/connect" element={<MailConnectPage />} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function Where() {
  const location = useLocation();
  return <p data-testid="where">{location.pathname + location.search}</p>;
}

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  vi.unstubAllGlobals();
  setMode("local");
  window.history.replaceState(null, "", "/");
});

describe("email page with the mailbox connector (local mode)", () => {
  it("offers the mailbox tab next to file upload, and lists the file tab first", async () => {
    fakeServer({ "GET /api/mail/mailbox/status": { body: STATUS } });
    renderAt("/mail");
    const tabs = screen.getByRole("tablist", { name: /where the message comes from/i });
    expect(within(tabs).getAllByRole("tab").map((t) => t.textContent)).toEqual(["Upload a file", "Check from your mailbox"]);
    expect(screen.getByLabelText(/choose an \.eml file/i)).toBeTruthy();
    fireEvent.click(within(tabs).getByRole("tab", { name: /check from your mailbox/i }));
    expect(await screen.findByText(/connected as ada@gmail\.example/i)).toBeTruthy();
    fireEvent.click(within(tabs).getByRole("tab", { name: /upload a file/i }));
    expect(screen.getByLabelText(/choose an \.eml file/i)).toBeTruthy();
  });

  it("opens the mailbox tab when the address says so (after sign-in)", async () => {
    fakeServer({ "GET /api/mail/mailbox/status": { body: STATUS } });
    renderAt("/mail?mailbox=gmail");
    expect(await screen.findByText(/connected as ada@gmail\.example/i)).toBeTruthy();
    expect(screen.getByRole("tab", { name: /check from your mailbox/i }).getAttribute("aria-selected")).toBe("true");
  });

  it("opens the provider named in the address", async () => {
    fakeServer({ "GET /api/mail/mailbox/status": { body: STATUS } });
    renderAt("/mail?mailbox=outlook");
    expect(await screen.findByLabelText(/application \(client\) id/i)).toBeTruthy();
    expect(screen.getByRole<HTMLInputElement>("radio", { name: /outlook/i }).checked).toBe(true);
  });

  it("picks a message, checks it with the shared options and shows the usual report", async () => {
    const { calls } = fakeServer({
      "GET /api/mail/mailbox/status": { body: STATUS },
      "POST /api/mail/mailbox/gmail/search": {
        body: { messages: [{ id: "m1", sender: "Alice", subject: "Invoice overdue", date: null, snippet: "pay" }], next_page_token: null },
      },
      "POST /api/mail/mailbox/gmail/check": { body: REPORT },
    });
    renderAt("/mail?mailbox=gmail");
    fireEvent.click(await screen.findByRole("button", { name: /show messages/i }));
    fireEvent.change(screen.getByLabelText(/protected domains/i), { target: { value: "PayPal.com" } });
    fireEvent.click(await screen.findByRole("button", { name: "Check message: Invoice overdue" }));
    expect(await screen.findByRole("heading", { level: 2, name: /suspicious/i })).toBeTruthy();
    expect(screen.getByText("Replies go to a different domain than the sender")).toBeTruthy();
    const check = calls.find((c) => c.path === "/api/mail/mailbox/gmail/check");
    expect(check?.body).toEqual({ message_id: "m1", protected_domains: ["paypal.com"], trusted_authserv_id: null });
  });

  it("shows a check that failed, with a retry that asks for the same message again", async () => {
    let n = 0;
    const { calls } = fakeServer({
      "GET /api/mail/mailbox/status": { body: STATUS },
      "POST /api/mail/mailbox/gmail/search": {
        body: { messages: [{ id: "m1", sender: "Alice", subject: "Big one", date: null, snippet: "" }], next_page_token: null },
      },
      "POST /api/mail/mailbox/gmail/check": () => {
        n += 1;
        return n === 1
          ? { status: 413, body: { reason: "input_too_large", detail: "the message is larger than the 26,214,400 byte limit" } }
          : { body: REPORT };
      },
    });
    renderAt("/mail?mailbox=gmail");
    fireEvent.click(await screen.findByRole("button", { name: /show messages/i }));
    fireEvent.click(await screen.findByRole("button", { name: "Check message: Big one" }));
    const alert = await screen.findByText(/larger than the 26,214,400 byte limit/);
    expect(alert).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(await screen.findByRole("heading", { level: 2, name: /suspicious/i })).toBeTruthy();
    expect(calls.filter((c) => c.path.endsWith("/check"))).toHaveLength(2);
  });

  it("completes the sign-in: removes the code from the address, posts it, and opens the mailbox tab", async () => {
    window.history.replaceState(null, "", "/mail/connect?code=4%2F0AbCd&state=state-123");
    const { calls } = fakeServer({
      "POST /api/mail/mailbox/callback": { body: STATUS.providers[0] },
      "GET /api/mail/mailbox/status": { body: STATUS },
    });
    renderAt("/mail/connect?code=4%2F0AbCd&state=state-123");
    await waitFor(() => {
      expect(screen.getByTestId("where").textContent).toBe("/mail?mailbox=gmail");
    });
    expect(window.location.search).toBe("");
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ state: "state-123", code: "4/0AbCd", error: null });
  });

  it("shows why the sign-in failed and links back", async () => {
    window.history.replaceState(null, "", "/mail/connect?error=access_denied&state=s1");
    fakeServer({
      "POST /api/mail/mailbox/callback": {
        status: 400,
        body: { reason: "invalid_input", detail: "sign-in was not completed (access_denied); no mailbox was connected" },
      },
    });
    renderAt("/mail/connect?error=access_denied&state=s1");
    expect((await screen.findByRole("alert")).textContent).toContain("access_denied");
    expect(screen.getByRole("link", { name: /back to the email check page/i })).toBeTruthy();
  });

  it("a callback address without a state starts nothing", async () => {
    const { calls } = fakeServer({});
    renderAt("/mail/connect");
    expect((await screen.findByRole("alert")).textContent).toContain("no sign-in to finish");
    expect(calls).toHaveLength(0);
  });
});

describe("email page on the hosted service", () => {
  it("shows no connector: no tabs and no mailbox request", () => {
    setMode("hosted");
    const { calls } = fakeServer({});
    renderAt("/mail?mailbox=gmail");
    expect(screen.queryByRole("tablist")).toBeNull();
    expect(screen.queryByText(/check from your mailbox/i)).toBeNull();
    expect(screen.getByLabelText(/choose an \.eml file/i)).toBeTruthy();
    expect(calls.filter((c) => c.path.includes("/mailbox"))).toHaveLength(0);
  });
});

describe("routes", () => {
  it("the sign-in return page exists locally and not on the hosted service", async () => {
    const { createRoutes } = await import("../../app/router");
    const paths = (routes: ReturnType<typeof createRoutes>): string[] =>
      routes.flatMap((route) => [route.path ?? "", ...paths(route.children ?? [])]);
    expect(paths(createRoutes())).toContain("mail/connect");
    setMode("hosted");
    expect(paths(createRoutes())).not.toContain("mail/connect");
  });
});
