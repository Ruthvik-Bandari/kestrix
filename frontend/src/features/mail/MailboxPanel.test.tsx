// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeServer } from "../../test/fakeServer";
import type { MailboxProviderStatus, MailboxStatus } from "../../lib/types";
import { MailboxPanel } from "./MailboxPanel";

const GMAIL: MailboxProviderStatus = {
  provider: "gmail",
  label: "Gmail",
  configured: false,
  connected: false,
  account: null,
  scope: "https://www.googleapis.com/auth/gmail.readonly",
  hosts: ["accounts.google.com", "oauth2.googleapis.com", "gmail.googleapis.com"],
  register_redirect_uri: null,
};
const OUTLOOK: MailboxProviderStatus = {
  provider: "outlook",
  label: "Outlook / Microsoft 365",
  configured: false,
  connected: false,
  account: null,
  scope: "https://graph.microsoft.com/Mail.Read",
  hosts: ["login.microsoftonline.com", "graph.microsoft.com"],
  register_redirect_uri: "http://localhost/mail/connect",
};

function status(gmail: Partial<MailboxProviderStatus> = {}, outlook: Partial<MailboxProviderStatus> = {}): MailboxStatus {
  return { notice: "Connecting contacts Google or Microsoft.", providers: [{ ...GMAIL, ...gmail }, { ...OUTLOOK, ...outlook }] };
}

const ROWS = {
  messages: [
    { id: "m1", sender: "Alice <alice@example.com>", subject: "Invoice overdue", date: "2026-10-20T09:30:00+00:00", snippet: "Please pay today" },
    { id: "m2", sender: "Bob <bob@example.com>", subject: "Lunch?", date: null, snippet: "" },
    { id: "m3", sender: "Carol <carol@example.com>", subject: "", date: null, snippet: "Hello" },
  ],
  next_page_token: "p2",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderPanel(props: Partial<Parameters<typeof MailboxPanel>[0]> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const onCheck = vi.fn();
  const navigate = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <MailboxPanel onCheck={onCheck} checking={null} navigate={navigate} {...props} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { onCheck, navigate };
}

describe("mailbox panel", () => {
  it("not connected: shows the setup form and sends nothing until the user saves", async () => {
    const { calls } = fakeServer({
      "GET /api/mail/mailbox/status": { body: status() },
      "PUT /api/mail/mailbox/gmail/config": { body: status({ configured: true }).providers[0] },
    });
    renderPanel();
    const id = await screen.findByLabelText(/oauth client id/i);
    expect(screen.getByRole("link", { name: /step-by-step setup/i }).getAttribute("href")).toBe("/docs/tools/email/connect-mailbox");
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /api/mail/mailbox/status"]);
    expect(screen.getByLabelText<HTMLInputElement>(/client secret/i).type).toBe("password");
    fireEvent.change(id, { target: { value: " 1234567890-abc.apps.googleusercontent.com " } });
    fireEvent.change(screen.getByLabelText(/client secret/i), { target: { value: "GOCSPX-secret" } });
    fireEvent.click(screen.getByRole("button", { name: /save app settings/i }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === "PUT")).toBe(true);
    });
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toEqual({ client_id: "1234567890-abc.apps.googleusercontent.com", client_secret: "GOCSPX-secret", tenant: null });
    await waitFor(() => {
      expect((screen.getByLabelText(/client secret/i) as HTMLInputElement | null)?.value ?? "").toBe("");
    });
  });

  it("outlook asks for a tenant and shows the redirect address to register", async () => {
    fakeServer({ "GET /api/mail/mailbox/status": { body: status() } });
    renderPanel();
    fireEvent.click(await screen.findByRole("radio", { name: /outlook/i }));
    expect(await screen.findByLabelText(/application \(client\) id/i)).toBeTruthy();
    expect(screen.getByLabelText(/tenant/i)).toBeTruthy();
    expect(screen.queryByLabelText(/client secret/i)).toBeNull();
    expect(screen.getByText("http://localhost/mail/connect")).toBeTruthy();
  });

  it("configured: says the dashboard will contact Google first, then connects only on the click", async () => {
    const { calls } = fakeServer({
      "GET /api/mail/mailbox/status": { body: status({ configured: true }) },
      "POST /api/mail/mailbox/gmail/start": { body: { authorize_url: "https://accounts.google.com/o/oauth2/v2/auth?x=1", expires_in: 600 } },
    });
    const { navigate } = renderPanel();
    expect(await screen.findByText(/this contacts google/i)).toBeTruthy();
    expect(screen.getByText(/accounts\.google\.com, oauth2\.googleapis\.com, gmail\.googleapis\.com/)).toBeTruthy();
    expect(screen.getByText(/never changes/i)).toBeTruthy();
    expect(calls).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: /connect gmail/i }));
    await waitFor(() => {
      expect(navigate).toHaveBeenCalledWith("https://accounts.google.com/o/oauth2/v2/auth?x=1");
    });
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ acknowledge_network: true });
  });

  it("shows the connecting state while the sign-in starts", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const real = fakeServer({ "GET /api/mail/mailbox/status": { body: status({ configured: true }) } });
    const original = real.fetchMock.getMockImplementation();
    real.fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (new URL(input instanceof Request ? input.url : input.toString(), "https://kestrix.test").pathname.endsWith("/start")) {
        await gate;
        return Response.json({ authorize_url: "https://accounts.google.com/x", expires_in: 600 });
      }
      return original?.(input, init) ?? new Response("{}");
    });
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: /connect gmail/i }));
    const pending = await screen.findByRole("button", { name: /opening google/i });
    expect(pending.getAttribute("aria-busy")).toBe("true");
    release();
  });

  it("a refused start (outlook opened at 127.0.0.1) shows the server's explanation", async () => {
    fakeServer({
      "GET /api/mail/mailbox/status": { body: status({}, { configured: true }) },
      "POST /api/mail/mailbox/outlook/start": {
        status: 400,
        body: { reason: "invalid_input", detail: "Microsoft accepts http://localhost as the redirect address" },
      },
    });
    renderPanel();
    fireEvent.click(await screen.findByRole("radio", { name: /outlook/i }));
    fireEvent.click(await screen.findByRole("button", { name: /connect outlook/i }));
    expect((await screen.findByRole("alert")).textContent).toContain("Microsoft accepts http://localhost");
  });

  it("connected: searches, lists only pick fields, pages and checks one message", async () => {
    const { calls } = fakeServer({
      "GET /api/mail/mailbox/status": { body: status({ configured: true, connected: true, account: "ada@gmail.example" }) },
      "POST /api/mail/mailbox/gmail/search": (call) => ({
        body: (call.body as { page_token: string | null }).page_token ? { messages: [{ id: "m4", sender: "Dan", subject: "More", date: null, snippet: "" }], next_page_token: null } : ROWS,
      }),
    });
    const { onCheck } = renderPanel();
    expect(await screen.findByText(/connected as ada@gmail\.example/i)).toBeTruthy();
    expect(calls).toHaveLength(1); // nothing is listed until the user asks
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: " from:alice " } });
    fireEvent.change(screen.getByLabelText(/where/i), { target: { value: "junk" } });
    fireEvent.click(screen.getByRole("button", { name: /^search$/i }));
    const list = await screen.findByRole("list", { name: /messages in your mailbox/i });
    expect(calls.find((c) => c.path.endsWith("/search"))?.body).toEqual({ query: "from:alice", folder: "junk", page_token: null });
    expect(within(list).getAllByRole("listitem")).toHaveLength(3);
    expect(screen.getByText("Invoice overdue")).toBeTruthy();
    expect(screen.getByText("Please pay today")).toBeTruthy();
    expect(screen.getByText(/3 messages shown. This list is not saved/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /show more/i }));
    expect(await screen.findByText("More")).toBeTruthy();
    expect(within(list).getAllByRole("listitem")).toHaveLength(4);
    fireEvent.click(screen.getByRole("button", { name: "Check message: Invoice overdue" }));
    expect(onCheck).toHaveBeenCalledWith("gmail", "m1");
  });

  it("arrow keys move between the Check buttons; Home and End jump", async () => {
    fakeServer({
      "GET /api/mail/mailbox/status": { body: status({ configured: true, connected: true, account: "a@b.example" }) },
      "POST /api/mail/mailbox/gmail/search": { body: { ...ROWS, next_page_token: null } },
    });
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: /show messages/i }));
    const first = await screen.findByRole("button", { name: "Check message: Invoice overdue" });
    first.focus();
    fireEvent.keyDown(first, { key: "ArrowDown" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Check message: Lunch?" }));
    fireEvent.keyDown(document.activeElement as Element, { key: "End" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Check message: (no subject)" }));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowDown" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Check message: (no subject)" }));
    fireEvent.keyDown(document.activeElement as Element, { key: "Home" });
    expect(document.activeElement).toBe(first);
  });

  it("marks the message being checked", async () => {
    fakeServer({
      "GET /api/mail/mailbox/status": { body: status({ configured: true, connected: true, account: "a@b.example" }) },
      "POST /api/mail/mailbox/gmail/search": { body: { ...ROWS, next_page_token: null } },
    });
    renderPanel({ checking: "m2" });
    fireEvent.click(await screen.findByRole("button", { name: /show messages/i }));
    const busy = await screen.findByRole("button", { name: "Check message: Lunch?" });
    expect(busy.getAttribute("aria-busy")).toBe("true");
    expect(screen.getByRole("button", { name: "Check message: Invoice overdue" }).getAttribute("aria-busy")).toBeNull();
  });

  it("empty results say so", async () => {
    fakeServer({
      "GET /api/mail/mailbox/status": { body: status({ configured: true, connected: true, account: "a@b.example" }) },
      "POST /api/mail/mailbox/gmail/search": { body: { messages: [], next_page_token: null } },
    });
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: /show messages/i }));
    expect(await screen.findByText(/no messages matched/i)).toBeTruthy();
  });

  it("a revoked sign-in offers to connect again; a rate limit says when to retry", async () => {
    let n = 0;
    fakeServer({
      "GET /api/mail/mailbox/status": { body: status({ configured: true, connected: true, account: "a@b.example" }) },
      "POST /api/mail/mailbox/gmail/search": () => {
        n += 1;
        return n === 1
          ? { status: 409, body: { reason: "mailbox_reconnect_required", detail: "Gmail no longer accepts the saved sign-in; connect again" } }
          : { status: 429, body: { reason: "rate_limited", detail: "Google is limiting requests" }, headers: { "Retry-After": "17" } };
      },
    });
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: /show messages/i }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("no longer accepts the saved sign-in");
    expect(within(alert).getByRole("button", { name: /connect again/i })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /show messages/i }));
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("try again in");
    });
  });

  it("disconnect calls the server and shows how access was removed", async () => {
    const { calls } = fakeServer({
      "GET /api/mail/mailbox/status": { body: status({ configured: true, connected: true, account: "a@b.example" }) },
      "DELETE /api/mail/mailbox/gmail": { body: { provider: "gmail", revoked: true, detail: "Google confirmed the revoke and the saved sign-in is deleted." } },
    });
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: /^disconnect$/i }));
    expect(await screen.findByText(/google confirmed the revoke/i)).toBeTruthy();
    expect(calls.some((c) => c.method === "DELETE" && c.path === "/api/mail/mailbox/gmail")).toBe(true);
  });

  it("a status failure is shown, not hidden", async () => {
    fakeServer({ "GET /api/mail/mailbox/status": { status: 500, body: { reason: "internal_error", detail: "unexpected error" } } });
    renderPanel();
    expect((await screen.findByRole("alert")).textContent).toContain("unexpected error");
  });
});
