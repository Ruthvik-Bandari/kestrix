// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type KeyboardEvent, type ReactNode, type SubmitEvent } from "react";
import { Link } from "react-router";
import { docsPath } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { Button, CopyButton, Disclosure, ErrorState, Field, StatusPill } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import { keys } from "../../lib/queries";
import type {
  MailboxFolder,
  MailboxMessage,
  MailboxProvider,
  MailboxProviderStatus,
  MailboxSearch,
} from "../../lib/types";

/** The how-to page: registering your own app at Google and Microsoft. */
export const CONNECT_DOC = "tools/email/connect-mailbox";

const PROVIDER_NAME: Record<MailboxProvider, string> = { gmail: "Google", outlook: "Microsoft" };
const SEARCH_HINT: Record<MailboxProvider, string> = {
  gmail: "Gmail search words, such as from:bank.example subject:invoice or newer_than:7d.",
  outlook: "Words to find in the sender, subject or body. Outlook search treats your text as plain words.",
};
const FOLDERS: { value: MailboxFolder; label: string }[] = [
  { value: "inbox", label: "Inbox" },
  { value: "junk", label: "Junk or spam" },
  { value: "all", label: "All mail" },
];

/** Move focus between the Check buttons with the arrow keys; Tab still reaches each one. */
export function moveWithArrows(event: KeyboardEvent<HTMLButtonElement>): void {
  const keysMoved = ["ArrowDown", "ArrowUp", "Home", "End"];
  if (!keysMoved.includes(event.key)) return;
  const buttons = Array.from(event.currentTarget.closest("ul")?.querySelectorAll<HTMLButtonElement>("button[data-check]") ?? []);
  const at = buttons.findIndex((button) => button === event.currentTarget);
  if (at < 0) return;
  event.preventDefault();
  const next =
    event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : at + (event.key === "ArrowDown" ? 1 : -1);
  buttons[Math.max(0, Math.min(buttons.length - 1, next))]?.focus();
}

function whenText(iso: string | null): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function NetworkNotice({ status }: { status: MailboxProviderStatus }) {
  return (
    <div className="flex gap-3 rounded-xl border border-line bg-surface-solid px-4 py-3 text-[0.875rem] text-ink-2">
      <Icon name="info" size={18} className="mt-0.5 flex-none text-ink-3" />
      <p>
        <span className="font-medium text-ink">This contacts {PROVIDER_NAME[status.provider]}.</span> Connecting opens{" "}
        {PROVIDER_NAME[status.provider]}&apos;s sign-in page in this browser, and this computer then contacts{" "}
        <span className="font-mono">{status.hosts.join(", ")}</span>. Kestrix asks for read-only access, never changes
        mail, and keeps only a refresh token on this computer until you disconnect. Messages you pick are checked on
        this computer and never sent to Kestrix servers.
      </p>
    </div>
  );
}

function SettingsForm({ status, onSaved }: { status: MailboxProviderStatus; onSaved: () => void }) {
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const [tenant, setTenant] = useState("");
  const save = useMutation({
    mutationFn: () =>
      api.mailboxConfigure(status.provider, {
        client_id: clientId.trim(),
        client_secret: secret.trim() || null,
        tenant: tenant.trim() || null,
      }),
    onSuccess: () => {
      setSecret("");
      onSaved();
    },
  });
  const gmail = status.provider === "gmail";
  function submit(event: SubmitEvent) {
    event.preventDefault();
    save.mutate();
  }
  return (
    <form onSubmit={submit} className="space-y-4" aria-label={`${status.label} app settings`}>
      <p className="text-[0.875rem] text-ink-2">
        You bring your own app registration, so no one else sees your mailbox access.{" "}
        <Link className="link" to={docsPath(CONNECT_DOC)}>
          Step-by-step setup
        </Link>
      </p>
      <Field
        htmlFor="mailbox-client-id"
        label={gmail ? "OAuth client ID" : "Application (client) ID"}
        hint={gmail ? "From a Desktop app client in your Google Cloud project." : "A GUID from your Microsoft Entra app registration."}
      >
        <input
          id="mailbox-client-id"
          className="field font-mono"
          type="text"
          spellCheck={false}
          autoComplete="off"
          value={clientId}
          onChange={(e) => {
            setClientId(e.target.value);
          }}
          required
        />
      </Field>
      {gmail ? (
        <Field
          htmlFor="mailbox-client-secret"
          label="Client secret"
          optional
          hint="Google shows one for a Desktop app client. It is stored only in your 0600 secrets file and never shown again."
        >
          <input
            id="mailbox-client-secret"
            className="field font-mono"
            type="password"
            spellCheck={false}
            autoComplete="off"
            value={secret}
            onChange={(e) => {
              setSecret(e.target.value);
            }}
          />
        </Field>
      ) : (
        <>
          <Field
            htmlFor="mailbox-tenant"
            label="Tenant"
            optional
            hint="Leave empty for common (work, school and personal accounts). Use your tenant ID if the app is single-tenant."
          >
            <input
              id="mailbox-tenant"
              className="field font-mono"
              type="text"
              spellCheck={false}
              autoComplete="off"
              value={tenant}
              onChange={(e) => {
                setTenant(e.target.value);
              }}
              placeholder="common"
            />
          </Field>
          {status.register_redirect_uri ? (
            <div className="flex flex-wrap items-center gap-2 text-[0.875rem] text-ink-2">
              <span>Register this redirect URI as a Mobile and desktop application:</span>
              <code className="rounded bg-inset px-1.5 py-0.5 font-mono text-ink">{status.register_redirect_uri}</code>
              <CopyButton text={status.register_redirect_uri} label="Copy redirect URI" />
            </div>
          ) : null}
        </>
      )}
      {save.isError ? <ErrorState error={save.error} /> : null}
      <Button type="submit" variant="secondary" pending={save.isPending} pendingLabel="Saving…" disabled={!clientId.trim()}>
        Save app settings
      </Button>
    </form>
  );
}

function Results({
  provider,
  data,
  checking,
  onCheck,
  more,
}: {
  provider: MailboxProvider;
  data: { messages: MailboxMessage[]; next: string | null };
  checking: string | null;
  onCheck: (provider: MailboxProvider, id: string) => void;
  more: ReactNode;
}) {
  if (data.messages.length === 0) return <p className="text-ink-2">No messages matched.</p>;
  return (
    <div>
      <p className="mb-2 text-[0.875rem] text-ink-2" role="status">
        {data.messages.length.toLocaleString()} {data.messages.length === 1 ? "message" : "messages"} shown. This list is
        not saved.
      </p>
      <ul aria-label="Messages in your mailbox" className="divide-y divide-line rounded-xl border border-line bg-surface-solid">
        {data.messages.map((message) => {
          const when = whenText(message.date);
          const label = message.subject || "(no subject)";
          return (
            <li key={message.id} className="flex flex-col gap-2 px-4 py-3">
              <div className="min-w-0">
                <p className="truncate font-medium text-ink">{label}</p>
                <p className="truncate text-[0.875rem] text-ink-2">
                  {message.sender || "(no sender)"}
                  {when ? <> &middot; {when}</> : null}
                </p>
                {message.snippet ? <p className="mt-1 line-clamp-2 text-[0.875rem] break-words text-ink-3">{message.snippet}</p> : null}
              </div>
              <Button
                size="sm"
                variant="secondary"
                className="self-start"
                data-check=""
                onKeyDown={moveWithArrows}
                aria-label={`Check message: ${label}`}
                pending={checking === message.id}
                pendingLabel="Checking…"
                onClick={() => {
                  onCheck(provider, message.id);
                }}
              >
                Check
              </Button>
            </li>
          );
        })}
      </ul>
      {more}
    </div>
  );
}

/**
 * Local mode only: connect Gmail or Outlook with your own app registration, search or browse, and pick single messages
 * to check (ADR 0009). The list lives in this component's state and is never stored. `onCheck` runs the check in the
 * page, so its report appears in the usual place.
 */
export function MailboxPanel({
  onCheck,
  checking,
  advanced,
  initialProvider = "gmail",
  navigate = (url) => {
    window.location.assign(url);
  },
}: {
  onCheck: (provider: MailboxProvider, id: string) => void;
  /** The id of the message being checked, if any. */
  checking: string | null;
  /** The shared advanced options (protected domains, authserv-id), shown under the list. */
  advanced?: ReactNode;
  /** The provider to show first (the address says which one just signed in). */
  initialProvider?: MailboxProvider;
  navigate?: (url: string) => void;
}) {
  const client = useQueryClient();
  const [provider, setProvider] = useState<MailboxProvider>(initialProvider);
  const [editing, setEditing] = useState(false);
  const [query, setQuery] = useState("");
  const [folder, setFolder] = useState<MailboxFolder>("inbox");
  const [list, setList] = useState<{ messages: MailboxMessage[]; next: string | null } | null>(null);
  const status = useQuery({ queryKey: keys.mailbox, queryFn: api.mailboxStatus, staleTime: 30_000 });
  const current = status.data?.providers.find((item) => item.provider === provider);

  const connect = useMutation({
    mutationFn: () => api.mailboxStart(provider),
    onSuccess: (data) => {
      navigate(data.authorize_url);
    },
  });
  const disconnect = useMutation({
    mutationFn: () => api.mailboxDisconnect(provider, false),
    onSuccess: () => {
      setList(null);
      void client.invalidateQueries({ queryKey: keys.mailbox });
    },
  });
  const search = useMutation({
    mutationFn: ({ token }: { token: string | null }) =>
      api.mailboxSearch(provider, { query: query.trim(), folder, page_token: token }),
    onSuccess: (data: MailboxSearch, { token }) => {
      setList((previous) => ({
        messages: token && previous ? [...previous.messages, ...data.messages] : data.messages,
        next: data.next_page_token,
      }));
    },
    onError: (error) => {
      if (error instanceof ApiError && error.reason.startsWith("mailbox_")) void client.invalidateQueries({ queryKey: keys.mailbox });
    },
  });

  function choose(next: MailboxProvider) {
    setProvider(next);
    setList(null);
    setEditing(false);
    connect.reset();
    search.reset();
    disconnect.reset();
  }

  function runSearch(event: SubmitEvent) {
    event.preventDefault();
    setList(null);
    search.mutate({ token: null });
  }

  const reconnect =
    search.error instanceof ApiError && search.error.reason === "mailbox_reconnect_required" ? search.error : null;

  return (
    <div className="space-y-4" aria-label="Check from your mailbox">
      <fieldset className="min-w-0">
        <legend className="label">Mailbox</legend>
        <div className="mt-1.5 flex flex-wrap gap-4">
          {(["gmail", "outlook"] as const).map((item) => (
            <label key={item} className="inline-flex min-h-11 items-center gap-2">
              <input
                type="radio"
                name="mailbox-provider"
                checked={provider === item}
                onChange={() => {
                  choose(item);
                }}
              />
              {item === "gmail" ? "Gmail" : "Outlook / Microsoft 365"}
            </label>
          ))}
        </div>
      </fieldset>

      {status.isPending ? (
        <p role="status" className="text-ink-2">
          Loading your mailbox settings…
        </p>
      ) : status.isError || !current ? (
        <ErrorState error={status.error ?? new Error("The mailbox settings did not load.")} />
      ) : current.connected ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <StatusPill tone="ok">Connected{current.account ? ` as ${current.account}` : ""}</StatusPill>
            <Button
              size="sm"
              variant="secondary"
              pending={disconnect.isPending}
              pendingLabel="Disconnecting…"
              onClick={() => {
                disconnect.mutate();
              }}
            >
              Disconnect
            </Button>
          </div>
          {disconnect.isError ? <ErrorState error={disconnect.error} /> : null}
          <form onSubmit={runSearch} className="space-y-3" aria-label="Search your mailbox">
            <Field htmlFor="mailbox-query" label="Search" optional hint={SEARCH_HINT[provider]}>
              <input
                id="mailbox-query"
                className="field"
                type="search"
                maxLength={200}
                spellCheck={false}
                autoComplete="off"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                }}
              />
            </Field>
            <Field htmlFor="mailbox-folder" label="Where">
              <select
                id="mailbox-folder"
                className="field"
                value={folder}
                onChange={(e) => {
                  setFolder(e.target.value as MailboxFolder);
                }}
              >
                {FOLDERS.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
            </Field>
            <Button type="submit" icon="search" className="w-full" pending={search.isPending && !list} pendingLabel="Searching…">
              {query.trim() ? "Search" : "Show messages"}
            </Button>
          </form>
          {search.isError ? (
            <ErrorState error={search.error}>
              {reconnect ? (
                <Button
                  size="sm"
                  variant="secondary"
                  pending={connect.isPending}
                  pendingLabel="Opening…"
                  onClick={() => {
                    connect.mutate();
                  }}
                >
                  Connect again
                </Button>
              ) : null}
            </ErrorState>
          ) : null}
          {list ? (
            <Results
              provider={provider}
              data={list}
              checking={checking}
              onCheck={onCheck}
              more={
                list.next ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="mt-3"
                    pending={search.isPending}
                    pendingLabel="Loading…"
                    onClick={() => {
                      search.mutate({ token: list.next });
                    }}
                  >
                    Show more
                  </Button>
                ) : null
              }
            />
          ) : null}
          {advanced}
        </div>
      ) : (
        <div className="space-y-4">
          {current.configured && !editing ? (
            <>
              {search.isError ? <ErrorState error={search.error} /> : null}
              <NetworkNotice status={current} />
              {provider === "outlook" && typeof window !== "undefined" && window.location.hostname === "127.0.0.1" ? (
                <p role="note" className="text-[0.875rem] text-ink-2">
                  Microsoft accepts only <span className="font-mono">http://localhost</span> as the redirect address. Open
                  this dashboard at <span className="font-mono">http://localhost:{window.location.port || "8765"}/mail</span>{" "}
                  to connect Outlook.
                </p>
              ) : null}
              {connect.isError ? <ErrorState error={connect.error} /> : null}
              <div className="flex flex-wrap gap-3">
                <Button
                  icon="arrowRight"
                  pending={connect.isPending}
                  pendingLabel={`Opening ${PROVIDER_NAME[provider]}…`}
                  onClick={() => {
                    connect.mutate();
                  }}
                >
                  Connect {current.label}
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setEditing(true);
                  }}
                >
                  Change app settings
                </Button>
              </div>
            </>
          ) : (
            <Disclosure summary="Set up your own app" defaultOpen>
              <SettingsForm
                key={provider}
                status={current}
                onSaved={() => {
                  setEditing(false);
                  void client.invalidateQueries({ queryKey: keys.mailbox });
                }}
              />
            </Disclosure>
          )}
        </div>
      )}
      {disconnect.data ? (
        <p role="status" className="text-[0.875rem] text-ink-2">
          {disconnect.data.detail}
        </p>
      ) : null}
    </div>
  );
}
