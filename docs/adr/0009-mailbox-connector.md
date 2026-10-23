# ADR 0009: Mailbox connector (local mode only): check messages you pick from Gmail or Microsoft 365

- Status: accepted
- Date: 2026-10-23
- Decision owner: Ruthvik Bandari
- Extends: [ADR 0003](0003-mail-module.md), section 3 "Optional connector"
- Amends: the invariants "outbound requests are opt-in and pass `netguard`" (adds a fixed provider allow-list) and
  "secrets come from the environment or the 0600 `secrets.json`" (adds OAuth client settings and refresh tokens)

## Context

ADR 0003 planned a read-only connector. The owner now wants it, with these limits:

- **Local mode first.** The connector exists only in the dashboard that `kestrix dashboard` serves on the user's own
  computer (loopback only). The hosted service must not expose it.
- **The user picks messages.** There is no bulk inbox scan. The user searches or browses a list and chooses single
  messages to check.
- **Read-only, nothing kept.** Kestrix never changes mail. The only thing kept is the normal report and the normal
  history summary (no subject or address in the summary, ADR 0008). The message list is shown in the page and never
  stored or logged.

Gmail read access is a Google *restricted scope*. A public app that requests it needs Google's verification and an
annual third-party security assessment (CASA). That rules out the hosted service and means each user brings their own
OAuth client in Google's "Testing" publishing status (up to 100 test users, no verification).

## Decision

### 1. Providers, endpoints and scopes

Only these hosts are ever contacted, and only over HTTPS on port 443:
`accounts.google.com`, `oauth2.googleapis.com`, `gmail.googleapis.com`, `login.microsoftonline.com`,
`graph.microsoft.com`.

| Step | Gmail | Microsoft 365 / Outlook.com |
| --- | --- | --- |
| Scope | `https://www.googleapis.com/auth/gmail.readonly` | `https://graph.microsoft.com/Mail.Read` (delegated), `offline_access`, `openid`, `profile` |
| Authorize | `https://accounts.google.com/o/oauth2/v2/auth` | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` |
| Token and refresh | `https://oauth2.googleapis.com/token` | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| Revoke | `https://oauth2.googleapis.com/revoke` | none for this flow (delete local tokens; the user removes consent) |
| Account label | `GET /gmail/v1/users/me/profile` (`emailAddress`) | `preferred_username` in the `id_token` (display only, not trusted for anything) |
| List and search | `GET /gmail/v1/users/me/messages?q=&labelIds=&maxResults=&pageToken=`, then `GET .../messages/{id}?format=metadata` per row | `GET /v1.0/me/messages` or `/me/mailFolders/{inbox,junkemail}/messages` with `$select`, `$top` and `$search="..."` |
| Raw message | `GET /gmail/v1/users/me/messages/{id}?format=raw` (`raw` is base64url) | `GET /v1.0/me/messages/{id}/$value` (MIME) |

`User.Read` is not requested: the account label comes from the OIDC `id_token` that the `openid profile` scopes
return. No send, modify, delete or label scope is ever requested, and the Graph calls are `GET` only.

Sources (checked 2026-10-23):

- Google, OAuth 2.0 for iOS and desktop apps (endpoints, loopback `http://127.0.0.1:port`, PKCE `S256`, revoke):
  <https://developers.google.com/identity/protocols/oauth2/native-app>
- Google, OAuth 2.0 overview, refresh token expiry (7 days for an external app in "Testing" status, unused for 6
  months, revoked by the user): <https://developers.google.com/identity/protocols/oauth2#expiration>
- Gmail API `users.messages.get` and `users.messages.list`:
  <https://developers.google.com/gmail/api/reference/rest/v1/users.messages/get>,
  <https://developers.google.com/gmail/api/reference/rest/v1/users.messages/list>,
  <https://developers.google.com/gmail/api/reference/rest/v1/users.messages> (`raw`, `snippet`, `internalDate`)
- Microsoft, OAuth 2.0 authorization code flow (endpoints, `code_challenge_method=S256`, public clients send no
  secret, `offline_access`, refresh token rotation):
  <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow>
- Microsoft, redirect URI rules (`http://localhost` allowed, port ignored when matching, `127.0.0.1` over `http` only
  through the manifest, `[::1]` unsupported):
  <https://learn.microsoft.com/en-us/entra/identity-platform/reply-url>
- Microsoft Graph, list messages (`Mail.Read` / `Mail.ReadBasic`, `$top` 1 to 1000, `@odata.nextLink`):
  <https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0>
- Microsoft Graph `$search` on messages (KQL, up to 1,000 results, sorted by sent time):
  <https://learn.microsoft.com/en-us/graph/search-query-parameter>
- Microsoft Graph MIME content (`/messages/{id}/$value`):
  <https://learn.microsoft.com/en-us/graph/outlook-get-mime-message>

### 2. The user's own OAuth app

Kestrix ships no client id or secret. The user registers a Google OAuth client of type *Desktop app* (publishing status
*Testing*, themselves as a test user) or a Microsoft Entra *public client* registration with the redirect URI
`http://localhost/mail/connect`, and gives Kestrix the client id (and for Google the client secret, which Google issues
for Desktop clients and which is not confidential for an installed app) and, for Microsoft, optionally the tenant
(`common` by default). They do it with `kestrix mail connect gmail|outlook --client-id ...` or in the dashboard's
mailbox panel. Values are stored in `secrets.json` (0600, directory 0700) under `mail_<provider>_*` keys. They are
never logged, returned by any route (status reports only whether each is set), or written to evidence.

### 3. Sign-in: authorization code with PKCE and a loopback redirect

- Redirect URI: `http://<host>:<port>/mail/connect` where host and port are those the dashboard was opened with
  (`127.0.0.1` or `localhost`; RFC 8252 section 7.3). The dashboard route `/mail/connect` is a page of the dashboard
  itself. It reads `code` and `state` from the address, removes them from the address bar at once, and `POST`s them to
  `POST /api/mail/mailbox/callback`. The token exchange therefore happens in a `POST` (`GET` routes keep no side
  effects) and passes the local Host, cross-site and body-size middleware. Microsoft accepts only `localhost`
  here, so the dashboard must be opened at `http://localhost:<port>` to connect Outlook; Kestrix says so instead of
  failing at Microsoft.
- `kestrix mail connect` uses the same flow with a one-shot listener on an ephemeral loopback port and the same
  `/mail/connect` path, so one registered redirect URI serves both.
- PKCE with `S256`, a 64-character verifier, a 256-bit `state`. Google also gets `access_type=offline` and
  `prompt=consent` so a refresh token is issued on reconnect.
- **State and browser binding.** `POST .../start` creates a pending flow (provider, verifier, redirect URI, state,
  a random binding value) held in memory only, for at most 10 minutes and at most 8 at a time, and sets the binding as
  an `HttpOnly`, `SameSite=Strict` cookie scoped to `/api/mail/mailbox`. `POST .../callback` accepts a flow once
  (it is removed before anything else), only when the state matches and the cookie matches the binding (compared in
  constant time). A callback without a matching flow, with a wrong or reused state, or from a browser that did not start
  it, is refused and nothing is exchanged.
- **Scope check.** The token response must list the read-only scope; if the user unticked it on Google's consent
  screen the connection is refused.
- Access tokens live in memory only. The refresh token is the only credential stored. Microsoft rotates refresh tokens
  on use; the new one replaces the old. A refresh answered `invalid_grant` (revoked, expired, 7-day Testing limit)
  deletes the stored token and asks the user to reconnect.
- Disconnect (`kestrix mail disconnect <provider>`, the panel's button, `DELETE /api/mail/mailbox/<provider>`): Google
  gets a revoke call for the refresh token; Microsoft has no equivalent for this flow, so the local tokens are deleted
  and the user is told where to remove consent. The local token is deleted even when the revoke call fails, and the
  answer says so. `--forget-app` also deletes the client id and secret.

### 4. Network rules

- Every outbound request goes through one client (`mail/mailbox/http.py`): HTTPS only, host in the allow-list above,
  no credentials in the URL, port 443 only, then `core/netguard.check_url` (public addresses only). Redirects are not
  followed; a 3xx answer is an `upstream_error`.
- Timeouts: 5 s to connect, 20 s overall per read. Response bodies are read as a stream with a byte cap: 1 MiB for
  JSON and token calls, and for a raw message the 25 MiB message limit (plus base64 overhead for Gmail). Gmail's
  `sizeEstimate` is checked before the download.
- Opt-in: nothing is contacted until the user presses a connect button (the page says first that it contacts Google
  or Microsoft, `.claude/rules/ui.md`) or runs the CLI command. `POST .../start` requires `acknowledge_network: true`.
- Page tokens from the provider are opaque to the browser, but a Graph `@odata.nextLink` is a URL. It is returned only
  as a token that must decode to an `https://graph.microsoft.com/v1.0/me/` URL, and the same host rules apply when it
  is used.

### 5. Features and what is kept

- **Search and browse** (`POST .../<provider>/search`): query up to 200 characters, folder `inbox`, `junk` or `all`,
  page size up to 50. Each row has only `id`, `from`, `subject`, `date` and a `snippet` of at most 120 characters. The
  list is returned to the page and not stored or logged.
- **Check** (`POST .../<provider>/check` with a message id): fetch the raw MIME, run `kestrix.mail.analyze` in memory,
  return the normal `MailReport`. The history middleware records that response like an upload check (tool `mail`,
  summary without subject or address). The message bytes are never written to disk.
- Never changes mail: no labels, no read flag (the Gmail scope cannot; Graph is `GET` only).
- **Reason codes**: `mailbox_not_configured`, `mailbox_not_connected`, `mailbox_reconnect_required` (HTTP 409);
  `rate_limited` (429 with `Retry-After` from the provider); `target_unreachable` (network off); `input_too_large`
  (message over 25 MiB); `upstream_error`; `invalid_input` (unknown or deleted message, bad query).

### 6. Hosted mode

The routes are not registered when `KESTRIX_MODE=hosted`, `HostedGate` answers 404 for `/api/mail/mailbox` before any
sign-in check (defence in depth), the OpenAPI schema is not served there, and the dashboard does not render the
connector when it is in hosted mode. Tests prove each of these.

## Consequences

- **Testing-mode limits.** Refresh tokens of a Google client in Testing status expire after 7 days, so the user
  reconnects weekly. Only the listed test users can sign in. A Microsoft work account may need an administrator to
  approve `Mail.Read` in tenants that forbid user consent.
- **Redirect-URI friction.** Outlook needs `http://localhost/mail/connect` registered (the Entra portal does not
  accept `http://127.0.0.1`) and the dashboard opened at `localhost`.
- **No claim of safety.** The check is the same offline heuristic analysis as for a saved file; `clean` is not a
  guarantee.
- **Not done:** bulk scans, attachment download, sending, labelling, other providers (IMAP), a hosted connector.
- **Unverified here.** No real Google or Microsoft account was used in development. Behaviour against the real
  services (consent screens, quotas, refresh token expiry) is taken from the documents above and from mock providers.
