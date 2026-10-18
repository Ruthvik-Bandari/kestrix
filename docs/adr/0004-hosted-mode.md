# ADR 0004: Hosted mode with Google and GitHub sign-in

- Status: accepted
- Date: 2026-10-18
- Decision owner: Ruthvik Bandari

## Context

Kestrix runs on the user's own computer. The local server binds to loopback, has no accounts, and sends nothing
anywhere unless the user asks (ADR 0001). The owner now wants a public website where anyone can sign in for
free and use some modules in the browser, next to the open-source install.

Running Kestrix for strangers changes the threat model:

- The server receives other people's files and emails.
- The website check becomes a request-making service that attackers could abuse.
- Accounts become worth stealing.

## Decision

### One code base, two modes

`KESTRIX_MODE=local` stays the default and is unchanged. `KESTRIX_MODE=hosted` turns on the following.

| Area | Local (unchanged) | Hosted |
| --- | --- | --- |
| Who can reach it | Loopback only | The public domain in `KESTRIX_PUBLIC_ORIGIN`; the Host allowlist is that domain only |
| Accounts | None | Sign-in with Google or GitHub (OpenID Connect / OAuth 2.0 authorization code with PKCE, `state` and `nonce`). No passwords are ever stored. |
| Modules | All | Web check, file and URL forensics, and email check. Detection repair, Bitcoin and the Anthropic-key settings return 404. |
| Website check targets | `--allow-private` possible | Public targets only. Each scan needs an "I own or am authorized to test this site" confirmation. |
| Landing page | `/welcome` | `/`, with the app under `/app` |

### Accounts and sessions

- **Users table:** internal id, provider, the provider's subject id, verified email, display name, created and
  last-login times. Nothing else.
- **Sessions:**
  - A random 256-bit id, stored only as its HMAC-SHA256 under a server-side pepper.
  - Sent as the `__Host-kx_session` cookie: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`.
  - Expires after 7 days idle and 30 days absolute.
  - Rotated at sign-in; deleted at sign-out.
- **CSRF protection:**
  - every state-changing request needs a per-session CSRF token header;
  - the existing cross-site write refusal stays (`Sec-Fetch-Site` / `Origin`).
- **Login CSRF:** `state` is also bound to the browser with a short-lived `__Host-kx_login` cookie, so a victim
  cannot be signed in to an attacker's account through a crafted callback link.
- **Account deletion** is one action that removes the user row and all of that user's sessions immediately.
- **Store:** SQLite on a mounted volume to start, opened through a small repository layer so Postgres can replace
  it.

### Data handling

- **Uploaded files and emails:**
  - analyzed in memory and never written to disk or a database;
  - the report is returned to the browser and not kept on the server.
- **Logs** hold the time, route, status, duration and a salted hash of the user id. They never contain bodies,
  file names, email addresses, URLs being checked, or tokens.
- **Secrets** (OAuth client secrets, the session pepper) come from the hosting platform's secret store as
  environment variables.

### Abuse and availability controls

- **Rate limits per user and per IP:**
  - website checks: 20 per hour;
  - analyses: 120 per hour;
  - sign-ins: 10 per 10 minutes.
- **Hard caps:**
  - concurrent analyses per user (not yet implemented; the per-hour limits apply);
  - the existing body-size caps;
  - request timeouts.
- **Website checks:**
  - keep `netguard` (no private, loopback, link-local or metadata addresses, and IPs re-checked on redirect);
  - one request per scan;
  - an honest `User-Agent` that names Kestrix and an abuse contact.

### Platform hardening

- **HTTP:**
  - HSTS with `preload`;
  - the strict CSP stays;
  - no CORS;
  - TLS only.
- **Container:**
  - the Docker image runs as non-root with a read-only root filesystem, no shell tools beyond what Python needs,
    and pinned base-image digests;
  - dependencies are locked with `uv.lock` and `package-lock.json`, and CI audits them.

### Legal pages

Before launch, the site needs a privacy notice and terms of use that state exactly the data handling above.

## Consequences

- **Delivery slices:**
  - H1: landing page and redesign;
  - H2: hosted-mode backend (auth, sessions, users, route gating, rate limits, CSRF), with tests;
  - H3: container image and deploy configuration;
  - H4: privacy notice, terms and account deletion;
  - H5: security review and launch checklist.
- **Hosting.** It starts on a free or low-cost platform (owner's choice). Detection repair stays local-only,
  because a per-user Elasticsearch is not affordable on a free tier.
- **Gmail and Microsoft 365 connectors stay local-only.** Hosting them would need Google's paid security
  assessment for restricted scopes, and would put users' mailboxes on our server.
- **Owner actions.** The owner must register OAuth apps with Google and GitHub for the production domain, and
  choose the domain.
