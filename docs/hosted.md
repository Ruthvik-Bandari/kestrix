# Hosted mode (preview)

Hosted mode runs Kestrix as a public website where people sign in with Google or GitHub and use the website check, file and URL forensics, and the email check in the browser. It is the H2 slice of [ADR 0004](adr/0004-hosted-mode.md): the backend only. The container image and deploy configuration (H3) and the privacy notice and terms (H4) are not done yet, so do not launch a public service on this alone.

The local install is unchanged. Hosted mode is on only when `KESTRIX_MODE=hosted` is set or the server is started with `kestrix serve-hosted`.

## Contents

- [What changes in hosted mode](#what-changes-in-hosted-mode)
- [Configuration](#configuration)
- [Register the OAuth apps](#register-the-oauth-apps)
- [Run it](#run-it)
- [Security properties](#security-properties)
- [Limitations](#limitations)

## What changes in hosted mode

| Area | Local mode | Hosted mode |
| --- | --- | --- |
| Allowed `Host` | `127.0.0.1`, `localhost`, `[::1]` | Only the host of `KESTRIX_PUBLIC_ORIGIN` |
| Cross-site write check | `Origin` host must be a loopback name | `Origin` must equal `KESTRIX_PUBLIC_ORIGIN` exactly |
| Accounts | None | Sign-in with Google or GitHub; no passwords |
| Modules | All five | Website check, forensics, email check. Detection repair, Bitcoin and `/api/settings*` return 404. |
| Module API routes | Open to local callers | Need a session (401 `sign_in_required`) and an `X-CSRF-Token` header on state-changing requests (403 `csrf_failed`) |
| Website check | `allow_private` allowed | Public targets only; each scan needs `"authorized": true` |
| Rate limits | None | Per user and per IP (see below) |
| Headers | CSP and friends | The same, plus `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` |
| Logs | uvicorn's access log | A privacy-safe access line per request; uvicorn's access log is off |

## Configuration

All settings come from environment variables, which on a hosting platform should come from its secret store. The server refuses to start, with a message naming the variable, if a required value is missing or malformed.

| Variable | Required | Meaning |
| --- | --- | --- |
| `KESTRIX_MODE` | No | `local` (default) or `hosted`. `kestrix serve-hosted` forces `hosted`. |
| `KESTRIX_PUBLIC_ORIGIN` | Yes | The public origin, such as `https://kestrix.example.org`. Must be `https://`, with no path, query or credentials. |
| `KESTRIX_SESSION_PEPPER` | Yes | A secret of at least 32 bytes. Keys the session-id, CSRF and `state` hashes. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Changing it signs everyone out. |
| `KESTRIX_GOOGLE_CLIENT_ID`, `KESTRIX_GOOGLE_CLIENT_SECRET` | One provider | Google sign-in. Enabled only when both are set; setting just one is an error. |
| `KESTRIX_GITHUB_CLIENT_ID`, `KESTRIX_GITHUB_CLIENT_SECRET` | One provider | GitHub sign-in, with the same rule. |
| `KESTRIX_DB` | No | SQLite file. Default: `hosted.sqlite3` in the config directory (`$KESTRIX_HOME`, else `~/.config/kestrix`). Put it on a persistent volume. |
| `KESTRIX_LOG_SALT` | No | At least 16 bytes. Salt for the user-id hash in logs. Default: derived from the pepper. |
| `KESTRIX_ABUSE_CONTACT` | No | Printable ASCII, at most 200 characters, such as `abuse@kestrix.example.org`. Added to the website check's `User-Agent`. |
| `KESTRIX_TRUST_PROXY_HEADERS` | No | `1` to take the client IP for rate limits from the right-most `X-Forwarded-For` entry. See [Limitations](#limitations). |
| `PORT` | No | Listening port for `kestrix serve-hosted` (default 8000). |

## Register the OAuth apps

Replace `kestrix.example.org` with your domain. The redirect URI must match exactly, including `https` and the path.

### Google

1. In the [Google Cloud console](https://console.cloud.google.com/), create or pick a project.
2. Open **APIs & Services > OAuth consent screen** (Google Auth Platform > Branding and Audience in the newer console). Choose **External**, fill in the app name, support email and your domain, and add the scopes `openid`, `email` and `profile`. No sensitive or restricted scopes are used.
3. Open **APIs & Services > Credentials > Create credentials > OAuth client ID**. Choose **Web application**.
4. Under **Authorized redirect URIs**, add `https://kestrix.example.org/api/auth/callback/google`. No JavaScript origins are needed.
5. Copy the client ID and secret into `KESTRIX_GOOGLE_CLIENT_ID` and `KESTRIX_GOOGLE_CLIENT_SECRET`.
6. Publish the consent screen when you are ready for users outside your test-user list.

### GitHub

1. Open **Settings > Developer settings > OAuth Apps > New OAuth App** (for your account or organization). Use an OAuth App, not a GitHub App.
2. Set **Homepage URL** to `https://kestrix.example.org` and **Authorization callback URL** to `https://kestrix.example.org/api/auth/callback/github`.
3. Register the app, then **Generate a new client secret**.
4. Copy the client ID and secret into `KESTRIX_GITHUB_CLIENT_ID` and `KESTRIX_GITHUB_CLIENT_SECRET`.

Kestrix asks GitHub for `read:user user:email`, and Google for `openid email profile`.

## Run it

```bash
export KESTRIX_PUBLIC_ORIGIN=https://kestrix.example.org
export KESTRIX_SESSION_PEPPER="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export KESTRIX_GOOGLE_CLIENT_ID=... KESTRIX_GOOGLE_CLIENT_SECRET=...
export KESTRIX_DB=/data/kestrix/hosted.sqlite3
kestrix serve-hosted            # listens on 0.0.0.0:$PORT (default 8000)
```

`serve-hosted` is a separate command rather than a `dashboard --hosted` flag. `dashboard` is built for one person on loopback: it opens a browser, defaults to `127.0.0.1`, and treats `--host` as an extra allowed name. Hosted mode needs none of that, binds every interface, and takes its allowed host from `KESTRIX_PUBLIC_ORIGIN`. Keeping the two apart means a typo in a local command cannot start the public service, and `kestrix dashboard` refuses to run when `KESTRIX_MODE=hosted` is set.

`serve-hosted` expects TLS to end at the platform's proxy in front of it. uvicorn's proxy-header handling is off, and so is its access log, which would record query strings (OAuth codes and `state`) and client addresses.

The browser flow:

1. The page calls `GET /api/auth/providers` and links to `GET /api/auth/login/{provider}?next=/app`.
2. After sign-in, the provider returns to `/api/auth/callback/{provider}`, which sets the session cookie and redirects to `next` (default `/app`). Any failure redirects to `/welcome?signin=failed`.
3. The page calls `GET /api/auth/me` for the user and the `csrf_token`, and sends that token as `X-CSRF-Token` on every `POST`, `PUT`, `PATCH` and `DELETE`.

Routes and status codes are in [api.md](api.md#hosted-mode).

## Security properties

- **Sign-in.**
  - OAuth 2.0 authorization code with PKCE (S256), a random `state`, and for Google an OpenID Connect `nonce`.
  - The pending attempt (provider, PKCE verifier, nonce, `next`) is stored server-side under a keyed hash of `state`, expires after 10 minutes, and is deleted on first use, so a `state` works once.
  - The `state` is also set in a 10-minute `__Host-kx_login` cookie and must match on the callback. This ties the callback to the browser that started sign-in, which blocks login CSRF (an attacker pasting their own callback link).
- **Google identity.**
  - The ID token comes straight from Google's token endpoint over verified TLS, in exchange for the code and the client secret. OpenID Connect Core 1.0, section 3.1.3.7, lets a client in this position rely on TLS instead of checking the token's signature, and Kestrix does that.
  - It still checks the claims: `iss` is `https://accounts.google.com` or `accounts.google.com`; `aud` is the client ID (with several audiences, `azp` must be the client ID too); `exp` is in the future; `iat` is within the last 15 minutes, allowing 5 minutes of clock skew; `nonce` matches the attempt; `email_verified` is `true`.
- **GitHub identity.** The access token is used once for `GET /user` and `GET /user/emails`. Sign-in needs an email that is both primary and verified. The access token is not stored.
- **Outbound requests.** Only to `accounts.google.com`, `oauth2.googleapis.com`, `github.com` and `api.github.com`, over `https` on port 443, with certificate verification, no redirects, no environment proxies, a 10-second timeout and a 64 KiB response cap. These are fixed provider hosts, so `netguard`'s private-address check is not used for them; the allowlist is the control.
- **Accounts.** Users are keyed by `(provider, subject)`. The table holds the verified email, display name and two timestamps. No passwords and no provider tokens.
- **Sessions.**
  - The session id is 256 random bits. The database stores only HMAC-SHA256(pepper, id), so a copy of the database cannot be replayed as cookies.
  - Cookie: `__Host-kx_session`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`.
  - A session ends after 7 days without use or 30 days after sign-in, whichever comes first. The last-seen time is updated at most every 5 minutes.
  - Signing in again replaces the browser's previous session. Expired rows are purged when someone signs in.
- **CSRF.**
  - The token is derived from the session id with the pepper, returned by `/api/auth/me`, and stored only as a keyed hash. It is compared in constant time.
  - It is required on every state-changing request from a signed-in user, on top of the existing `Origin` / `Sec-Fetch-Site` refusal, which now compares against the public origin.
- **Route gating.** Every `/api/` route is private unless it is on a short public list: health, the OpenAPI schema, providers, `me`, `logout`, `login` and `callback`. A route added later is private by default. Detection repair, Bitcoin and the Anthropic-key settings are not mounted and return 404.
- **Website check.**
  - Public targets only: `allow_private: true` is refused with 400, and `netguard` still applies to every hop.
  - Each scan needs `"authorized": true`, the user's confirmation that they own or are authorized to test the site.
  - The `User-Agent` names Kestrix and, if set, `KESTRIX_ABUSE_CONTACT`.
- **Uploads.** Files and messages are analyzed as in local mode (in memory or an anonymous spooled temporary file) and are not stored. Reports are not kept on the server.
- **Logs.** One `kestrix.access` line per request: method, route template (`/api/auth/callback/{provider}`, never the query string), status, duration in ms, and the first 16 hex characters of HMAC-SHA256(log salt, user id). For unmatched paths, the path (without query) is logged instead of a template. Failed sign-ins add a `kestrix.auth` line with a fixed reason code, such as `id_token_wrong_audience`. Bodies, file names, emails, URLs being checked, cookies and tokens are never logged.
- **Database file.** Created `0600`, in a directory created or tightened to `0700` when Kestrix owns it. All queries are parameterized.

## Limitations

- **Single instance.** Rate limits are kept in process memory. With more than one instance or worker, each keeps its own counters, so the effective limit is multiplied by the instance count. Run one instance until a shared store is added. The limiter keeps at most 100,000 keys; above that the oldest keys are dropped, which resets their counters.
- **SQLite.** One file on a persistent volume, fine for one instance. It is reached through a small repository class (`server/store.py`) so Postgres can replace it.
- **Rate limits** (all return 429 `rate_limited` with `Retry-After`):

  | What | Limit | Counted per |
  | --- | --- | --- |
  | `POST /api/webcheck` | 20 per hour | User |
  | `POST /api/forensics/file`, `/api/forensics/url`, `/api/mail/analyze` (one shared bucket) | 120 per hour | User |
  | `GET /api/auth/login/{provider}` | 10 per 10 minutes | Client IP |
  | `GET /api/auth/callback/{provider}` | 10 per 10 minutes | Client IP |

- **Client IP behind a proxy.** By default the client IP is the socket peer, which behind a platform proxy is the proxy itself, so every visitor shares one sign-in limit. Set `KESTRIX_TRUST_PROXY_HEADERS=1` only when a proxy you control always appends the real client address to `X-Forwarded-For`. Kestrix then uses the right-most entry. Without such a proxy the header is attacker-controlled.
- **Not yet in this slice.** Per-user caps on concurrent analyses, the container image, the privacy notice and terms, and the dashboard's sign-in screens belong to later slices of ADR 0004.
- **Session rows are purged opportunistically.** An expired session is refused and deleted when its cookie is next presented; otherwise its row stays until the next sign-in purges it.
- **`GET` routes with side effects.** `login` stores a pending attempt and `callback` creates a session. Both are needed for OAuth and both are rate-limited.
