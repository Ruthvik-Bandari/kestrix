# Hosted mode (preview)

Hosted mode runs Kestrix as a public website where people sign in with Google or GitHub and use the website check, file and URL forensics, and the email check in the browser. It is the H2 slice of [ADR 0004](adr/0004-hosted-mode.md): the backend. The container image and Fly.io configuration (H3) are described in [deploy.md](deploy.md). The dashboard's hosted screens (landing page at `/`, sign-in at `/signin`, the app under `/app`, account menu with sign-out and deletion) are built; the privacy notice and terms (H4) exist only as drafts ([privacy](legal/privacy-draft.md), [terms](legal/terms-draft.md), also served at `/privacy` and `/terms`) that the owner must review, so do not launch a public service yet.

The local install is unchanged. Hosted mode is on only when `KESTRIX_MODE=hosted` is set or the server is started with `kestrix serve-hosted`.

## Contents

- [What changes in hosted mode](#what-changes-in-hosted-mode)
- [Configuration](#configuration)
- [Register the OAuth apps](#register-the-oauth-apps)
- [Run it](#run-it)
- [Security properties](#security-properties)
- [Abuse handling](#abuse-handling)
- [Limitations](#limitations)

## What changes in hosted mode

| Area | Local mode | Hosted mode |
| --- | --- | --- |
| Allowed `Host` | `127.0.0.1`, `localhost`, `[::1]` | Only the host of `KESTRIX_PUBLIC_ORIGIN` |
| Cross-site write check | `Origin` host must be a loopback name | `Origin` must equal `KESTRIX_PUBLIC_ORIGIN` exactly |
| Accounts | None | Sign-in with Google or GitHub; no passwords |
| Modules | All five | Website check, forensics, email check. Detection repair, Bitcoin and `/api/settings*` return 404 (except the history setting). |
| Result history | Kept 30 days, plaintext, in `history.sqlite3` in the config folder | Kept 30 days per user, encrypted with `KESTRIX_HISTORY_KEY` ([ADR 0008](adr/0008-per-user-result-history.md)) |
| Module API routes | Open to local callers | Need a session (401 `sign_in_required`) and an `X-CSRF-Token` header on state-changing requests (403 `csrf_failed`) |
| Website check | `allow_private` allowed; any port; detailed connection errors | Public targets on ports 80 and 443 only; each scan needs `"authorized": true`; one generic message for connection failures |
| Uploads | Files up to 50 MiB, messages up to 25 MiB | Both up to 10 MiB |
| Analyses | In the server process | In a separate worker process with CPU, memory and time limits |
| Concurrency | No limit | One module request at a time per user; at most 2 analyses and 8 website checks at once |
| Rate limits | None | Per user and per IP (see below) |
| Headers | CSP and friends | The same, plus `Strict-Transport-Security: max-age=63072000; includeSubDomains` (`; preload` only when `KESTRIX_HSTS_PRELOAD=1`), `upgrade-insecure-requests` in the CSP, and `Cache-Control: no-store` on every `/api/` response |
| API schema | `/api/openapi.json` | Not served |
| Logs | uvicorn's access log | A privacy-safe access line per request; uvicorn's access log is off |

## Configuration

All settings come from environment variables, which on a hosting platform should come from its secret store. The server refuses to start, with a message naming the variable, if a required value is missing or malformed.

| Variable | Required | Meaning |
| --- | --- | --- |
| `KESTRIX_MODE` | No | `local` (default) or `hosted`. `kestrix serve-hosted` forces `hosted`. |
| `KESTRIX_PUBLIC_ORIGIN` | Yes | The public origin, such as `https://kestrix.example.org`. Must be `https://`, with no path, query or credentials. |
| `KESTRIX_SESSION_PEPPER` | Yes | A secret of at least 32 bytes. Keys the refresh-token, CSRF and `state` hashes. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Changing it signs everyone out. |
| `KESTRIX_JWT_SECRET` | Yes | A different secret of at least 32 bytes that signs the access tokens (HS256, [ADR 0007](adr/0007-jwt-access-and-rotating-refresh-tokens.md)). Generate it the same way: `python -c "import secrets; print(secrets.token_urlsafe(48))"` (64 characters, 48 random bytes). It must differ from the pepper. |
| `KESTRIX_JWT_SECRET_PREVIOUS` | No | The previous `KESTRIX_JWT_SECRET` during a rotation, at least 32 bytes. Accepted only to verify access tokens; new tokens use `KESTRIX_JWT_SECRET`. Remove it 15 minutes after the rotation, when the last old token has expired. |
| `KESTRIX_HISTORY_KEY` | Yes | Exactly 32 random bytes, base64-encoded: the AES-256-GCM key for stored result reports ([ADR 0008](adr/0008-per-user-result-history.md)). Generate it with `python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`. Losing it makes stored reports unreadable (they are then treated as missing); nothing else is affected. |
| `KESTRIX_HISTORY_KEY_PREVIOUS` | No | The previous `KESTRIX_HISTORY_KEY` during a rotation. Used only to decrypt reports stored under it; new reports use `KESTRIX_HISTORY_KEY`. Every row records the id of its key (a keyed hash of the key), so both keys work side by side. Remove it 30 days after the rotation, when the last report under the old key has expired. |
| `KESTRIX_GOOGLE_CLIENT_ID`, `KESTRIX_GOOGLE_CLIENT_SECRET` | One provider | Google sign-in. Enabled only when both are set; setting just one is an error. |
| `KESTRIX_GITHUB_CLIENT_ID`, `KESTRIX_GITHUB_CLIENT_SECRET` | One provider | GitHub sign-in, with the same rule. |
| `KESTRIX_DB` | No | SQLite file. Default: `hosted.sqlite3` in the config directory (`$KESTRIX_HOME`, else `~/.config/kestrix`). Put it on a persistent volume. The result history goes in a second file beside it, with `-history` added to the name (`hosted-history.sqlite3`, or `/data/kestrix-history.db` for `/data/kestrix.db`). |
| `KESTRIX_LOG_SALT` | No | At least 16 bytes. Salt for the user-id hash in logs. Default: derived from the pepper. |
| `KESTRIX_ABUSE_CONTACT` | No | Printable ASCII, at most 200 characters, such as `abuse@kestrix.example.org`. Added to the website check's `User-Agent`. |
| `KESTRIX_CLIENT_IP_HEADER` | No | A header your platform's proxy always overwrites with the client address, such as `Fly-Client-IP`; used for per-IP sign-in limits. Cannot be combined with `KESTRIX_TRUST_PROXY_HEADERS`. See [deploy.md](deploy.md#client-ips-and-rate-limits). |
| `KESTRIX_HSTS_PRELOAD` | No | `1` adds `preload` to the HSTS header. Off by default: the preload list covers the whole registrable domain and every subdomain and is slow to undo, so it is the owner's decision ([deploy.md](deploy.md#go-live-checklist)). |
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
export KESTRIX_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export KESTRIX_HISTORY_KEY="$(python -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
export KESTRIX_GOOGLE_CLIENT_ID=... KESTRIX_GOOGLE_CLIENT_SECRET=...
export KESTRIX_DB=/data/kestrix/hosted.sqlite3
kestrix serve-hosted            # listens on 0.0.0.0:$PORT (default 8000)
```

Hosted mode needs the `hosted` extra (`pip install 'kestrix[hosted]'`, which adds PyJWT and `cryptography`); the container image includes it. Without it, `serve-hosted` refuses to start and says so. Local mode never imports it.

`serve-hosted` is a separate command rather than a `dashboard --hosted` flag. `dashboard` is built for one person on loopback: it opens a browser, defaults to `127.0.0.1`, and treats `--host` as an extra allowed name. Hosted mode needs none of that, binds every interface, and takes its allowed host from `KESTRIX_PUBLIC_ORIGIN`. Keeping the two apart means a typo in a local command cannot start the public service, and `kestrix dashboard` refuses to run when `KESTRIX_MODE=hosted` is set.

`serve-hosted` expects TLS to end at the platform's proxy in front of it. uvicorn's proxy-header handling is off, and so is its access log, which would record query strings (OAuth codes and `state`) and client addresses.

The browser flow:

1. The page calls `GET /api/auth/providers` and links to `GET /api/auth/login/{provider}?next=/app`, adding `&intent=signup` from the Sign up tab once the visitor has ticked the terms checkbox.
2. After sign-in, the provider returns to `/api/auth/callback/{provider}`, which sets the access and refresh cookies and redirects to `next` (default `/app`). An account created through Log in (no `intent=signup`) gets `welcome=created` added to `next`, and the dashboard shows a one-time note linking to the terms. Any failure redirects to `/welcome?signin=failed`.
3. The page calls `GET /api/auth/me` for the user, the `csrf_token` and `access_expires_at`, and sends the token as `X-CSRF-Token` on every `POST`, `PUT`, `PATCH` and `DELETE`.
4. About a minute before `access_expires_at`, while the tab is visible, the page calls `POST /api/auth/refresh`. A request that gets 401 `token_expired` refreshes once (one refresh at a time, across tabs too) and is retried once; if the refresh fails, the page goes to `/signin`. A page opened after the access cookie lapsed gets `refreshable` from `/api/auth/me` and refreshes first.

Routes and status codes are in [api.md](api.md#hosted-mode).

## Security properties

- **Browser hardening.** Every response, including refusals, carries a Content-Security-Policy with `script-src 'self'` and `style-src 'self'` (no `'unsafe-inline'`, no `'unsafe-eval'`), `object-src 'none'`, `frame-src 'none'`, `base-uri 'none'`, `form-action 'self'` and `frame-ancestors 'none'`; `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, and a `Permissions-Policy` that turns off every powerful feature. The dashboard needs none of the relaxations: it has no inline script or style, and React sets styles through the CSSOM. Files under `/assets/` carry a content hash and are served `immutable`; `index.html` is `no-cache`; a missing bundle file is a 404, never the page. There is no CORS: no response carries an `Access-Control-*` header, and a preflight gets 405. The code is in [`server/headers.py`](../src/kestrix/server/headers.py); [`scripts/deploy_preflight.py`](../scripts/deploy_preflight.py) re-checks it on a real deployment.
- **Generic errors.** An unexpected exception is a JSON 500 `unexpected error` (only the exception type is logged). A request body that fails validation is a 422 that names the field (`loc`, `type`, `msg`) but, unlike FastAPI's default, does not echo the rejected value, so a mistyped secret or another person's upload field never comes back in a response.
- **Audit log.** `kestrix.auth` writes one line for each sign-in (provider, salted user hash, whether the account is new), sign-out, account deletion, refused refresh, detected refresh-token reuse and failed sign-in (a fixed reason code). Sign-in, sign-out and account deletion carry the salted user hash; refusals carry only a fixed reason code. No line holds an email, name, provider id, token or IP address.
- **Sign-in.**
  - OAuth 2.0 authorization code with PKCE (S256), a random `state`, and for Google an OpenID Connect `nonce`.
  - The pending attempt (provider, PKCE verifier, nonce, `next`) is stored server-side under a keyed hash of `state`, expires after 10 minutes, and is deleted on first use, so a `state` works once.
  - The `state` is also set in a 10-minute `__Host-kx_login` cookie and must match on the callback. This ties the callback to the browser that started sign-in, which blocks login CSRF (an attacker pasting their own callback link).
  - A sign-in start that another site loads without a top-level navigation (an image, script, frame or `fetch`: `Sec-Fetch-Site: cross-site` without `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`) is refused with 403 before it is counted or stored, so a page cannot use up its visitors' sign-in allowance.
  - A disabled account (see [Abuse handling](#abuse-handling)) cannot sign in: the callback redirects to `/welcome?signin=failed` and logs `reason=account_disabled`.
- **Google identity.**
  - The ID token comes straight from Google's token endpoint over verified TLS, in exchange for the code and the client secret. OpenID Connect Core 1.0, section 3.1.3.7, lets a client in this position rely on TLS instead of checking the token's signature, and Kestrix does that.
  - It still checks the claims: `iss` is `https://accounts.google.com` or `accounts.google.com`; `aud` is the client ID (with several audiences, `azp` must be the client ID too); `exp` is in the future; `iat` is within the last 15 minutes, allowing 5 minutes of clock skew; `nonce` matches the attempt; `email_verified` is `true`.
- **GitHub identity.** The access token is used once for `GET /user` and `GET /user/emails`. Sign-in needs an email that is both primary and verified. The access token is not stored.
- **Outbound requests.** Only to `accounts.google.com`, `oauth2.googleapis.com`, `github.com` and `api.github.com`, over `https` on port 443, with certificate verification, no redirects, no environment proxies, a 10-second timeout and a 64 KiB response cap. These are fixed provider hosts, so `netguard`'s private-address check is not used for them; the allowlist is the control.
- **Accounts.** Users are keyed by `(provider, subject)`. The table holds the verified email, display name, two timestamps, when the terms were accepted (`terms_accepted_at`, for an account created through Sign up) and, for a disabled account, when it was disabled. No passwords and no provider tokens. User ids are never reused (`AUTOINCREMENT`).
- **Access tokens** ([ADR 0007](adr/0007-jwt-access-and-rotating-refresh-tokens.md), [`server/tokens.py`](../src/kestrix/server/tokens.py)).
  - A JWT signed with HS256 under `KESTRIX_JWT_SECRET`, with a `kid` header (a keyed hash of the secret). Claims: `iss` (the public origin), `aud` (`kestrix`), `sub` (the user id), `sid` (the refresh family), `iat`, `nbf`, `exp` (15 minutes) and `jti`; all are required.
  - Verified with PyJWT with `algorithms=["HS256"]` pinned, so `alg: none`, HS384/HS512 and public-key algorithms are refused; an unknown `kid` is refused. The time claims allow 30 seconds of leeway.
  - Cookie: `__Host-kx_at`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age=900`, no `Domain`.
  - Every authenticated request then checks that the `sid` family is live and belongs to `sub`, through an in-process cache of at most 30 seconds per family. Logout, account deletion and reuse detection update the cache at once; a change made by another process (such as `kestrix hosted disable-user`) applies within 30 seconds.
  - An expired token (or a missing one while a refresh cookie is present) gives 401 `token_expired`; a missing or invalid one gives 401 `sign_in_required`.
- **Refresh tokens.**
  - 256 random bits (`secrets.token_urlsafe(32)`). The database stores only HMAC-SHA256(pepper, token), so a copy of the database cannot be replayed as cookies.
  - Cookie: `__Host-kx_rt`, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, `Max-Age` up to the family's 30-day end, no `Domain`. `__Host-` requires `Path=/`, so the cookie is sent to every route; `SameSite=Strict` and the CSRF check on refresh cover that.
  - A sign-in creates a family (`sid`). Each `POST /api/auth/refresh` rotates the refresh token and issues a new access token. A family ends 30 days after sign-in or 7 days after its last refresh.
  - Presenting a refresh token that was already rotated revokes the whole family and logs `refresh token reuse detected; family revoked user=<user hash>`.
  - Signing in again revokes the family named by the browser's refresh cookie. Ended families are purged when someone signs in.
  - A disabled account's families are revoked and refused.
- **CSRF.**
  - The token is derived from the family's `sid` with the pepper, returned by `/api/auth/me`, never stored, and compared in constant time. It stays the same across refreshes.
  - It is required on every state-changing request from a signed-in user, and on `POST /api/auth/refresh` and `POST /api/auth/logout` (checked against the family named by the refresh cookie when the access token has expired), on top of the existing `Origin` / `Sec-Fetch-Site` refusal, which compares against the public origin.
- **Route gating.** Every `/api/` route is private unless it is on a short public list: health, providers, `me`, `refresh`, `logout`, `login` and `callback`. The OpenAPI schema is not served. A route added later is private by default. Detection repair, Bitcoin and the Anthropic-key settings are not mounted and return 404.
- **Website check.**
  - Public targets only: `allow_private: true` is refused with 400, and `netguard` still applies to every hop.
  - Each scan needs `"authorized": true`, the user's confirmation that they own or are authorized to test the site.
  - The `User-Agent` names Kestrix and, if set, `KESTRIX_ABUSE_CONTACT`.
  - Only ports 80 and 443, on the first request and on every redirect, and one generic `target_unreachable` message for every connection-level failure, so the check cannot map open ports.
  - A whole-site scan (the default; `"scope": "site"`) sends at most 65 GET requests and 1 TLS handshake: up to 50 pages (the start page, links, sitemap pages and six common login addresses) plus 15 extra requests for the sitemap and redirects, one at a time, 150 ms apart, within 60 seconds after the start page. Each page's fetch, DNS lookups included, has 10 seconds, enforced on every socket operation; the TLS handshake has its own 10 seconds. Every discovered page passes the same public-address and port rules as the start page; a redirect to another site is not followed. A `"scope": "page"` scan sends at most 6 requests (the first and up to 5 redirects). A scan counts once against the hourly limit and the concurrency gate. Whole-site scans also have their own limit of 5 per user per hour, so one account can cause at most about 5 x 65 + 15 x 6 = 415 requests per hour to the sites it names.
- **Uploads.** At most 10 MiB per file or message, refused while the body arrives. The multipart parser keeps an upload in memory up to 1 MiB and spills larger ones to an anonymous temporary file (Starlette's `SpooledTemporaryFile`, in `/tmp`), which is deleted when the request ends. Files and messages are never stored, and reports are not kept on the server.
- **Analyses run in worker processes** ([`server/isolation.py`](../src/kestrix/server/isolation.py)). Each email check, file analysis and URL analysis runs in a fresh process forked from a fork server that was started with only `PATH`, locale, time-zone and temp-directory variables, so workers never see the pepper, the JWT secrets or client secrets; `kestrix serve-hosted` also removes the secret variables (`KESTRIX_SESSION_PEPPER`, `KESTRIX_JWT_SECRET`, `KESTRIX_JWT_SECRET_PREVIOUS`, `KESTRIX_HISTORY_KEY`, `KESTRIX_HISTORY_KEY_PREVIOUS`, `KESTRIX_LOG_SALT`, the client secrets) from its own environment once the settings are loaded, so a restarted fork server cannot inherit them either. A worker gets the input bytes and options, and returns JSON that the server validates against the report model (never a pickle). Limits: 10 seconds of CPU (`RLIMIT_CPU`), 384 MiB of address space on Linux (`RLIMIT_AS`; macOS does not enforce it), no core dumps, and 20 seconds of wall-clock time, after which the worker is killed. A stopped analysis returns 422 `analysis_timeout`; one that runs out of memory returns 413 `input_too_large`. In a container test a worker for a worst-case 9.9 MiB email peaked at 170 MiB RSS, about 70 MiB of it shared with the fork server.
- **Concurrency.** One website check or analysis at a time per user (a second one gets 429 `busy`), and at most 2 analyses and 8 website checks across the service (then 503 `busy`). Both answer at once with `Retry-After: 5` and do not count against the hourly limits; requests never wait in a queue or hold a worker thread, so health checks and pages stay responsive.
- **Result history** ([ADR 0008](adr/0008-per-user-result-history.md), [`server/history.py`](../src/kestrix/server/history.py)).
  - After a 200 response from an analysis route, the response body (the report) is stored for the signed-in user. The request body is never read by the recorder, so uploaded files and messages are not stored; a mail report never carries the message body (only the subject, the sender and short evidence such as a matched cue phrase of at most 60 characters).
  - Each row: a random 128-bit id, the user id, the tool, the time, the unencrypted list summary (verdict, grade or highest severity, and the number of findings) and the report encrypted with AES-256-GCM under `KESTRIX_HISTORY_KEY`, with a random 96-bit nonce and the row id, user id and tool as associated data, so a ciphertext moved to another row or user fails to decrypt. A row that cannot be decrypted is answered as 404.
  - Kept 30 days: older rows are deleted on every write and at start-up and are never listed. Users can delete one or all results, or turn history off (`PUT /api/settings/history`), which deletes theirs and stops recording. Account deletion deletes the user's history and setting.
  - A separate SQLite file beside `KESTRIX_DB`, created `0600`, with `secure_delete` and a WAL checkpoint after bulk deletions. Another user's id answers 404, like a missing one. Writes need the CSRF header and are limited to 120 per user per hour.
  - Logs record only the tool and the report size (`history stored tool=… bytes=…`), never report content.
- **Logs.** One `kestrix.access` line per request: method, route template (`/api/auth/callback/{provider}`, never the query string), status, duration in ms, and the first 16 hex characters of HMAC-SHA256(log salt, user id). For unmatched paths, the path (without query) is logged instead of a template. Failed sign-ins add a `kestrix.auth` line with a fixed reason code, such as `id_token_wrong_audience`. Each website check adds a `kestrix.webcheck` line, `webcheck user=<user hash> host=<host hash>`, where the host hash is the first 16 hex characters of HMAC-SHA256(log salt, lower-cased host name); see [Abuse handling](#abuse-handling). An unexpected error logs `unexpected error <exception type> on <method>` and never a traceback, which could quote someone's upload. Bodies, file names, emails, URLs or host names being checked, cookies and tokens are never logged.
- **Database file.** Created `0600`, in a directory created or tightened to `0700` when Kestrix owns it. All queries are parameterized. Deleted rows are overwritten (`PRAGMA secure_delete=ON`), and deleting an account also checkpoints and truncates the write-ahead log, so the email does not linger in the database files (volume snapshots keep it until they expire; see [deploy.md](deploy.md#backups)). A database created by an earlier preview of hosted mode, without `AUTOINCREMENT` ids, the `disabled_at` or `terms_accepted_at` columns, or the refresh-family columns of ADR 0007, is refused at start-up with exit code 2 and a message: stop the service, move the file and its `-wal` and `-shm` files aside, and start again. Users sign in again to recreate their accounts.

## Abuse handling

Operator commands read the same `KESTRIX_*` variables as `kestrix serve-hosted`, so run them where the service runs, for example `fly ssh console -C "kestrix hosted disable-user --email someone@mail.example"`. They never print secrets.

| Command | What it does |
| --- | --- |
| `kestrix hosted disable-user --email ADDRESS` | Disables every account with that email (any provider, case-insensitive): it can no longer sign in, and its refresh families are revoked (a running server notices within 30 seconds). Exit code 1 if no account matches. |
| `kestrix hosted enable-user --email ADDRESS` | Lets those accounts sign in again. |
| `kestrix hosted hash-host HOST` | Prints the host hash that `kestrix.webcheck` log lines carry for a host name or URL, such as one named in an abuse report. Search the logs for it to find the user hash, and so the account, that checked it. |

The host hash changes when `KESTRIX_LOG_SALT` changes (or, without it, the pepper), so hash a reported host with the salt that was in use when the log line was written.

## Limitations

- **Single instance.** Rate limits are kept in process memory. With more than one instance or worker, each keeps its own counters, so the effective limit is multiplied by the instance count. Run one instance until a shared store is added. The limiter keeps at most 100,000 keys. Above that it drops keys with no hit inside their window, then the least recently requested ones, until 10% of the room is free; a key that is blocked right now is dropped only when nothing else is left. Dropping a live key resets its counter. A restart resets every counter.
- **SQLite.** One file on a persistent volume, fine for one instance. It is reached through a small repository class (`server/store.py`) so Postgres can replace it.
- **Rate limits** (all return 429 `rate_limited` with `Retry-After`):

  | What | Limit | Counted per |
  | --- | --- | --- |
  | `POST /api/webcheck` | 20 per hour; of those, at most 5 whole-site scans | User |
  | `POST /api/forensics/file`, `/api/forensics/url`, `/api/mail/analyze` (one shared bucket) | 120 per hour | User |
  | `DELETE /api/history`, `DELETE /api/history/{id}`, `PUT /api/settings/history` (one shared bucket) | 120 per hour | User |
  | `GET /api/auth/login/{provider}` | 20 per 10 minutes | Client IP (IPv6: its /64) |
  | `GET /api/auth/callback/{provider}` | 10 per 10 minutes | Client IP (IPv6: its /64) |
  | `POST /api/auth/refresh` | 60 per 10 minutes | Client IP (IPv6: its /64) |

- **Client IP behind a proxy.** By default the client IP is the socket peer, which behind a platform proxy is the proxy itself, so every visitor shares one sign-in limit. Set `KESTRIX_TRUST_PROXY_HEADERS=1` only when a proxy you control always appends the real client address to `X-Forwarded-For`. Kestrix then uses the right-most entry. Without such a proxy the header is attacker-controlled.
- **Not yet in this slice.** The reviewed (non-draft) privacy notice and terms belong to a later slice of ADR 0004. The container image is in [deploy.md](deploy.md).
- **Worker processes and the entry point.** Python's `multiprocessing` re-runs the server's entry script in each analysis worker, so the hosted server must be started from an import-safe entry point (`kestrix serve-hosted`, or any script with an `if __name__ == "__main__":` guard). Workers are a fork server's children, so they need `/tmp` for its socket.
- **Uploads can touch disk.** An upload over 1 MiB is spooled to an anonymous file in `/tmp` while it is processed. On Fly.io `/tmp` is on the machine's root disk, not a tmpfs (see [deploy.md](deploy.md)).
- **Refresh families are purged opportunistically.** An ended family is refused at once, and its row stays until the next sign-in purges it.
- **Revocation across processes.** The 30-second family cache is per process. With one instance that only matters for operator commands; a second instance would need a shared revocation store.
- **`GET` routes with side effects.** `login` stores a pending attempt and `callback` creates a refresh family. Both are needed for OAuth and both are rate-limited.
