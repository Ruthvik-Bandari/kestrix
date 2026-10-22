# HTTP API

`kestrix dashboard` starts a local HTTP server that serves the dashboard and a JSON API on `http://localhost:8765`. Use the API when you want to script Kestrix from another program on the same machine, or to see exactly what the dashboard sends. The API calls the same functions as the CLI, so results match. It has no accounts or tokens: it is meant for one user on their own computer, and it refuses requests that do not come from a loopback address name.

The machine-readable schema is served at `GET /api/openapi.json` (by the local server only; the hosted service does not publish it). To browse it, open it in any OpenAPI viewer. For example, run `npx @redocly/cli preview-docs http://localhost:8765/api/openapi.json`, or paste a saved copy into editor.swagger.io. This page adds what the schema cannot express: error behavior, size limits and the local-only rules. Routes are defined in [`server/app.py`](../src/kestrix/server/app.py) and each module's `api.py`.

## Contents

- [Quick example](#quick-example)
- [Local-only protections](#local-only-protections)
- [Errors](#errors)
- [Platform routes](#platform-routes)
- [Detection repair](#detection-repair)
- [Forensics](#forensics)
- [Website check](#website-check)
- [Bitcoin](#bitcoin)
- [Mail](#mail)
- [Result history](#result-history)
- [Hosted mode](#hosted-mode)

## Quick example

```bash
curl -s http://127.0.0.1:8765/api/health
# {"status":"ok","version":"0.1.0","modules":["detect","forensics","webcheck","bitcoin","mail"]}

curl -s -X POST http://127.0.0.1:8765/api/forensics/url \
  -H 'content-type: application/json' \
  -d '{"url": "http://paypa1-login.example.top/verify"}'
```

Clients outside a browser, such as `curl` or Python `httpx`, send no `Origin` or `Sec-Fetch-Site` header, so the cross-site rule does not affect them.

## Local-only protections

Every request passes the `_LocalOnly` middleware in [`server/app.py`](../src/kestrix/server/app.py) before it reaches a route. The checks run in this order.

**1. Host allowlist (HTTP 421).** The `Host` header, with its port removed, must be `127.0.0.1`, `localhost` or `[::1]`. A web page that uses DNS rebinding to point its own name at 127.0.0.1 still sends its own name in `Host`, so it is refused. If you start the dashboard with `--host` set to another interface, that one name is added to the allowlist.

```json
{"reason": "host_not_allowed", "detail": "Kestrix only serves local requests"}
```

**2. Cross-site write refusal (HTTP 403).** For every method except `GET`, `HEAD` and `OPTIONS`, a request is refused when either of these holds:

- `Sec-Fetch-Site` is present and is not `same-origin` or `none`;
- `Origin` is present and its host is not in the allowlist.

This blocks cross-site "simple" requests, such as an HTML form posting a multipart upload, which browsers send without a CORS preflight. The server sends no CORS headers, so other origins cannot read API responses either.

```json
{"reason": "cross_site_request", "detail": "requests from other websites are not allowed"}
```

**3. Body size cap (HTTP 413).** The declared `Content-Length` must be a number no larger than the route's limit:

| Route | Limit |
| --- | --- |
| `POST /api/detect/run` | 60 MiB (62,914,560 bytes) |
| `POST /api/forensics/file` | 51 MiB (53,477,376 bytes); the file itself is limited to 50 MiB while it streams |
| `POST /api/mail/analyze` | 26 MiB (27,262,976 bytes); the message itself is limited to 25 MiB while it streams |
| Every other route | 1 MiB (1,048,576 bytes) |

```json
{"reason": "input_too_large", "detail": "request body exceeds 1048576 bytes"}
```

Bodies sent with chunked transfer encoding and no `Content-Length` are counted as they stream in and refused with the same 413 once they pass the limit.

**Security headers.** Every response, including refusals, carries:

| Header | Value |
| --- | --- |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `X-Frame-Options` | `DENY` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Permissions-Policy` | every powerful feature (camera, microphone, geolocation, payment, USB and the like) switched off with `()` |

## Errors

Kestrix errors use one envelope:

```json
{"reason": "invalid_url", "detail": "the URL is empty"}
```

`reason` is a stable machine-readable code (the `Reason` enum in [`core/errors.py`](../src/kestrix/core/errors.py)); `detail` is a human-readable message. Status codes:

| Status | `reason` |
| --- | --- |
| 400 | Any rejected input not listed below, for example `invalid_input`, `invalid_url`, `invalid_rule`, `unsupported_modifier`, `invalid_mapping`, `invalid_fixture`, `malformed_yaml`, `engine_error`, `index_count_mismatch` |
| 401 | `sign_in_required`, `token_expired` (hosted mode only) |
| 403 | `target_not_allowed`, `cross_site_request` from the middleware, and `csrf_failed` (hosted mode only) |
| 404 | `not_found`, for an unknown path under `/api/` |
| 413 | `input_too_large` |
| 421 | `host_not_allowed` |
| 422 | `analysis_timeout` (hosted mode only): the analysis was stopped at its CPU or time limit |
| 429 | `rate_limited` and `busy` (hosted mode only), with a `Retry-After` header in seconds |
| 500 | `internal_error`, for an unexpected server error; `detail` is always `unexpected error` and the security headers are still sent |
| 502 | `upstream_error`, `target_unreachable` |
| 503 | `engine_unavailable`, `ai_key_missing`, `busy` (hosted mode only, when the service-wide cap is reached), and `dashboard_not_built` for page requests when the dashboard bundle is missing |

**Validation errors (422).** A request body that does not fit the route's schema (a missing field, a wrong type, a string over its `max_length`, an unknown key where extras are forbidden) gets FastAPI's standard response instead of the envelope:

```json
{"detail": [{"type": "missing", "loc": ["body", "url"], "msg": "Field required", "input": {}}]}
```

**Outcomes are not errors.** Detection repair outcomes such as `abstained`, `unsupported` or `engine_unavailable` come back as HTTP 200 with the outcome in the report body.

## Platform routes

| Route | Request | Response |
| --- | --- | --- |
| `GET /api/health` | none | `{"status": "ok", "version": "0.1.0", "modules": ["detect", "forensics", "webcheck", "bitcoin", "mail"]}` |
| `GET /api/settings` | none | `{"anthropic_key_configured": bool}`. The key itself is never returned. |
| `PUT /api/settings/anthropic-key` | `{"key": string \| null}`; a string must be 20 to 512 characters | `204 No Content`. `null` removes the stored key. |
| `GET /api/openapi.json` | none | The OpenAPI schema. |

Any other `GET` path outside `/api/` serves the dashboard's static files, falling back to `index.html` for client-side routes.

## Detection repair

Semantics, limits and report fields are in [`docs/modules/detect.md`](modules/detect.md). Routes are in [`detect/api.py`](../src/kestrix/detect/api.py). The engine URL comes from `KESTRIX_ES_URL` (default `http://127.0.0.1:9200`).

| Route | Request | Response |
| --- | --- | --- |
| `GET /api/detect/engine` | none | `reachable`, `version` (or `null`), `pinned_version` (`"8.19.3"`), `pinned`, `image` |
| `GET /api/detect/cases` | none | Array of case manifests: `case_id`, `provenance`, `split`, `title`, `root_id`, `fault`, `expected` |
| `POST /api/detect/cases/{case_id}/run` | none | The [workflow report](modules/detect.md#report-and-evidence-json) plus `case` (the manifest). An unknown `case_id` returns 400 `invalid_input`. |
| `POST /api/detect/parse` | `{"rule": string}` (at most 102,400 characters) | `title`, `id`, `sha256`, `fields`, `condition` (canonical text), `selections` (`{name: [[{field, modifier, values, match_all}, ...], ...]}`: each selection is a list of alternative maps, each map a list of predicates). A rule outside the subset returns 400 with its reason code. |
| `POST /api/detect/run` | See below | The workflow report. |

`POST /api/detect/run` body:

| Field | Type | Limit |
| --- | --- | --- |
| `rule` | string, required | 102,400 characters |
| `mapping` | string, required | 102,400 characters |
| `development` | string, required: labeled JSONL | 26,214,400 characters |
| `validation` | string or `null`: labeled JSONL | 26,214,400 characters |
| `healthy_rule` | string or `null` | 102,400 characters |
| `healthy_mapping` | string or `null` | 102,400 characters |

The fixture texts are written to a private temporary directory, loaded through the same size-checked loader as CLI files, and deleted after the run.

An engine that is down when the run starts gives HTTP 200 with `"outcome": "engine_unavailable"`. An engine that goes down during the run gives HTTP 503 `engine_unavailable`.

## Forensics

Routes are in [`forensics/api.py`](../src/kestrix/forensics/api.py). Field-level descriptions are in the OpenAPI schema (`FileReport`, `UrlReport`); behavior is in [`docs/modules/forensics.md`](modules/forensics.md).

| Route | Request | Response |
| --- | --- | --- |
| `POST /api/forensics/file` | `multipart/form-data` with one file field named `file`; no other fields | `FileReport` |
| `POST /api/forensics/url` | `{"url": string}` | `UrlReport`. The URL is never visited. |

```bash
curl -s -F file=@suspicious.bin http://127.0.0.1:8765/api/forensics/file
```

For uploads:

- A body that is not `multipart/form-data`, or has no `file` field, returns 400 `invalid_input`.
- The body is counted while it streams, and the request is refused with 413 once it passes 50 MiB plus 64 KiB of multipart overhead.
- The file is held in an anonymous spooled temporary file: memory first, then an unnamed temporary file. It is read and never executed.

## Website check

The route is in [`webcheck/api.py`](../src/kestrix/webcheck/api.py); behavior and the grading rubric are in [`docs/modules/webcheck.md`](modules/webcheck.md).

| Route | Request | Response |
| --- | --- | --- |
| `POST /api/webcheck` | `{"url": string (1 to 2,048 characters), "allow_private": bool = false, "site_type": "static" \| "static_api" \| "dynamic" \| null = null, "scope": "site" \| "page" = "site"}` | `Report`: `notice`, `requested_url`, `final_url`, `status_code`, `headers_checked`, `redirect_chain`, `tls`, `grade`, `score`, `findings` (each may carry `baseline_severity`, `context`, and in a whole-site scan `pages` and `pages_total`), `timings`, `profile`, `scope`, `pages`, `requests_sent`, `limits_reached`, `links_skipped`, `sitemap_entries` |

A target that resolves to a non-public address returns 403 `target_not_allowed` unless `allow_private` is true. A host name that is not a valid DNS name returns 400 `invalid_url`. `scope: "site"` (the default) checks up to 50 pages, with at most 15 extra requests and 60 seconds for the pages after the start page; `scope: "page"` sends one GET plus redirects ([what is sent and never done](modules/webcheck.md#whole-site-scan)). Only a failure of the start page is an error response; a page that fails is listed in `pages`. Connection failures, DNS failures and timeouts of the start page (its fetch has 10 seconds) return 502 `target_unreachable`; too many redirects, a broken response and other HTTP failures return 502 `upstream_error`.

## Bitcoin

Routes are in [`bitcoin/api.py`](../src/kestrix/bitcoin/api.py); behavior is in [`docs/modules/bitcoin.md`](modules/bitcoin.md). The request models forbid unknown keys.

| Route | Request | Response |
| --- | --- | --- |
| `POST /api/bitcoin/scan` | `{"addresses": [string] (1 to 100, each at most 200 characters), "lookup_chain": bool = false, "testnet": "testnet4" \| "signet" = "testnet4"}` | `ScanResult`: `results` (each with `input`, `address_type`, `network`, `risk`, `key_exposure`, `explanation`, `recommendation`, `chain_activity`) and `summary` (`total`, `by_risk`) |
| `GET /api/bitcoin/migration/{address_type}` | Path: `P2PK`, `P2PKH`, `P2SH`, `P2WPKH`, `P2WSH` or `P2TR`, any case | `MigrationPlan`: `address_type`, `urgency`, `summary`, `steps`, `cautions` |
| `POST /api/bitcoin/guardian` | `{"message": string (1 to 2,000 characters)}` | `GuardianResult`: `intent`, `addresses`, `ignored_addresses`, `address_type`, `model_summary`, `next_step`, `model` |

- An invalid address returns 400 `invalid_input` naming its position, for example `address #2`.
- With `lookup_chain: true`, the hash-based addresses are sent to mempool.space. A lookup failure returns 502 `upstream_error`.
- The guardian returns 503 `ai_key_missing` when no key is configured or the `[ai]` extra is not installed, and 502 `upstream_error` for Anthropic API failures. The key is checked after the body is validated. `model_summary` is unverified model text.

## Mail

The route is in [`mail/api.py`](../src/kestrix/mail/api.py); checks, verdict rules and limits are in [`docs/modules/mail.md`](modules/mail.md). Analysis is offline: links are not visited and attachments are not opened.

| Route | Request | Response |
| --- | --- | --- |
| `POST /api/mail/analyze` | `multipart/form-data` with one file field named `file` (the raw `.eml` bytes); no other fields. Optional query parameters: `protected_domain` (repeatable, at most 20, each a host name; used for display-name and look-alike checks) and `trusted_authserv_id` (repeatable, at most 5). | `MailReport`: `schema_version`, `notice`, `sha256`, `subject`, `from_address`, `verdict`, `heuristic_score`, `findings` (each with `id`, `analyzer` (`auth`, `sender`, `lookalike`, `links`, `attachments` or `intent`), `severity`, `title`, `explanation`, `evidence`), `counts` |

```bash
curl -s -F file=@message.eml 'http://127.0.0.1:8765/api/mail/analyze?protected_domain=example-bank.com'
```

- A body that is not `multipart/form-data`, has no `file` field, or has extra fields returns 400 `invalid_input`.
- The body is counted while it streams, and the request is refused with 413 `input_too_large` once it passes 25 MiB plus 64 KiB of multipart overhead.
- Input that is not an email message, or an invalid query parameter, returns 400 `invalid_input`. MIME nesting deeper than 10 levels, or a header nested too deeply to parse (such as thousands of nested comments), returns 400 `nesting_too_deep`; too many parts or headers, an oversized header or header block, or a `Content-Type` or `Content-Disposition` with more than 50 parameters return 413 `input_too_large`.
- The report never contains the message body, link text or attachment bytes. The one exception is an `intent` finding, whose evidence is the matched cue phrase (at most 60 characters).

## Result history

Both modes keep the report of each successful analysis for 30 days ([ADR 0008](adr/0008-per-user-result-history.md)): `POST /api/mail/analyze` (tool `mail`), `POST /api/webcheck` (`webcheck`), `POST /api/forensics/file` (`forensics_file`) and `POST /api/forensics/url` (`forensics_url`). Only the JSON response is kept, never the request: uploaded files and messages are not stored. Failed requests (any status other than 200) and responses over 2 MiB are not recorded. Locally there is one user and the history is plaintext in `history.sqlite3` in the config folder (`0600`); on the hosted service each signed-in user has their own, encrypted at rest (AES-256-GCM).

`verdict` is a short summary for lists: the mail `verdict`, the website `grade` (`A` to `F`), the URL `level`, or for a file the highest finding severity (`high`, `medium`, `low`, `info`) or `none`. `findings` is the number of findings.

| Route | Request | Response |
| --- | --- | --- |
| `GET /api/history` | Optional `?page=` (from 1, default 1) and `?per_page=` (1 to 50, default 20) | `{"enabled": bool, "retention_days": 30, "page", "per_page", "total", "items": [{"id": string, "tool": string, "created_at": epoch seconds, "verdict": string, "findings": int}]}`, newest first. Results older than 30 days are never listed. `per_page` over 50 gives 422. |
| `GET /api/history/{id}` | none | The item's fields plus `"report"`: the report exactly as the analysis returned it. 404 `not_found` for an unknown, expired or undecryptable id, and for another user's. |
| `DELETE /api/history/{id}` | none | 204, or 404 `not_found` as above. |
| `DELETE /api/history` | none | 204. Deletes all of the caller's results. |
| `PUT /api/settings/history` | `{"enabled": bool}` (unknown keys refused, 422) | `{"enabled": bool}`. History is on by default; `false` deletes every stored result and stops recording until it is turned on again. |

Results older than 30 days are deleted whenever a result is stored and when the server starts.

## Hosted mode

With `KESTRIX_MODE=hosted` (or `kestrix serve-hosted`) the server is a public, signed-in service. Setup, security properties and limits are in [hosted.md](hosted.md). Everything above still applies, with these differences:

- **Host and origin.** `Host` must be the host of `KESTRIX_PUBLIC_ORIGIN` (no loopback names), else 421. On state-changing requests, `Origin`, when sent, must equal `KESTRIX_PUBLIC_ORIGIN` exactly, else 403 `cross_site_request`.
- **Headers.** Every response also carries `Strict-Transport-Security: max-age=63072000; includeSubDomains` (plus `; preload` when the owner sets `KESTRIX_HSTS_PRELOAD=1`) and `upgrade-insecure-requests` in its CSP, and every `/api/` response carries `Cache-Control: no-store`. A 422 validation error names the field but omits `input` and `ctx`, so a rejected value is never echoed.
- **No API schema.** `GET /api/openapi.json` is not served (401 without a session, 404 with one).
- **Not served.** `/api/detect/*`, `/api/bitcoin/*`, `/api/settings` and `/api/settings/*` return 404 `not_found` for every method, signed in or not, except `PUT /api/settings/history` (see [Result history](#result-history)).
- **Sign-in required.** Every `/api/` route except `GET /api/health` and the `/api/auth/*` routes marked public below needs a valid access token (the `__Host-kx_at` cookie, [ADR 0007](adr/0007-jwt-access-and-rotating-refresh-tokens.md)). Without one it returns 401 with one of two reasons:
  - `token_expired`: the access token has expired (its signature and claims are otherwise valid), or it is missing while a `__Host-kx_rt` refresh cookie is present. Call `POST /api/auth/refresh` once, then retry.
  - `sign_in_required`: no usable token (missing, forged, wrong key, issuer or audience, a revoked or ended family). Sign in again.
- **CSRF.** A signed-in `POST`, `PUT`, `PATCH` or `DELETE`, and every `POST /api/auth/refresh`, must send `X-CSRF-Token` with the token from `GET /api/auth/me`, else 403 `csrf_failed`. The token stays the same across refreshes.
- **Rate limits.** 429 `rate_limited` with `Retry-After`: 20 website checks per user per hour; 120 analyses (forensics file and URL, mail) per user per hour; 120 result-history changes (`DELETE /api/history*`, `PUT /api/settings/history`) per user per hour; 20 sign-in starts, 10 callbacks and 60 refreshes per client IP (IPv6: per /64) per 10 minutes.
- **One request at a time.** A user's second website check or analysis while the first is still running gets 429 `busy` with `Retry-After: 5`. When the service already runs 2 analyses or 8 website checks, the next one gets 503 `busy` with `Retry-After: 5`. Neither counts against the hourly limits, and nothing is queued.
- **Uploads.** `POST /api/forensics/file` and `POST /api/mail/analyze` accept at most 10 MiB of file or message (10 MiB plus 64 KiB of request body); more gives 413 `input_too_large`.
- **Analyses run in a worker process** with 10 seconds of CPU, 384 MiB of address space (on Linux) and 20 seconds of wall-clock time. An analysis stopped by these limits returns 422 `analysis_timeout`; one that runs out of memory returns 413 `input_too_large`.
- **Sign-in from other sites.** `GET /api/auth/login/{provider}` with `Sec-Fetch-Site: cross-site` is refused with 403 `cross_site_request` unless it is a top-level navigation (`Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`); refused requests do not count against the limit.
- **Health.** `GET /api/health` adds `"mode": "hosted"` and lists only `["forensics", "webcheck", "mail"]`.
- **Website check.** `POST /api/webcheck` also takes `"authorized": bool` and refuses unknown keys. `authorized` must be `true` ("I own or am authorized to test this site") and `allow_private` must be `false`; otherwise 400 `invalid_input`. `scope` is accepted as in local mode. Only ports 80 and 443 can be checked, on the first request, every redirect and every page of a whole-site scan (403 `target_not_allowed` for the start page; a later page is listed as `blocked`), and every connection failure, timeout or broken response is reported as 502 `target_unreachable` with the detail `the site could not be reached`.

| Route | Public | Request | Response |
| --- | --- | --- | --- |
| `GET /api/auth/providers` | Yes | none | `{"providers": ["google", "github"]}`: the providers configured on this server |
| `GET /api/auth/login/{provider}` | Yes | Optional `?next=` a same-origin path starting with `/` (not `//`, no backslashes, control characters or spaces); anything else is ignored. Optional `intent=signup` from the Sign up tab; any other value means log in | 302 to the provider's authorization page, with a 10-minute `__Host-kx_login` cookie. An unknown or disabled provider gives 404. |
| `GET /api/auth/callback/{provider}` | Yes | The provider's `code` and `state` | 303 to `next` (default `/app`) with the `__Host-kx_at` (access, 15 minutes) and `__Host-kx_rt` (refresh) cookies. A new account created with `intent=signup` records `terms_accepted_at`; one created without it gets `welcome=created` added to `next`. Any failure gives 303 to `/welcome?signin=failed` with no detail. |
| `GET /api/auth/me` | Yes | none | `{"signed_in": true, "user": {"display_name", "email", "provider"}, "csrf_token": string, "access_expires_at": epoch seconds}`; without a usable access token but with a live refresh family, `{"signed_in": false, "refreshable": true, "csrf_token": string}`; else `{"signed_in": false}`. Never rotates anything. Sent with `Cache-Control: no-store`. |
| `POST /api/auth/refresh` | Yes | `X-CSRF-Token`; the `__Host-kx_rt` cookie | 200 `{"access_expires_at": epoch seconds}` with new `__Host-kx_at` and `__Host-kx_rt` cookies (the refresh token rotates). 403 `csrf_failed` without the family's token. 401 `sign_in_required`, clearing both cookies, for a missing, unknown or ended family, or for a refresh token that was already rotated, which also revokes its whole family. |
| `POST /api/auth/logout` | Yes | none; `X-CSRF-Token` when there is a family to end (from the access token, else the refresh cookie) | 204. Revokes the refresh family, so its access tokens stop working at once, and clears both cookies. |
| `DELETE /api/auth/account` | No | `X-CSRF-Token` | 204. Deletes the user, every refresh family of that user, their result history and history setting, and their rate-limit counters, then clears both cookies. |

```json
{"reason": "sign_in_required", "detail": "sign in to use this feature"}
{"reason": "token_expired", "detail": "your sign-in needs refreshing; call POST /api/auth/refresh"}
{"reason": "csrf_failed", "detail": "missing or invalid X-CSRF-Token header"}
{"reason": "rate_limited", "detail": "too many requests; try again in 1200 seconds"}
{"reason": "busy", "detail": "your previous check is still running; try again when it finishes"}
{"reason": "analysis_timeout", "detail": "the analysis took too long and was stopped; the input may be too complex to check here"}
```
