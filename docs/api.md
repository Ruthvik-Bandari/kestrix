# HTTP API

`kestrix dashboard` starts a local HTTP server that serves the dashboard and a JSON API on `http://localhost:8765`. Use the API when you want to script Kestrix from another program on the same machine, or to see exactly what the dashboard sends. The API calls the same functions as the CLI, so results match. It has no accounts or tokens: it is meant for one user on their own computer, and it refuses requests that do not come from a loopback address name.

The machine-readable schema is served at `GET /api/openapi.json`. To browse it, open it in any OpenAPI viewer. For example, run `npx @redocly/cli preview-docs http://localhost:8765/api/openapi.json`, or paste a saved copy into editor.swagger.io. This page adds what the schema cannot express: error behavior, size limits and the local-only rules. Routes are defined in [`server/app.py`](../src/kestrix/server/app.py) and each module's `api.py`.

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
| `Content-Security-Policy` | `default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `X-Frame-Options` | `DENY` |
| `Cross-Origin-Opener-Policy` | `same-origin` |

## Errors

Kestrix errors use one envelope:

```json
{"reason": "invalid_url", "detail": "the URL is empty"}
```

`reason` is a stable machine-readable code (the `Reason` enum in [`core/errors.py`](../src/kestrix/core/errors.py)); `detail` is a human-readable message. Status codes:

| Status | `reason` |
| --- | --- |
| 400 | Any rejected input not listed below, for example `invalid_input`, `invalid_url`, `invalid_rule`, `unsupported_modifier`, `invalid_mapping`, `invalid_fixture`, `malformed_yaml`, `engine_error`, `index_count_mismatch` |
| 403 | `target_not_allowed`, and `cross_site_request` from the middleware |
| 404 | `not_found`, for an unknown path under `/api/` |
| 413 | `input_too_large` |
| 421 | `host_not_allowed` |
| 502 | `upstream_error`, `target_unreachable` |
| 503 | `engine_unavailable`, `ai_key_missing`, and `dashboard_not_built` for page requests when the dashboard bundle is missing |

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
| `POST /api/webcheck` | `{"url": string (1 to 2,048 characters), "allow_private": bool = false, "site_type": "static" \| "static_api" \| "dynamic" \| null = null}` | `Report`: `notice`, `requested_url`, `final_url`, `status_code`, `headers_checked`, `redirect_chain`, `tls`, `grade`, `score`, `findings` (each may carry `baseline_severity` and `context`), `timings`, `profile` |

A target that resolves to a non-public address returns 403 `target_not_allowed` unless `allow_private` is true. Connection failures and timeouts return 502 `target_unreachable`; too many redirects and other HTTP failures return 502 `upstream_error`.

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
| `POST /api/mail/analyze` | `multipart/form-data` with one file field named `file` (the raw `.eml` bytes); no other fields. Optional query parameters: `protected_domain` (repeatable, at most 20, each a host name) and `trusted_authserv_id` (repeatable, at most 5). | `MailReport`: `schema_version`, `notice`, `sha256`, `subject`, `from_address`, `verdict`, `heuristic_score`, `findings` (each with `id`, `analyzer`, `severity`, `title`, `explanation`, `evidence`), `counts` |

```bash
curl -s -F file=@message.eml 'http://127.0.0.1:8765/api/mail/analyze?protected_domain=example-bank.com'
```

- A body that is not `multipart/form-data`, has no `file` field, or has extra fields returns 400 `invalid_input`.
- The body is counted while it streams, and the request is refused with 413 `input_too_large` once it passes 25 MiB plus 64 KiB of multipart overhead.
- Input that is not an email message, or an invalid query parameter, returns 400 `invalid_input`. MIME nesting deeper than 10 levels returns 400 `nesting_too_deep`; too many parts or headers, or an oversized header, return 413 `input_too_large`.
- The report never contains the message body, link text or attachment bytes.
