# Website check finding ids (`kestrix webcheck scan URL --json`)

Each finding has `id`, `severity`, `title`, `explanation`, `recommendation` (the fix the tool itself
gives; prefer quoting it), `evidence` (header values cut to 200 characters; cookie values are never
echoed), and `baseline_severity` / `context` when the severity was lowered for the site profile.
Source: `src/kestrix/webcheck/checks.py`. The Fix column repeats the tool's recommendation.
In a whole-site scan (the default) each id appears once, at its most severe, with `pages` (where it was seen, at most 20) and
`pages_total`; HTTPS and TLS findings are about the whole site and carry no page list.

## Grade

Start at 100; subtract 25 per high, 10 per medium, 4 per low (info is free); floor 0. A at 90+, B 80+,
C 70+, D 60+, otherwise F. The grade is forced to F when the final URL is not HTTPS or `tls.status` is not
`ok`. It is a prioritization aid, not a compliance rating.

## Site profile

`profile.kind` is `static`, `static_api` or `dynamic` (a sign-in field, meaning a password, one-time-code or passkey field or a form posting from a login address, or a cookie on any checked page; in a whole-site scan the
most sensitive page sets it and `profile.decided_by` names it). On `static` sites
`csp.missing`, `csp.report_only` and `csp.no_script_restriction` drop to low (they stay medium when scripts
load from a third-party host) and `framing.unprotected` and `referrer.weak` drop to info; on `static_api`
`framing.unprotected` drops to low. Nothing else changes. `--site-type` can raise the profile, never lower it. A single-page scan (`--page-only`) judges that page only.

## HTTPS and TLS

| `id` | Severity | Raised when | Fix |
| --- | --- | --- | --- |
| `https.not_used` | high | The final URL is plain HTTP. | Serve the site over HTTPS (for example a free Let's Encrypt certificate) and redirect HTTP to HTTPS. |
| `tls.expired` | high | The certificate has expired. | Renew the certificate; enable automatic renewal. |
| `tls.not_yet_valid` | high | The certificate's start date is in the future. | Check the server clock and the certificate's start date. |
| `tls.hostname_mismatch` | high | The certificate does not list this hostname. | Issue a certificate that lists this exact hostname. |
| `tls.untrusted` | high | The certificate chain is not trusted, for example self-signed or incomplete. | Use a certificate from a public CA and serve the full chain. |
| `tls.outdated_protocol` | high | The server offers only TLS older than 1.2. | Enable TLS 1.2 and 1.3; disable TLS 1.0/1.1. |
| `tls.handshake_failed` | high | The TLS handshake failed for another reason. | Check the server's TLS configuration. |
| `tls.expiring_soon` | medium | The certificate expires in fewer than 14 days. | Renew now and automate renewal. |

## Headers

| `id` | Severity | Raised when | Fix |
| --- | --- | --- | --- |
| `hsts.missing` | medium | HTTPS response without `Strict-Transport-Security`. | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| `hsts.short_max_age` | low | HSTS `max-age` is missing or under 15,552,000 seconds (180 days). | Use `max-age` of at least 15552000 (180 days); 31536000 is common. |
| `hsts.disabled` | medium | HSTS `max-age=0`, which switches HSTS off. No other HSTS finding is reported. | `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| `hsts.no_subdomains` | info | HSTS lacks `includeSubDomains`. | Add `includeSubDomains` once every subdomain supports HTTPS. |
| `hsts.not_preload_ready` | info | HSTS has `includeSubDomains` but not a `max-age` of at least one year together with `preload`, so it does not qualify for the [preload list](https://hstspreload.org). | If every subdomain is HTTPS-only, add `preload` and submit the domain at hstspreload.org. |
| `csp.missing` | medium | Neither `Content-Security-Policy` nor `Content-Security-Policy-Report-Only`. | Start with `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'` and tighten. |
| `csp.report_only` | medium | Only `Content-Security-Policy-Report-Only` is sent. It reports violations but does not block anything. | Once the reports are clean, send the same policy as `Content-Security-Policy`. |
| `csp.no_script_restriction` | medium | A CSP is enforced but has neither `script-src` nor `default-src`, so it gives no protection against injected scripts. For example, a policy with only `frame-ancestors`. | Add a script-src, ideally nonce-based: `script-src 'nonce-<random>' 'strict-dynamic'; object-src 'none'; base-uri 'none'`. |
| `csp.unsafe_inline` | low | The effective script sources (`script-src`, or `default-src` when there is no `script-src`) allow `'unsafe-inline'` without a nonce or hash. Browsers ignore `'unsafe-inline'` when a nonce or hash is present. | Use nonces or hashes for the inline scripts you need and drop `'unsafe-inline'`. |
| `csp.unsafe_eval` | low | The effective script sources allow `'unsafe-eval'`. | Remove `'unsafe-eval'` and replace eval-style code. |
| `csp.wildcard_source` | low | The effective script sources allow `*`, `http:`, `https:` or `data:`, and do not use `'strict-dynamic'`, which makes browsers ignore host and scheme sources. | List the exact hosts that serve your scripts, or use nonces with `'strict-dynamic'`. |
| `csp.object_src_open` | low | Neither `object-src 'none'` nor `default-src 'none'`, so plugins (`<object>`, `<embed>`) are not blocked. | Add `object-src 'none'`. |
| `csp.base_uri_missing` | info | No `base-uri`, so an injected `<base>` tag can redirect relative script URLs. | Add `base-uri 'none'` (or `'self'`). |
| `framing.unprotected` | medium | Neither `X-Frame-Options: DENY` or `SAMEORIGIN`, nor a CSP `frame-ancestors` directive in any enforced policy. | `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: DENY`). |
| `xcto.missing` | low | `X-Content-Type-Options` is not `nosniff`. | `X-Content-Type-Options: nosniff` |
| `referrer.weak` | low | `Referrer-Policy` is missing, `unsafe-url` or `no-referrer-when-downgrade`. | `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`). |
| `permissions_policy.missing` | info | No `Permissions-Policy`. | Disable unused features, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`. |
| `coop.missing` | info | No `Cross-Origin-Opener-Policy`. | `Cross-Origin-Opener-Policy: same-origin` if the site does not rely on cross-origin popups. |

## Information disclosure

| `id` | Severity | Raised when | Fix |
| --- | --- | --- | --- |
| `disclosure.server_version` | low | The `Server` header contains a version number such as `nginx/1.25.3`. | Remove the version from the `Server` header (for example nginx `server_tokens off;`). |
| `disclosure.powered_by` | low | An `X-Powered-By` header is present. | Remove the `X-Powered-By` header. |

## Cookies

| `id` | Severity | Raised when | Fix |
| --- | --- | --- | --- |
| `cookie.no_secure` | medium | HTTPS site and the cookie lacks `Secure`. | Add the `Secure` attribute. |
| `cookie.no_httponly` | low | The cookie lacks `HttpOnly`. This is acceptable only when JavaScript must read the cookie. | Add `HttpOnly` to session and authentication cookies. |
| `cookie.no_samesite` | low | The cookie has no `SameSite` attribute. | Add `SameSite=Lax` (or `Strict`). |
| `cookie.samesite_none_insecure` | medium | `SameSite=None` without `Secure`. | Add `Secure`, or use `SameSite=Lax`. |
| `cookie.prefix_violation` | medium | A `__Secure-` cookie without `Secure`, or a `__Host-` cookie without `Secure`, with a `Domain`, or with a `Path` other than `/`. Browsers drop such cookies. The prefixes are matched case-insensitively. | Set `Secure`, and for `__Host-` also `Path=/` and no `Domain` attribute. |

## A starting header set

Adapt it to the site. A CSP that is too strict breaks pages, so suggest trying it as
`Content-Security-Policy-Report-Only` first.

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: session=<value>; Path=/; Secure; HttpOnly; SameSite=Lax
```

`tls.status` values: `ok`, `not_https`, `expired`, `not_yet_valid`, `hostname_mismatch`, `untrusted`,
`outdated_protocol`, `handshake_failed`.
