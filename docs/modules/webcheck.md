# Website check

The website check grades how well a site protects its visitors at the connection and browser level: HTTPS, the TLS certificate, security headers and cookie flags. Use it on a site you own or are authorized to assess, after a deploy or a hosting change, or to get a concrete fix list for a small site. It sends one GET request (following up to five redirects) and makes one TLS handshake. It does not crawl, fuzz, log in or scan ports, so it cannot find application bugs such as SQL injection.

Each problem comes with a recommendation, and the result is an A to F grade from a fixed rubric. Source files are under [`src/kestrix/webcheck/`](../../src/kestrix/webcheck/).

## Command

```bash
kestrix webcheck scan https://your-site.example
kestrix webcheck scan http://192.168.1.20:8080 --allow-private   # a lab host you own
kestrix webcheck scan https://your-site.example --json
kestrix webcheck scan https://your-site.example --site-type dynamic   # it has a login the page doesn't show
```

| Option | Effect |
| --- | --- |
| `--allow-private` | Allows targets that resolve to private, loopback, link-local or other non-public addresses. Off by default. |
| `--json` | Prints the full report as JSON and skips the notice line. |
| `--site-type static\|static_api\|dynamic` | Declares what you know the site is. It can raise the detected profile, never lower it (see [Site profile](#site-profile)). |

| Exit code | Meaning ([`cli.py`](../../src/kestrix/webcheck/cli.py)) |
| --- | --- |
| 0 | The check completed. A poor grade still exits 0. |
| 2 | The URL or target was rejected: `invalid_url` or `target_not_allowed`. |
| 3 | The target could not be reached: `target_unreachable` or `upstream_error`. |

The text output starts with the notice "Only check websites you own or are authorized to assess", then prints the final URL, grade, score, TLS status and each finding with its fix.

## What the check sends

The fetch logic is in [`fetch.py`](../../src/kestrix/webcheck/fetch.py).

- **Target validation.** Every hop, including each redirect, passes [`core/netguard.py`](../../src/kestrix/core/netguard.py):
  - only `http` and `https` URLs with a host, at most 2,048 characters, with no credentials in the URL;
  - every resolved address must be public unless `--allow-private` is set. This refuses private, loopback, link-local (which includes cloud metadata at 169.254.169.254), multicast and reserved ranges, including IPv4 addresses embedded in IPv6 forms.
- **Connect to the validated IP.** The request goes to the first validated address in sorted order. The `Host` header and TLS SNI carry the real hostname, so a DNS answer that changes between the check and the connection cannot redirect the request.
- **One GET per hop.** The request has `User-Agent: kestrix-webcheck/<version>`, no proxy settings from the environment, and certificate verification on. It asks for an uncompressed response (`Accept-Encoding: identity`) and reads raw bytes, so nothing is decompressed. At most 1 MiB of the final page is kept for the [site profile](#site-profile); bodies of redirect hops are discarded.
- **Redirects.** Up to 5 redirects (301, 302, 303, 307, 308) are followed. More than that fails with `upstream_error`.
- **Time limit.** 10 seconds for the whole redirect chain, and 10 seconds for the TLS probe.
- **TLS probe.** When the final URL is `https`, one more verified handshake is made against the same validated IP. It records the protocol version, issuer, expiry date and days remaining.

If the HTTPS connection fails during the TLS handshake, the report still comes back with `status_code: null` and `headers_checked: false`, and only the HTTPS and TLS checks are applied.

## Site profile

A missing CSP or framing protection matters most where there is something to steal or click: logins, forms, sessions and API calls. On a static page the same gaps are real but carry less risk. Before grading, the check profiles the site from the page it already fetched ([`profile.py`](../../src/kestrix/webcheck/profile.py)):

| Profile | Assigned when |
| --- | --- |
| `dynamic` | Accounts or sessions: the page has a password field or sets a cookie. |
| `static_api` | A backend but no accounts: a data-entry form (a contact form, say), inline scripts that call APIs (`fetch`, XHR, `axios`, `/api/`, GraphQL, WebSockets), or a JSON response. |
| `static` | Pages only: none of the above. |

The parser is Python's `html.parser`. It runs on at most 1 MiB, never executes anything, and counts only tags, attributes and short markers in inline scripts, capped at 200,000 characters. The report's `profile` field lists the evidence and the reasons. The evidence covers forms, password and input fields, cookies, inline and external scripts, third-party script hosts, iframes and API markers.

**How severities change.** A few findings depend on what the site does. Their severity is re-weighed for the profile, and only ever lowered:

| Finding | static | static_api | dynamic |
| --- | --- | --- | --- |
| `csp.missing`, `csp.report_only`, `csp.no_script_restriction` | low (stays medium if scripts load from a third-party host) | unchanged | unchanged |
| `framing.unprotected` | info | low | unchanged |
| `referrer.weak` | info | unchanged | unchanged |

Every other finding keeps its checklist severity on every profile, including all HTTPS, TLS, HSTS and cookie findings. A re-weighed finding keeps its original severity in `baseline_severity`, and `context` explains the change.

**Limits and the owner's declaration.** One page cannot show everything: a login behind a link, or API calls made by an external bundle, are invisible to it. With `--site-type` (or `site_type` in the API, or the "What is this site?" field in the dashboard) the owner can say what the site really is. A declaration can raise the profile but never lower it below what the page shows. Declaring `static` on a page with a password field keeps `dynamic`, and the report says so. A page therefore cannot be argued into a better grade.

## Grading rubric

The rubric is in [`grade.py`](../../src/kestrix/webcheck/grade.py):

1. Start at 100.
2. Subtract 25 per `high`, 10 per `medium` and 4 per `low` finding. `info` findings cost nothing. The score does not go below 0.
3. Map the score to a letter: A at 90 or above, B at 80, C at 70, D at 60, otherwise F.
4. Force the grade to F when the final URL is not HTTPS or the TLS status is not `ok`, whatever the score. Every other protection depends on an intact connection.

The rubric is a summary for prioritizing fixes. It is not a compliance rating.

## Findings

Every finding has `id`, `severity`, `title`, `explanation`, `recommendation` and, where useful, `evidence` (header values cut to 200 characters). Cookie findings name the cookie but never echo its value. The checks are in [`checks.py`](../../src/kestrix/webcheck/checks.py).

### HTTPS and TLS

| `id` | Severity | Raised when |
| --- | --- | --- |
| `https.not_used` | high | The final URL is plain HTTP. |
| `tls.expired` | high | The certificate has expired. |
| `tls.not_yet_valid` | high | The certificate's start date is in the future. |
| `tls.hostname_mismatch` | high | The certificate does not list this hostname. |
| `tls.untrusted` | high | The certificate chain is not trusted, for example self-signed or incomplete. |
| `tls.outdated_protocol` | high | The server offers only TLS older than 1.2. |
| `tls.handshake_failed` | high | The TLS handshake failed for another reason. |
| `tls.expiring_soon` | medium | The certificate expires in fewer than 14 days. |

### Headers

| `id` | Severity | Raised when |
| --- | --- | --- |
| `hsts.missing` | medium | HTTPS response without `Strict-Transport-Security`. |
| `hsts.short_max_age` | low | HSTS `max-age` is missing or under 15,552,000 seconds (180 days). |
| `hsts.disabled` | medium | HSTS `max-age=0`, which switches HSTS off. No other HSTS finding is reported. |
| `hsts.no_subdomains` | info | HSTS lacks `includeSubDomains`. |
| `hsts.not_preload_ready` | info | HSTS has `includeSubDomains` but not a `max-age` of at least one year together with `preload`, so it does not qualify for the [preload list](https://hstspreload.org). |
| `csp.missing` | medium | Neither `Content-Security-Policy` nor `Content-Security-Policy-Report-Only`. |
| `csp.report_only` | medium | Only `Content-Security-Policy-Report-Only` is sent. It reports violations but does not block anything. |
| `csp.no_script_restriction` | medium | A CSP is enforced but has neither `script-src` nor `default-src`, so it gives no protection against injected scripts. For example, a policy with only `frame-ancestors`. |
| `csp.unsafe_inline` | low | The effective script sources (`script-src`, or `default-src` when there is no `script-src`) allow `'unsafe-inline'` without a nonce or hash. Browsers ignore `'unsafe-inline'` when a nonce or hash is present. |
| `csp.unsafe_eval` | low | The effective script sources allow `'unsafe-eval'`. |
| `csp.wildcard_source` | low | The effective script sources allow `*`, `http:`, `https:` or `data:`, and do not use `'strict-dynamic'`, which makes browsers ignore host and scheme sources. |
| `csp.object_src_open` | low | Neither `object-src 'none'` nor `default-src 'none'`, so plugins (`<object>`, `<embed>`) are not blocked. |
| `csp.base_uri_missing` | info | No `base-uri`, so an injected `<base>` tag can redirect relative script URLs. |
| `framing.unprotected` | medium | Neither `X-Frame-Options: DENY` or `SAMEORIGIN`, nor a CSP `frame-ancestors` directive in any enforced policy. |
| `xcto.missing` | low | `X-Content-Type-Options` is not `nosniff`. |
| `referrer.weak` | low | `Referrer-Policy` is missing, `unsafe-url` or `no-referrer-when-downgrade`. |
| `permissions_policy.missing` | info | No `Permissions-Policy`. |
| `coop.missing` | info | No `Cross-Origin-Opener-Policy`. |

The HSTS checks run only for HTTPS responses.

A browser enforces every CSP it receives: several `Content-Security-Policy` headers, or comma-separated policies in one header. A CSP weakness is therefore reported only when every enforced policy has it. The CSP checks follow the [CSP Level 3](https://www.w3.org/TR/CSP3/) rules for nonces, hashes and `'strict-dynamic'`.

### Information disclosure

| `id` | Severity | Raised when |
| --- | --- | --- |
| `disclosure.server_version` | low | The `Server` header contains a version number such as `nginx/1.25.3`. |
| `disclosure.powered_by` | low | An `X-Powered-By` header is present. |

### Cookies

These checks run on every `Set-Cookie` header of the final response.

| `id` | Severity | Raised when |
| --- | --- | --- |
| `cookie.no_secure` | medium | HTTPS site and the cookie lacks `Secure`. |
| `cookie.no_httponly` | low | The cookie lacks `HttpOnly`. This is acceptable only when JavaScript must read the cookie. |
| `cookie.no_samesite` | low | The cookie has no `SameSite` attribute. |
| `cookie.samesite_none_insecure` | medium | `SameSite=None` without `Secure`. |
| `cookie.prefix_violation` | medium | A `__Secure-` cookie without `Secure`, or a `__Host-` cookie without `Secure`, with a `Domain`, or with a `Path` other than `/`. Browsers drop such cookies. The prefixes are matched case-insensitively. |

## Report fields

| Field | Content |
| --- | --- |
| `notice` | The authorization notice. |
| `requested_url`, `final_url` | The URL you gave, and the URL after redirects. |
| `status_code` | HTTP status of the final response, or `null` when the handshake failed. |
| `headers_checked` | Whether header and cookie checks ran. |
| `redirect_chain` | One entry per hop: `url`, `address` (the IP connected to), `status_code`, `elapsed_ms`. |
| `tls` | `host`, `status`, `detail`, `protocol`, `issuer`, `not_after`, `days_remaining`. `status` is `ok`, `not_https`, `expired`, `not_yet_valid`, `hostname_mismatch`, `untrusted`, `outdated_protocol` or `handshake_failed`. |
| `grade`, `score` | The letter and the 0 to 100 score. |
| `findings` | Sorted high, medium, low, info. |
| `timings` | `total_ms`, `http_ms`, `tls_ms`. |
| `profile` | `kind` (the profile used for grading), `detected`, `declared`, `reasons` and `evidence`. `null` when headers were not checked. |

## Limits

- One response is checked. Headers set only on other pages, or only for logged-in users, are not seen.
- TLS is checked once, with httpx's default verified client context. The check does not enumerate cipher suites or every protocol version the server accepts.
- Only the first resolved address is contacted. Sites behind several addresses or a CDN may answer differently elsewhere.
- `--allow-private` removes the address protections for that run. Use it only for hosts you control.
- Certificate revocation (OCSP or CRL) is not checked.

## How the checks are verified

- **Header and cookie checks:** `tests/webcheck` holds a table of known-bad header sets. Each set is served through a full scan, with the network mocked, and the scan must report exactly the expected findings. These run in CI.
- **Certificate and TLS checks:** `uv run python scripts/webcheck_conformance.py` scans [badssl.com](https://badssl.com) endpoints: expired, wrong host, self-signed, untrusted root, TLS 1.0, plain HTTP and HSTS. It checks each result. It needs the network, so it is not part of CI. On 2026-10-14, all 8 endpoints gave the expected result. A client whose OpenSSL disables TLS 1.0 reports `tls-v1-0.badssl.com` as `handshake_failed` rather than `outdated_protocol`.
- **Comparison with other scanners:** to look for gaps, scan 10 to 20 sites you are allowed to test with this tool, [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) and [securityheaders.com](https://securityheaders.com). Then compare the findings. Each tool uses its own rubric, so compare the findings, not the letter grades. Wherever the tools disagree, one of them has a bug or makes a different judgment.
