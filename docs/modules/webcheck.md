# Website check

The website check grades how well a site protects its visitors at the connection and browser level: HTTPS, the TLS certificate, security headers and cookie flags. Use it on a site you own or are authorized to assess, after a deploy or a hosting change, or to get a concrete fix list for a small site. By default it checks the whole site: up to 50 read-only GET requests to the page you name, the pages it links to, the pages in its sitemap and six common login addresses, plus one TLS handshake. With `--page-only` ("Just this page") it sends one GET request (following up to five redirects) and one TLS handshake. It never submits a form, logs in, follows a link to another site, fuzzes or scans ports, so it cannot find application bugs such as SQL injection.

Each problem comes with a recommendation, and the result is an A to F grade from a fixed rubric. Source files are under [`src/kestrix/webcheck/`](../../src/kestrix/webcheck/).

## Command

```bash
kestrix webcheck scan https://your-site.example
kestrix webcheck scan http://192.168.1.20:8080 --allow-private   # a lab host you own
kestrix webcheck scan https://your-site.example --page-only   # only the page you name, as before
kestrix webcheck scan https://your-site.example --json
kestrix webcheck scan https://your-site.example --site-type dynamic   # it has a login the scan can't find
```

| Option | Effect |
| --- | --- |
| `--allow-private` | Allows targets that resolve to private, loopback, link-local or other non-public addresses. Off by default. |
| `--page-only` | Checks only the page you name (one GET plus redirects). The default is the whole site, up to 50 pages (see [Whole-site scan](#whole-site-scan)). |
| `--json` | Prints the full report as JSON and skips the notice line. |
| `--site-type static\|static_api\|dynamic` | Declares what you know the site is. It can raise the detected profile, never lower it (see [Site profile](#site-profile)). |

| Exit code | Meaning ([`cli.py`](../../src/kestrix/webcheck/cli.py)) |
| --- | --- |
| 0 | The check completed. A poor grade still exits 0. |
| 2 | The URL or target was rejected: `invalid_url` or `target_not_allowed`. |
| 3 | The target could not be reached: `target_unreachable` or `upstream_error`. |

The text output starts with the notice for the chosen scope ("Only check websites you own or are authorized to assess" and what will be sent), then prints the final URL, grade, score, TLS status, for a whole-site scan how many pages were checked and which limit was hit, and each finding with its fix and the number of pages it was seen on.

## What the check sends

The fetch logic is in [`fetch.py`](../../src/kestrix/webcheck/fetch.py). This section describes one page request (the start page, or each page of a whole-site scan); [Whole-site scan](#whole-site-scan) adds discovery and limits.

- **Target validation.** Every hop, including each redirect, passes [`core/netguard.py`](../../src/kestrix/core/netguard.py):
  - only `http` and `https` URLs with a host, at most 2,048 characters, with no credentials in the URL;
  - every resolved address must be public unless `--allow-private` is set. This refuses private, loopback, link-local (which includes cloud metadata at 169.254.169.254), multicast and reserved ranges, including IPv4 addresses embedded in IPv6 forms.
- **Connect to the validated IP.** The request goes to the first validated address in sorted order. The `Host` header and TLS SNI carry the real hostname, so a DNS answer that changes between the check and the connection cannot redirect the request.
- **One GET per hop.** The request has `User-Agent: kestrix-webcheck/<version>`, no proxy settings from the environment, and certificate verification on. It has no body, no credentials and no cookie: the HTTP client's cookie jar is replaced by a policy that accepts and returns nothing, so a `Set-Cookie` is read for the cookie checks but never sent back, not even to the next hop of a redirect chain. It asks for an uncompressed response (`Accept-Encoding: identity`) and reads raw bytes, so nothing is decompressed. At most 1 MiB of the final page is kept for the [site profile](#site-profile); bodies of redirect hops are discarded.
- **Redirects.** Up to 5 redirects (301, 302, 303, 307, 308) are followed. More than that fails with `upstream_error`.
- **Time limit.** 10 seconds for the whole redirect chain, DNS lookups included. Every socket operation's timeout is capped at the time left, so a server that sends its response a byte at a time cannot hold the check open. The TLS probe has its own 10 seconds for connect and handshake together. A single-page scan therefore takes at most about 20 seconds and sends at most 6 requests (the first plus 5 redirects) and 1 TLS handshake.
- **On the hosted service** only ports 80 and 443 can be checked, on the first request and on every redirect, and every connection-level failure (refused, reset, timeout, a non-HTTP answer) is reported with the same message, so the check cannot be used to map which ports are open.
- **TLS probe.** When the final URL is `https`, one more verified handshake is made against the same validated IP. It records the protocol version, issuer, expiry date and days remaining.

If the HTTPS connection fails during the TLS handshake, the report still comes back with `status_code: null` and `headers_checked: false`, and only the HTTPS and TLS checks are applied.

## Whole-site scan

The default scope is `site`; `page` (`--page-only`, `"scope": "page"`) keeps the single-request behavior above. Discovery and fetching are in [`crawl.py`](../../src/kestrix/webcheck/crawl.py).

**The site** is exactly the scheme, host and port of the start page's final URL (after its redirects). Another host, another port, `http` versus `https`, and a subdomain are all "another site" and are never requested.

**Discovery order**, stable and de-duplicated (fragments dropped, relative links resolved, query strings kept):

1. the `<a href>` links of the start page, in document order (at most 1,000 read);
2. `/sitemap.xml` (one GET), its `<loc>` addresses (at most 500 read). A sitemap index is not followed: its entries end in `.xml` and are skipped;
3. six common login addresses, tried with one GET each, whether or not anything links to them: `/login`, `/signin`, `/admin`, `/admin/login`, `/account`, `/wp-login.php`. They are listed in the report with `found_via: "probe"` (or the link or sitemap that already named them). When there are more candidates than room, the six probes keep their slots.

Skipped without a request, and counted in `links_skipped`: links to other sites, ports or schemes, `mailto:`, `tel:` and `javascript:` links, URLs over 2,048 characters, and files that are not web pages (images, PDFs, archives, styles, scripts, fonts, media, `.json`, `.xml`, `.txt`, `.csv`, office files).

| Limit | Value |
| --- | --- |
| Pages (first GET to each: the start page, linked and sitemap pages, login probes) | 50. Reaching it reports `page_cap` in `limits_reached`. |
| Extra GETs (the sitemap and every redirect hop, the start page's included) | 15. Running out reports `request_budget`; the redirect that was not followed is shown on its page. |
| Most requests in one scan | 65 GETs and 1 TLS handshake. |
| Time for the crawl after the start page and TLS check | 60 seconds; reaching it reports `deadline` and no further pages are requested. Each page has its own 10 seconds (or the time left, if less). |
| Pause between requests | 150 ms. |
| One response read | 1 MiB; a longer page is checked on its first 1 MiB. |
| Requests at the same time | 1 (strictly sequential). |

**What a page result says.** Each requested page appears in `pages` with its path, how it was found (`start`, `link`, `sitemap`, `probe`), an `outcome`, the HTTP status and, when it was checked, its own kind and finding ids:

| `outcome` | Meaning |
| --- | --- |
| `checked` | A 2xx HTML response; its headers, cookies and profile were evaluated. The start page is always `checked` when it answered, whatever its status, as in a single-page scan. |
| `not_html` | A 2xx response that is not HTML (JSON, an image served without an extension, and so on). |
| `http_error` | A 4xx, 5xx or a redirect without a target. |
| `redirects_off_site` | The page redirects to another scheme, host or port. The redirect is not followed and the other site is never contacted. |
| `blocked` | The address failed the private-address or port rule on this request (for example the name now resolves to a private address). |
| `failed` | Connection error, timeout or TLS failure on that page, or the redirect limit. |
| `duplicate` | The page redirected to a page that was already checked; it is not evaluated twice. |

A page that fails never stops the scan; only a failure of the start page behaves as in a single-page scan (`target_unreachable` and the other rejections).

**Evaluation.** Every `checked` page gets the header, cookie, CSP and disclosure checks. Findings are merged by `id`: the most severe instance (the first on a tie) supplies the text, and the finding lists the paths it was seen on (`pages`, at most 20, in crawl order) and `pages_total`. HTTPS and TLS findings belong to the whole site and carry no page list. The grade is computed from the merged findings, so each problem counts once at its worst and the weakest page sets the grade. The HSTS, TLS and cookie rules are unchanged.

**What is never done.** No form is submitted, no login is attempted, no request but GET is sent, and none carries a body, credentials, a `Referer` or a cookie. No link to another site is followed and no page is fetched that was not found by the three sources above. Every request and redirect hop passes `check_url` with the same private-address rule as the start page; on the hosted service also the ports 80 and 443 rule and the generic error message. HTML is read with `html.parser` and the sitemap with `str.find` over `<loc>` tags: no XML parser runs, so no entity or DTD is ever resolved.

## Site profile

A missing CSP or framing protection matters most where there is something to steal or click: logins, forms, sessions and API calls. On a static page the same gaps are real but carry less risk. Before grading, the check profiles the site from the pages it already fetched ([`profile.py`](../../src/kestrix/webcheck/profile.py)):

| Profile | Assigned when |
| --- | --- |
| `dynamic` | Accounts or sessions: a page has a sign-in field or sets a cookie. A sign-in field is a password field; a field whose `autocomplete` names `current-password`, `new-password`, `one-time-code` or `webauthn`; a field named `otp`, `totp`, `mfa`, `2fa`, `passcode` or `one-time-code`; or any form that posts from a login-like address (`/login`, `/signin`, `/account`, `/admin`, `/wp-login`). Passwordless and two-factor sign-ins have no password field, so the other kinds count too; they are reported in `evidence.login_fields`. |
| `static_api` | A backend but no accounts: a data-entry form (a contact form, say), inline scripts that call APIs (`fetch`, XHR, `axios`, `/api/`, GraphQL, WebSockets), or a JSON response. |
| `static` | Pages only: none of the above. |

Each page is assessed on its own. In a whole-site scan the site's profile is the most sensitive page's (`dynamic` over `static_api` over `static`; the first page on a tie), the reasons are that page's, written in plain sentences that name it (`/admin/login has a password field`), and `decided_by` holds its path. The `evidence` counts are summed over all checked pages. In a single-page scan the reasons say "This page ..." and describe that page only; if the page links to a login-like address (`/login`, `/signin`, `/account`, `/admin`, `/wp-login`) or its CSP `form-action` allows another host, one more reason says the site likely has logins or forms on other pages. That clue never changes the kind.

The parser is Python's `html.parser`. It runs on at most 1 MiB, never executes anything, and counts only tags, attributes and short markers in inline scripts, capped at 200,000 characters. The report's `profile` field lists the evidence and the reasons. The evidence covers forms, password and input fields, cookies, inline and external scripts, third-party script hosts, iframes and API markers.

**How severities change.** A few findings depend on what the site does. Their severity is re-weighed for the profile, and only ever lowered:

| Finding | static | static_api | dynamic |
| --- | --- | --- | --- |
| `csp.missing`, `csp.report_only`, `csp.no_script_restriction` | low (stays medium if scripts load from a third-party host) | unchanged | unchanged |
| `framing.unprotected` | info | low | unchanged |
| `referrer.weak` | info | unchanged | unchanged |

Every other finding keeps its checklist severity on every profile, including all HTTPS, TLS, HSTS and cookie findings. A re-weighed finding keeps its original severity in `baseline_severity`, and `context` explains the change.

**Limits and the owner's declaration.** Even a whole-site scan cannot see a login at an address it does not find, or API calls made by an external bundle. With `--site-type` (or `site_type` in the API, or the "What is this site?" field in the dashboard) the owner can say what the site really is. A declaration can raise the profile but never lower it below what the pages show. Declaring "pages only" (`static`) when a page has a password field keeps `dynamic`, and the report says so in a plain sentence ("You chose 'pages only', but /admin/login has a password field, so it was checked as a site with logins."). A site therefore cannot be argued into a better grade.

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
| `disclosure.generator_version` | low | A `<meta name="generator">` tag or an `X-Generator`, `X-AspNet-Version` or `X-AspNetMvc-Version` header names a WordPress, Drupal, Joomla or ASP.NET version. |
| `exposure.eol_version` | medium or high | A header or generator tag announces a branch that its vendor no longer supports (see the next table). High when the end of life is a year or more old, when the vendor gives no date and says not to use it, or when a critical advisory leaves the branch unfixed; medium otherwise. |
| `exposure.known_vulnerable_version` | high | A header announces a version below the first fixed release that an official advisory in the bundled data states for that branch. |
| `exposure.outdated_branch` | low | A header announces an nginx branch that nginx.org lists as a legacy version rather than the current stable or mainline release. |

#### Announced software versions

The disclosure and `exposure.*` findings read the versions a response announces: the `Server`, `X-Powered-By`, `Via`, `X-AspNet-Version`, `X-AspNetMvc-Version` and `X-Generator` headers, and `<meta name="generator">` on each checked page. They recognise PHP, nginx, Apache httpd, Microsoft IIS, OpenSSL (inside `Server`), Node.js, Drupal, WordPress, Joomla and ASP.NET, with bounded, tolerant parsing, and send no request beyond the page GETs already made. `X-Powered-By: Express` carries no version, so it is only the existing `disclosure.powered_by` finding.

The versions are compared with a bundled offline data file, `src/kestrix/webcheck/data/exposure.json`, generated 2026-10-22. Every entry has its own source URL:

| Product | What the data holds | Source |
| --- | --- | --- |
| PHP | End-of-life date of every branch from 3.0 to 8.5 (a supported branch's date is the end of its security support, so it turns end of life after that day) | [php.net/eol.php](https://www.php.net/eol.php), [supported-versions.php](https://www.php.net/supported-versions.php) |
| Node.js | `end` date of every release line | [nodejs/Release schedule.json](https://raw.githubusercontent.com/nodejs/Release/main/schedule.json) |
| nginx | Branches listed as "Legacy versions" | [nginx.org/en/download.html](https://nginx.org/en/download.html) |
| Apache httpd | 2.2 (end of life December 2017), 2.0 and 1.3 (the project says they should not be used) | [httpd.apache.org](https://httpd.apache.org/security/vulnerabilities_22.html) security pages for 2.2, 2.0 and 1.3 |
| Microsoft IIS | End of support of IIS 6.0, 7.0, 7.5, 8.0 and 8.5 (IIS 10 depends on the Windows release and is not judged) | [Microsoft Lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/internet-information-services-iis) |
| OpenSSL | End-of-support dates the policy page gives (3.4, 3.5, 3.6, 4.0) and the branches it lists as no longer supported (3.0, 1.1.1 and older) | [OpenSSL release strategy](https://openssl-library.org/policies/releasestrat/index.html) |
| Drupal | End of life of Drupal 7, 8, 9 and 10 | [drupal.org release schedule](https://www.drupal.org/about/core/policies/core-release-cycles/schedule) |
| Advisories | PHP, CVE-2026-109618 and CVE-2026-109619 (critical remote code execution, published 2026-10-21): fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12; php.net says PHP 8.1 and older get no update from the project | [php.net announcement](https://www.php.net/archive/2026.php#2026-10-21-5), GitHub advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp (affected: below each fixed version) |

A branch or product that is not in the file gets no end-of-life claim, and WordPress and Joomla versions are only reported as announced because their sources give no end-of-life dates. An advisory range is used only when the vendor's advisory states it; the PHP 8.1 and older branches are reported as end of life, not as "vulnerable", because the advisory gives no affected range for them.

Refresh the file by hand: `uv run python scripts/refresh_exposure_data.py` rewrites the PHP and Node.js entries from their official pages; the other entries and the advisories are edited from their source URLs, then `--confirm-manual` sets the `generated` date. When that date is more than 30 days old, the report carries a note in `notes`.

Evidence shows the header (or tag) and value, the matched branch, its end-of-life date and the source URL. The recommendation is to upgrade to a supported branch and to stop announcing the version (`expose_php = Off`, nginx `server_tokens off;`, Apache `ServerTokens Prod`). A whole-site scan merges each id across pages like other findings.

### Cookies

These checks run on every `Set-Cookie` header of each checked page's final response.

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
| `notice` | The authorization notice and what was sent, for the scope that ran. |
| `requested_url`, `final_url` | The URL you gave, and the URL after redirects. |
| `status_code` | HTTP status of the final response, or `null` when the handshake failed. |
| `headers_checked` | Whether header and cookie checks ran. |
| `redirect_chain` | One entry per hop: `url`, `address` (the IP connected to), `status_code`, `elapsed_ms`. |
| `tls` | `host`, `status`, `detail`, `protocol`, `issuer`, `not_after`, `days_remaining`. `status` is `ok`, `not_https`, `expired`, `not_yet_valid`, `hostname_mismatch`, `untrusted`, `outdated_protocol` or `handshake_failed`. |
| `grade`, `score` | The letter and the 0 to 100 score. |
| `findings` | Sorted high, medium, low, info. The software-version findings also carry `cwe` (CWE-1104, CWE-937 or CWE-200). |
| `timings` | `total_ms`, `http_ms`, `tls_ms`. |
| `profile` | `kind` (the profile used for grading), `detected`, `declared`, `reasons`, `decided_by` (the page that set the kind) and `evidence`. `null` when headers were not checked. |
| `scope` | `site` or `page`. Every field above describes the start page and the site's connection in both cases; `findings` and `profile` cover all checked pages when `scope` is `site`. |
| `pages` | Whole-site scans: one entry per requested page after the start page and the start page itself: `path`, `found_via`, `outcome`, `status_code`, `kind`, `finding_ids`, `detail`. Empty for `page`. |
| `requests_sent` | GET requests actually sent. |
| `limits_reached` | `page_cap`, `deadline` and `request_budget`, whichever stopped the scan early. |
| `links_skipped`, `sitemap_entries` | Links not fetched (see above) and addresses read from the sitemap. |
| `notes` | Caveats about the check itself. Currently one: the bundled software-version data is more than 30 days old. |

A finding in a whole-site scan also has `pages` (paths, at most 20) and `pages_total`. Reports saved before whole-site scans have none of the new fields and describe a single page.

## Limits

- A whole-site scan checks at most 50 pages reachable without logging in. Pages found only through JavaScript, forms or beyond the limits, and headers set only for logged-in users, are not seen. The six login addresses are a fixed list: a login anywhere else is found only if a page links to it.
- A server that answers every path with the same page shows up as several identical pages.
- A `Just this page` check sees one response only.
- TLS is checked once, with httpx's default verified client context. The check does not enumerate cipher suites or every protocol version the server accepts.
- Only the first resolved address is contacted. Sites behind several addresses or a CDN may answer differently elsewhere.
- `--allow-private` removes the address protections for that run. Use it only for hosts you control.
- Certificate revocation (OCSP or CRL) is not checked.
- The software-version findings trust a banner. A banner can be wrong, hidden or set by a proxy, and distribution packages keep an old version number while backporting fixes, so a finding is a strong hint and the absence of one is not proof that the software is current or safe. The data is a small bundled snapshot: it does not cover every product, and it does not list every vulnerability, only the end-of-life branches and the critical advisories named above.

## How the checks are verified

- **Header and cookie checks:** `tests/webcheck` holds a table of known-bad header sets. Each set is served through a full scan, with the network mocked, and the scan must report exactly the expected findings. These run in CI.
- **Certificate and TLS checks:** `uv run python scripts/webcheck_conformance.py` scans [badssl.com](https://badssl.com) endpoints: expired, wrong host, self-signed, untrusted root, TLS 1.0, plain HTTP and HSTS. It checks each result. It needs the network, so it is not part of CI. On 2026-10-14, all 8 endpoints gave the expected result. A client whose OpenSSL disables TLS 1.0 reports `tls-v1-0.badssl.com` as `handshake_failed` rather than `outdated_protocol`.
- **Comparison with other scanners:** to look for gaps, scan 10 to 20 sites you are allowed to test with this tool, [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) and [securityheaders.com](https://securityheaders.com). Then compare the findings. Each tool uses its own rubric, so compare the findings, not the letter grades. Wherever the tools disagree, one of them has a bug or makes a different judgment.
