// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { guide, list, note, p, section, see, steps, table } from "../blocks";
import type { DocPage } from "../model";
import { LIMITS_NAV, ref, toolOverview } from "./helpers";

/* Follows docs/modules/webcheck.md and docs/api.md. */

const BASE = "tools/website";

export const websitePages: DocPage[] = [
  toolOverview("webcheck", BASE, [`${BASE}/how-it-works`, `${BASE}/using-it`, `${BASE}/findings`, `${BASE}/limits`]),
  {
    path: `${BASE}/how-it-works`,
    title: "Web check: how it works",
    nav: "How it works",
    summary: "What is sent, how a whole-site scan finds pages, how the site profile changes severities, and how the grade is computed.",
    sections: [
      ref("webcheck", "How it works"),
      section(
        "What one request does",
        list(
          "Every hop, including each redirect, is validated: only `http` and `https` URLs with a host, at most 2,048 characters, no credentials in the URL, and every resolved address must be public unless `--allow-private` is set.",
          "The request goes to the first validated address. The `Host` header and TLS SNI carry the real hostname, so a DNS answer that changes between the check and the connection cannot redirect it.",
          "One GET per hop, with `User-Agent: kestrix-webcheck/<version>`, no proxy settings from the environment, certificate verification on, no body, no credentials and no cookie. A `Set-Cookie` is read for the cookie checks but never sent back.",
          "Up to 5 redirects are followed. The whole chain has 10 seconds, DNS included; the TLS probe has its own 10 seconds.",
          "At most 1 MiB of the final page is kept for the site profile.",
        ),
      ),
      section(
        "Whole-site scan",
        p("By default the scope is the whole site: the exact scheme, host and port of the start page's final URL. Another host, another port, `http` versus `https`, and a subdomain are all \"another site\" and are never requested. Pages are discovered in this order, de-duplicated:"),
        steps(
          "The `<a href>` links of the start page, in document order (at most 1,000 read).",
          "`/sitemap.xml` (one GET), its `<loc>` addresses (at most 500 read). A sitemap index is not followed.",
          "Six common login addresses, tried with one GET each, whether or not anything links to them: `/login`, `/signin`, `/admin`, `/admin/login`, `/account`, `/wp-login.php`.",
        ),
        table(
          ["Limit", "Value"],
          [
            ["Pages (first GET to each)", "50. Reaching it reports `page_cap` in `limits_reached`"],
            ["Extra GETs (the sitemap and every redirect hop)", "15. Running out reports `request_budget`"],
            ["Most requests in one scan", "65 GETs and 1 TLS handshake"],
            ["Time for the crawl after the start page and TLS check", "60 seconds; reaching it reports `deadline`"],
            ["Pause between requests", "150 ms"],
            ["One response read", "1 MiB"],
            ["Requests at the same time", "1 (strictly sequential)"],
          ],
        ),
        p("Links to other sites, `mailto:`, `tel:` and `javascript:` links, URLs over 2,048 characters, and files that are not web pages are skipped without a request. No form is submitted, no login is attempted, no request but GET is sent, and none carries a body, credentials, a `Referer` or a cookie."),
        p("Findings from all pages are merged by id: the most severe instance supplies the text and the finding lists the paths it was seen on. The grade is computed from the merged findings, so each problem counts once at its worst and the weakest page sets the grade."),
      ),
      section(
        "Site profile",
        p("A missing CSP or framing protection matters most where there is something to steal or click. Before grading, the check profiles the site from the pages it already fetched:"),
        table(
          ["Profile", "Assigned when"],
          [
            ["`dynamic`", "Accounts or sessions: a page has a sign-in field (a password field, a field whose `autocomplete` names `current-password`, `new-password`, `one-time-code` or `webauthn`, or a one-time-code style field name), or any form that posts from a login-like address, or a page sets a cookie."],
            ["`static_api`", "A backend but no accounts: a data-entry form, inline scripts that call APIs, or a JSON response."],
            ["`static`", "Pages only: none of the above."],
          ],
        ),
        p("In a whole-site scan the site's profile is the most sensitive page's (`dynamic` over `static_api` over `static`), and the reason names that page. A few findings depend on what the site does. Their severity is re-weighed for the profile, and only ever lowered:"),
        table(
          ["Finding", "static", "static_api", "dynamic"],
          [
            ["`csp.missing`, `csp.report_only`, `csp.no_script_restriction`", "low (stays medium if scripts load from a third-party host)", "unchanged", "unchanged"],
            ["`framing.unprotected`", "info", "low", "unchanged"],
            ["`referrer.weak`", "info", "unchanged", "unchanged"],
          ],
        ),
        p("Every other finding keeps its checklist severity on every profile, including all HTTPS, TLS, HSTS and cookie findings. A re-weighed finding keeps its original severity in `baseline_severity`, and `context` explains the change."),
        p("With `--site-type` (or the \"What is this site?\" field in the dashboard) you can say what the site really is. A declaration can raise the profile but never lower it below what the pages show, so a site cannot be argued into a better grade."),
      ),
      section(
        "Grading rubric",
        steps(
          "Start at 100.",
          "Subtract 25 per `high`, 10 per `medium` and 4 per `low` finding. `info` findings cost nothing. The score does not go below 0.",
          "Map the score to a letter: A at 90 or above, B at 80, C at 70, D at 60, otherwise F.",
          "Force the grade to F when the final URL is not HTTPS or the TLS status is not `ok`, whatever the score. Every other protection depends on an intact connection.",
        ),
        note("The rubric is a summary for prioritizing fixes. It is not a compliance rating.", "caution"),
      ),
    ],
  },
  {
    path: `${BASE}/using-it`,
    title: "Web check: using it",
    nav: "Using it",
    summary: "Scan a site in the dashboard or with `kestrix webcheck scan`, and read the report.",
    sections: [
      section(
        "In the dashboard",
        p("Enter the website address, confirm that you own the site or are authorized to test it, choose the whole site or just the page, and select Scan. Optional settings let you declare what the site is and, on your own computer, allow private and local addresses. The page tells you before it sends anything what the scan will request."),
        p("On the hosted service the scan is sent from Kestrix's server, public targets on ports 80 and 443 only, and every scan needs your confirmation."),
      ),
      section("On the command line", guide("webcheck")),
      section(
        "Options and exit codes",
        table(
          ["Option", "Effect"],
          [
            ["`--allow-private`", "Allows targets that resolve to private, loopback, link-local or other non-public addresses. Off by default."],
            ["`--page-only`", "Checks only the page you name (one GET plus redirects). The default is the whole site, up to 50 pages."],
            ["`--json`", "Prints the full report as JSON and skips the notice line."],
            ["`--site-type static|static_api|dynamic`", "Declares what you know the site is. It can raise the detected profile, never lower it."],
          ],
        ),
        table(
          ["Exit code", "Meaning"],
          [
            ["0", "The check completed. A poor grade still exits 0."],
            ["2", "The URL or target was rejected: `invalid_url` or `target_not_allowed`."],
            ["3", "The target could not be reached: `target_unreachable` or `upstream_error`."],
          ],
        ),
      ),
      section(
        "The report",
        table(
          ["Field", "Content"],
          [
            ["`requested_url`, `final_url`", "The URL you gave, and the URL after redirects"],
            ["`status_code`, `headers_checked`", "HTTP status of the final response (or `null` when the handshake failed), and whether header and cookie checks ran"],
            ["`redirect_chain`", "One entry per hop: `url`, `address`, `status_code`, `elapsed_ms`"],
            ["`tls`", "`host`, `status`, `detail`, `protocol`, `issuer`, `not_after`, `days_remaining`"],
            ["`grade`, `score`", "The letter and the 0 to 100 score"],
            ["`findings`", "Sorted high, medium, low, info; each with `id`, `severity`, `title`, `explanation`, `recommendation` and evidence"],
            ["`profile`", "`kind`, `detected`, `declared`, `reasons`, `decided_by` and `evidence`"],
            ["`scope`, `pages`", "`site` or `page`; for a whole-site scan one entry per requested page with its `outcome`"],
            ["`requests_sent`, `limits_reached`", "GET requests actually sent, and `page_cap`, `deadline` or `request_budget` when one stopped the scan early"],
          ],
        ),
        p("Cookie findings name the cookie but never echo its value. Header values in evidence are cut to 200 characters."),
        see("Every finding id", `${BASE}/findings`),
      ),
    ],
  },
  {
    path: `${BASE}/findings`,
    title: "Web check: findings reference",
    nav: "Findings reference",
    summary: "Every finding id the web check can raise, with its severity and what raises it.",
    sections: [
      section(
        "HTTPS and TLS",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`https.not_used`", "high", "The final URL is plain HTTP."],
            ["`tls.expired`", "high", "The certificate has expired."],
            ["`tls.not_yet_valid`", "high", "The certificate's start date is in the future."],
            ["`tls.hostname_mismatch`", "high", "The certificate does not list this hostname."],
            ["`tls.untrusted`", "high", "The certificate chain is not trusted, for example self-signed or incomplete."],
            ["`tls.outdated_protocol`", "high", "The server offers only TLS older than 1.2."],
            ["`tls.handshake_failed`", "high", "The TLS handshake failed for another reason."],
            ["`tls.expiring_soon`", "medium", "The certificate expires in fewer than 14 days."],
          ],
        ),
      ),
      section(
        "Headers",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`hsts.missing`", "medium", "HTTPS response without `Strict-Transport-Security`."],
            ["`hsts.short_max_age`", "low", "HSTS `max-age` is missing or under 15,552,000 seconds (180 days)."],
            ["`hsts.disabled`", "medium", "HSTS `max-age=0`, which switches HSTS off. No other HSTS finding is reported."],
            ["`hsts.no_subdomains`", "info", "HSTS lacks `includeSubDomains`."],
            ["`hsts.not_preload_ready`", "info", "HSTS has `includeSubDomains` but not a `max-age` of at least one year together with `preload`."],
            ["`csp.missing`", "medium", "Neither `Content-Security-Policy` nor `Content-Security-Policy-Report-Only`."],
            ["`csp.report_only`", "medium", "Only `Content-Security-Policy-Report-Only` is sent. It reports violations but does not block anything."],
            ["`csp.no_script_restriction`", "medium", "A CSP is enforced but has neither `script-src` nor `default-src`."],
            ["`csp.unsafe_inline`", "low", "The effective script sources allow `'unsafe-inline'` without a nonce or hash."],
            ["`csp.unsafe_eval`", "low", "The effective script sources allow `'unsafe-eval'`."],
            ["`csp.wildcard_source`", "low", "The effective script sources allow `*`, `http:`, `https:` or `data:`, and do not use `'strict-dynamic'`."],
            ["`csp.object_src_open`", "low", "Neither `object-src 'none'` nor `default-src 'none'`, so plugins are not blocked."],
            ["`csp.base_uri_missing`", "info", "No `base-uri`, so an injected `<base>` tag can redirect relative script URLs."],
            ["`framing.unprotected`", "medium", "Neither `X-Frame-Options: DENY` or `SAMEORIGIN`, nor a CSP `frame-ancestors` directive in any enforced policy."],
            ["`xcto.missing`", "low", "`X-Content-Type-Options` is not `nosniff`."],
            ["`referrer.weak`", "low", "`Referrer-Policy` is missing, `unsafe-url` or `no-referrer-when-downgrade`."],
            ["`permissions_policy.missing`", "info", "No `Permissions-Policy`."],
            ["`coop.missing`", "info", "No `Cross-Origin-Opener-Policy`."],
          ],
        ),
        p("The HSTS checks run only for HTTPS responses. A browser enforces every CSP it receives, so a CSP weakness is reported only when every enforced policy has it."),
      ),
      section(
        "Information disclosure",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`disclosure.server_version`", "low", "The `Server` header contains a version number such as `nginx/1.25.3`."],
            ["`disclosure.powered_by`", "low", "An `X-Powered-By` header is present."],
          ],
        ),
      ),
      section(
        "Cookies",
        table(
          ["id", "Severity", "Raised when"],
          [
            ["`cookie.no_secure`", "medium", "HTTPS site and the cookie lacks `Secure`."],
            ["`cookie.no_httponly`", "low", "The cookie lacks `HttpOnly`. This is acceptable only when JavaScript must read the cookie."],
            ["`cookie.no_samesite`", "low", "The cookie has no `SameSite` attribute."],
            ["`cookie.samesite_none_insecure`", "medium", "`SameSite=None` without `Secure`."],
            ["`cookie.prefix_violation`", "medium", "A `__Secure-` or `__Host-` cookie that breaks its prefix rules. Browsers drop such cookies."],
          ],
        ),
        p("These checks run on every `Set-Cookie` header of each checked page's final response."),
      ),
      section(
        "Page outcomes in a whole-site scan",
        table(
          ["outcome", "Meaning"],
          [
            ["`checked`", "A 2xx HTML response; its headers, cookies and profile were evaluated."],
            ["`not_html`", "A 2xx response that is not HTML."],
            ["`http_error`", "A 4xx, 5xx or a redirect without a target."],
            ["`redirects_off_site`", "The page redirects to another scheme, host or port. The redirect is not followed and the other site is never contacted."],
            ["`blocked`", "The address failed the private-address or port rule on this request."],
            ["`failed`", "Connection error, timeout or TLS failure on that page, or the redirect limit."],
            ["`duplicate`", "The page redirected to a page that was already checked; it is not evaluated twice."],
          ],
        ),
        p("A page that fails never stops the scan; only a failure of the start page rejects the check."),
      ),
    ],
  },
  {
    path: `${BASE}/limits`,
    title: "Web check: limits and measured accuracy",
    nav: LIMITS_NAV,
    summary: "What the web check cannot see, and how its checks were verified. No detection rate has been measured.",
    sections: [
      ref("webcheck", "Limits"),
      section(
        "More limits",
        list(
          "A server that answers every path with the same page shows up as several identical pages.",
          "TLS is checked once, with the default verified client context. The check does not enumerate cipher suites or every protocol version the server accepts.",
          "Sites behind several addresses or a CDN may answer differently from the one address that is contacted.",
          "`--allow-private` removes the address protections for that run. Use it only for hosts you control.",
        ),
      ),
      section(
        "Measured accuracy",
        p("Not measured. The web check has not been compared against a labeled set of sites, so no detection rate or false-alarm rate is claimed. The grade is a fixed rubric, not an estimate of anything."),
        p("What has been checked:"),
        list(
          "The header and cookie checks run against a table of known-bad header sets, each served through a full scan with the network mocked; the scan must report exactly the expected findings. These tests run in CI.",
          "The certificate and TLS checks were run against 8 badssl.com endpoints (expired, wrong host, self-signed, untrusted root, TLS 1.0, plain HTTP and HSTS) on 2026-10-14, and all 8 gave the expected result. A client whose OpenSSL disables TLS 1.0 reports `tls-v1-0.badssl.com` as `handshake_failed` rather than `outdated_protocol`.",
        ),
        p("Different scanners use different rubrics, so compare findings, not letter grades, when you cross-check with Mozilla Observatory or securityheaders.com."),
      ),
    ],
  },
];
