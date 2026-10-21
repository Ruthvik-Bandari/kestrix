// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useState, type SubmitEvent } from "react";
import { Icon } from "../../components/Icon";
import {
  Evidence,
  FailedRequest,
  FindingList,
  FindingTally,
  HelpPanel,
  LiveStatus,
  PendingPanel,
  ReasonCode,
  ToolLayout,
  useFocusOnArrival,
  VerdictCard,
} from "../../components/report";
import { Badge, Button, cx, Disclosure, Field, Panel, RawJson } from "../../components/ui";
import { tones, type Tone } from "../../components/tone";
import { api } from "../../lib/api";
import { ToolHeader } from "../tools/ToolHeader";
import { isHosted } from "../../lib/mode";
import { slug } from "../../lib/download";
import { plural } from "../../lib/format";
import type {
  SiteKind,
  SiteProfile,
  TlsStatus,
  WebFinding,
  WebPage,
  WebPageOutcome,
  WebReport,
  WebScope,
} from "../../lib/types";

const AUTHORIZED = "Only check websites you own or are authorized to assess.";
const SITE_SENDS =
  "up to 50 read-only GET requests to this site's pages, including 6 common login addresses, plus its sitemap and any redirects (at most 15 more), and one TLS handshake. It never submits a form, logs in, or follows a link to another site.";

/** Mirror webcheck.models.NOTICE_PAGE and NOTICE_SITE; the report repeats the server's own copy. */
export const NOTICE_PAGE = `${AUTHORIZED} Kestrix sends one GET request (plus redirects) and one TLS handshake.`;
export const NOTICE_SITE = `${AUTHORIZED} Kestrix sends ${SITE_SENDS}`;
export const NOTICE = NOTICE_PAGE;

/** The hosted service makes the request, not the user's computer (ADR 0004). */
export const HOSTED_NOTICE_PAGE = `${AUTHORIZED} Kestrix's server, not your computer, sends one GET request (plus redirects) and one TLS handshake to the site. Public addresses only.`;
export const HOSTED_NOTICE_SITE = `${AUTHORIZED} Kestrix's server, not your computer, sends ${SITE_SENDS} Public addresses only.`;
export const HOSTED_NOTICE = HOSTED_NOTICE_PAGE;

export function noticeFor(scope: WebScope, hosted: boolean): string {
  if (hosted) return scope === "site" ? HOSTED_NOTICE_SITE : HOSTED_NOTICE_PAGE;
  return scope === "site" ? NOTICE_SITE : NOTICE_PAGE;
}

/** Reports saved before whole-site scans have no `scope`; they checked one page. */
function scopeOf(report: WebReport): WebScope {
  return report.scope ?? "page";
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export const gradeTone: Record<WebReport["grade"], Tone> = {
  A: "ok",
  B: "ok",
  C: "med",
  D: "high",
  F: "crit",
};

const tlsText: Record<
  TlsStatus,
  { label: string; tone: Tone; explain: string }
> = {
  ok: {
    label: "Valid",
    tone: "ok",
    explain: "The certificate is trusted, current and matches the host name.",
  },
  not_https: {
    label: "Not HTTPS",
    tone: "crit",
    explain: "The final page is served without encryption.",
  },
  expired: {
    label: "Expired",
    tone: "crit",
    explain: "The certificate has expired; browsers will show a warning.",
  },
  not_yet_valid: {
    label: "Not yet valid",
    tone: "crit",
    explain: "The certificate's start date is in the future.",
  },
  hostname_mismatch: {
    label: "Wrong host name",
    tone: "crit",
    explain: "The certificate was issued for a different name than this site.",
  },
  untrusted: {
    label: "Untrusted",
    tone: "crit",
    explain: "The certificate is not signed by an authority browsers trust.",
  },
  outdated_protocol: {
    label: "Outdated protocol",
    tone: "high",
    explain: "The server negotiated an old TLS version with known weaknesses.",
  },
  handshake_failed: {
    label: "Handshake failed",
    tone: "crit",
    explain: "A secure connection could not be set up.",
  },
};

function headline(report: WebReport): string {
  const host = hostOf(report.final_url);
  const actionable = report.findings.filter(
    (f) => f.severity !== "info",
  ).length;
  if (actionable === 0)
    return `${host} earns an ${report.grade}: no issues worth fixing were found.`;
  const article = report.grade === "A" || report.grade === "F" ? "an" : "a";
  return `${host} earns ${article} ${report.grade}: ${plural(actionable, "issue")} worth fixing.`;
}

const siteKindText: Record<
  WebScope,
  Record<SiteKind, { label: string; explain: string }>
> = {
  site: {
    static: {
      label: "Static site",
      explain: "None of the pages checked has a form, a cookie or an API call.",
    },
    static_api: {
      label: "Sends form or API data",
      explain:
        "A page has a form or calls an API, so it sends data somewhere (its own server, a serverless function or a service such as a form provider), but no page has a login or sets cookies.",
    },
    dynamic: {
      label: "Dynamic site",
      explain:
        "At least one page has a login (a password, one-time code or passkey field, or a form at a login address) or sets cookies.",
    },
  },
  page: {
    static: {
      label: "Static page",
      explain:
        "No forms, cookies or API calls were found on this page. Other pages were not checked.",
    },
    static_api: {
      label: "Page with a form or API",
      explain:
        "This page has a form or calls an API, but no login and no cookies. Other pages were not checked.",
    },
    dynamic: {
      label: "Page with a login or cookies",
      explain:
        "This page has a login (a password, one-time code or passkey field, or a form at a login address) or sets cookies. Other pages were not checked.",
    },
  },
};

function ProfilePanel({
  profile,
  scope,
}: {
  profile: SiteProfile;
  scope: WebScope;
}) {
  const text = siteKindText[scope][profile.kind];
  const ev = profile.evidence;
  const where = scope === "site" ? " (all pages)" : "";
  const facts: [string, number][] = [
    [`Forms${where}`, ev.forms],
    [`Password fields${where}`, ev.password_fields],
    [`Other sign-in fields${where}`, ev.login_fields ?? 0],
    [`Cookies set${where}`, ev.cookies],
    [
      `Scripts, inline and external${where}`,
      ev.scripts_inline + ev.scripts_external,
    ],
    ["Third-party script hosts", ev.third_party_script_hosts.length],
    [`API calls in scripts${where}`, ev.api_markers],
  ];
  return (
    <Panel as="section" className="@2xl:col-span-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="profile-title" className="font-semibold">
          Site profile
        </h3>
        <Badge tone={profile.kind === "dynamic" ? "med" : "ok"}>{text.label}</Badge>
      </div>
      <p className="mt-2 max-w-[68ch] text-ink-2">
        {text.explain} Findings whose risk depends on what a site does are weighed for this profile; each one says when it
        was. HSTS, TLS and cookie flags are never lowered.
      </p>
      <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1.5 text-[0.875rem] @lg:grid-cols-2 @3xl:grid-cols-3">
        {facts.map(([label, value]) => (
          <div key={label} className="flex justify-between gap-3 border-b border-line py-1">
            <dt className="text-ink-3">{label}</dt>
            <dd className="font-mono">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-3 text-[0.8125rem] text-ink-3">
        <p className="font-medium text-ink-2">
          Why
          {profile.decided_by ? (
            <>
              {" "}
              (set by{" "}
              <span className="font-mono break-all">{profile.decided_by}</span>)
            </>
          ) : null}
        </p>
        <ul className="mt-1 list-disc space-y-0.5 pl-5">
          {profile.reasons.map((reason) => (
            <li key={reason} className="max-w-[68ch]">
              {reason.replace(/\.$/, "")}.
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}

const outcomeText: Record<WebPageOutcome, string> = {
  checked: "Checked",
  not_html: "Not a web page",
  http_error: "Not checked",
  redirects_off_site: "Redirects off-site, not followed",
  blocked: "Blocked",
  failed: "Failed",
  duplicate: "Same page as another",
};

const viaText: Record<WebPage["found_via"], string> = {
  start: "Start page",
  link: "Link",
  sitemap: "Sitemap",
  probe: "Login address tried",
};

const kindShort: Record<SiteKind, string> = {
  static: "Static",
  static_api: "Form or API",
  dynamic: "Login or cookies",
};

const limitText: Record<
  NonNullable<WebReport["limits_reached"]>[number],
  string
> = {
  page_cap:
    "Stopped at the 50-page limit: more pages were found than were checked.",
  deadline:
    "Stopped after the 60-second time limit: some pages were not requested.",
  request_budget:
    "Some redirects were not followed because the scan reached its limit of 15 extra requests.",
};

function PagesChecked({ report }: { report: WebReport }) {
  const pages = report.pages ?? [];
  const checked = pages.filter((p) => p.outcome === "checked");
  const rows = [...checked, ...pages.filter((p) => p.outcome !== "checked")];
  const limits = report.limits_reached ?? [];
  const via = (["link", "sitemap", "probe"] as const).map(
    (v) => [v, pages.filter((p) => p.found_via === v).length] as const,
  );
  return (
    <section aria-labelledby="pages-title">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3
          id="pages-title"
          className="text-xl font-semibold tracking-[-0.015em]"
        >
          Pages checked
        </h3>
        <p className="text-[0.875rem] text-ink-2">
          {plural(checked.length, "page")} checked of{" "}
          {plural(pages.length, "page")} requested
          {report.requests_sent
            ? ` · ${plural(report.requests_sent, "request")} sent`
            : ""}
        </p>
      </div>
      <p className="mt-1 max-w-[80ch] text-[0.8125rem] text-ink-3">
        {via
          .map(
            ([v, n]) =>
              `${n.toLocaleString()} from ${v === "link" ? "links" : v === "sitemap" ? "the sitemap" : "common login addresses"}`,
          )
          .join(", ")}
        {report.links_skipped
          ? `; ${plural(report.links_skipped, "link")} not followed (other sites, files and the like)`
          : ""}
        .
      </p>
      {limits.map((limit) => (
        <p
          key={limit}
          className="mt-2 flex gap-2 rounded-lg border border-line bg-med-bg px-3 py-2 text-[0.875rem] text-ink"
          role="note"
        >
          <Icon name="alert" size={16} className="mt-0.5 flex-none text-med" />
          {limitText[limit]}
        </p>
      ))}
      <div className="mt-3 overflow-hidden rounded-xl border border-line bg-surface-solid">
        <table className="data-table w-full table-fixed">
          <caption className="sr-only">
            Pages the scan requested and what came back
          </caption>
          <thead>
            <tr>
              <th scope="col" className="w-[46%] sm:w-[34%]">
                Page
              </th>
              <th scope="col" className="w-[30%] sm:w-[28%]">
                Result
              </th>
              <th scope="col" className="w-[24%] sm:w-[19%]">
                Type
              </th>
              <th scope="col" className="hidden w-[19%] sm:table-cell">
                Found via
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((page) => (
              <tr
                key={page.path}
                className={
                  page.outcome === "checked" ? undefined : "text-ink-2"
                }
              >
                <th
                  scope="row"
                  className="font-mono text-[0.8125rem] break-all"
                >
                  {page.path}
                  <span className="mt-0.5 block font-sans text-[0.75rem] text-ink-3 sm:hidden">
                    {viaText[page.found_via]}
                  </span>
                </th>
                <td className="break-words">
                  {page.status_code ? (
                    <span className="font-mono">{page.status_code} </span>
                  ) : null}
                  {outcomeText[page.outcome]}
                  {page.detail ? (
                    <span className="block text-[0.75rem] break-words text-ink-3">
                      {page.detail}
                    </span>
                  ) : null}
                </td>
                <td>
                  {page.kind ? (
                    kindShort[page.kind]
                  ) : (
                    <span className="text-ink-3">n/a</span>
                  )}
                </td>
                <td className="hidden sm:table-cell">
                  {viaText[page.found_via]}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function FindingPages({ paths, total }: { paths: string[]; total: number }) {
  return (
    <details className="group max-w-[68ch]">
      <summary className="inline-flex min-h-8 cursor-pointer items-center gap-1.5 text-[0.875rem] font-medium text-ink select-none">
        <Icon
          name="chevronDown"
          size={14}
          className="-rotate-90 text-ink-3 transition-transform duration-150 motion-reduce:transition-none group-open:rotate-0"
        />
        On {plural(total, "page")}
      </summary>
      <ul className="mt-1 space-y-0.5 pl-5 font-mono text-[0.8125rem] text-ink-2">
        {paths.map((path) => (
          <li key={path} className="break-all">
            {path}
          </li>
        ))}
        {total > paths.length ? (
          <li className="font-sans text-ink-3">
            and {(total - paths.length).toLocaleString()} more
          </li>
        ) : null}
      </ul>
    </details>
  );
}

function GradeTile({ report }: { report: WebReport }) {
  const style = tones[gradeTone[report.grade]];
  return (
    <div
      className={cx(
        "flex size-16 flex-none items-center justify-center rounded-xl border border-line bg-surface-solid text-4xl font-semibold",
        style.text,
      )}
      role="img"
      aria-label={`Grade ${report.grade}`}
    >
      {report.grade}
    </div>
  );
}

function ScoreAside({ report }: { report: WebReport }) {
  const style = tones[gradeTone[report.grade]];
  return (
    <div className="space-y-3">
      <div>
        <p className="text-[0.875rem] text-ink-2">Score</p>
        <p className="text-2xl font-semibold text-ink">
          {report.score}
          <span className="text-base font-normal text-ink-3"> / 100</span>
        </p>
        <div
          className="mt-2 h-2 w-full overflow-hidden rounded-full bg-inset"
          role="meter"
          aria-label="Score"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={report.score}
        >
          <div className={cx("h-full rounded-full", style.mark)} style={{ width: `${report.score}%` }} />
        </div>
      </div>
      <FindingTally findings={report.findings} />
    </div>
  );
}

export function WebReportView({ report }: { report: WebReport }) {
  const heading = useFocusOnArrival(report);
  const tls = tlsText[report.tls.status];
  const secureCap =
    report.grade === "F" &&
    (report.tls.status !== "ok" || !report.final_url.startsWith("https:"));
  const scope = scopeOf(report);
  const pageCount = (report.pages ?? []).filter(
    (p) => p.outcome === "checked",
  ).length;

  return (
    <section aria-labelledby="web-result" className="@container reveal scroll-mt-6 space-y-6">
      <VerdictCard
        tone={gradeTone[report.grade]}
        lead={<GradeTile report={report} />}
        label={`Grade ${report.grade}`}
        headingId="web-result"
        headingRef={heading}
        title={headline(report)}
        aside={<ScoreAside report={report} />}
      >
        {secureCap ? (
          <p>
            The grade is capped at F because the connection itself is not secure; every other protection depends on it.
          </p>
        ) : (
          <p>
            Grades start at 100 and lose 25 per high, 10 per medium and 4 per
            low finding.{" "}
            {scope === "site"
              ? `${plural(pageCount, "page")} checked; each finding counts once, at its most severe, so the weakest page sets the grade.`
              : "Only this page was checked; other pages may differ."}
          </p>
        )}
      </VerdictCard>

      {!report.headers_checked ? (
        <div className="flex gap-3 rounded-xl border border-line bg-med-bg px-5 py-4" role="note">
          <Icon name="alert" size={20} className="mt-0.5 flex-none text-med" />
          <div className="text-ink">
            <p className="font-semibold text-med">Partial analysis</p>
            <p className="mt-1 max-w-[68ch]">
              The page could not be fetched, so headers were not checked. Only the certificate and connection results
              below are complete.
            </p>
          </div>
        </div>
      ) : null}

      {report.findings.length === 0 ? (
        <section aria-labelledby="findings-title">
          <h3 id="findings-title" className="text-xl font-semibold tracking-[-0.015em]">
            Findings
          </h3>
          <p className="mt-2 text-ink-2">Nothing to report: every header check passed.</p>
        </section>
      ) : (
        <FindingList
          id="web-findings"
          heading="Findings, failed checks first"
          findings={report.findings}
          keyOf={(finding) => finding.id}
          renderDetail={(finding: WebFinding) => (
            <>
              <p className="max-w-[68ch] text-ink-2">{finding.explanation}</p>
              <p className="max-w-[68ch]">
                <span className="font-medium text-ink">How to fix: </span>
                <span className="text-ink-2">{finding.recommendation}</span>
              </p>
              {finding.context ? (
                <p className="max-w-[68ch] text-[0.8125rem] text-ink-3">
                  <span className="font-medium text-ink-2">Weighed for this site: </span>
                  {finding.context}
                </p>
              ) : null}
              {finding.pages_total ? (
                <FindingPages
                  paths={finding.pages ?? []}
                  total={finding.pages_total}
                />
              ) : null}
              {finding.evidence ? (
                <Evidence label="Seen">{finding.evidence}</Evidence>
              ) : null}
              <ReasonCode>{finding.id}</ReasonCode>
            </>
          )}
        />
      )}

      {scope === "site" && (report.pages ?? []).length > 0 ? (
        <PagesChecked report={report} />
      ) : null}

      <div className="grid items-start gap-4 @2xl:grid-cols-2">
        <Panel as="section">
          <div className="flex items-center justify-between gap-2">
            <h3 id="tls-title" className="font-semibold">
              Certificate and TLS
            </h3>
            <Badge tone={tls.tone}>{tls.label}</Badge>
          </div>
          <p className="mt-2 text-ink-2">{report.tls.detail ?? tls.explain}</p>
          <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-5 gap-y-1.5 text-[0.875rem]">
            <dt className="text-ink-3">Host</dt>
            <dd className="font-mono break-all">{report.tls.host}</dd>
            {report.tls.protocol ? (
              <>
                <dt className="text-ink-3">Protocol</dt>
                <dd className="font-mono">{report.tls.protocol}</dd>
              </>
            ) : null}
            {report.tls.issuer ? (
              <>
                <dt className="text-ink-3">Issuer</dt>
                <dd className="break-words">{report.tls.issuer}</dd>
              </>
            ) : null}
            {report.tls.not_after ? (
              <>
                <dt className="text-ink-3">Expires</dt>
                <dd>
                  {new Date(report.tls.not_after).toLocaleDateString(undefined, { dateStyle: "medium" })}
                  {report.tls.days_remaining !== null ? (
                    <span className={cx("ml-2", report.tls.days_remaining < 14 ? "font-medium text-high" : "text-ink-3")}>
                      ({plural(report.tls.days_remaining, "day")} left)
                    </span>
                  ) : null}
                </dd>
              </>
            ) : null}
          </dl>
        </Panel>

        <Panel as="section">
          <h3 id="redirect-title" className="font-semibold">
            Redirect chain
          </h3>
          {report.redirect_chain.length === 0 ? (
            <p className="mt-2 text-ink-2">No response was received.</p>
          ) : (
            <ol className="mt-3 space-y-3">
              {report.redirect_chain.map((hop, i) => (
                <li key={`${hop.url}-${i.toString()}`} className="flex gap-3">
                  <span className="flex size-6 flex-none items-center justify-center rounded-full bg-inset text-xs font-medium text-ink-2">
                    {i + 1}
                  </span>
                  <div className="min-w-0">
                    <p className="font-mono text-[0.8125rem] break-all text-ink">{hop.url}</p>
                    <p className="text-[0.8125rem] text-ink-3">
                      HTTP {hop.status_code} · {hop.address} · {hop.elapsed_ms} ms
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Panel>

        {report.profile ? (
          <ProfilePanel profile={report.profile} scope={scope} />
        ) : null}
      </div>

      <div className="space-y-3">
        <p className="text-[0.8125rem] text-ink-3">
          Took {report.timings.total_ms} ms (HTTP {report.timings.http_ms} ms, TLS {report.timings.tls_ms} ms). {report.notice}
        </p>
        <RawJson data={report} filename={`kestrix-webcheck-${slug(report.final_url)}.json`} />
      </div>
    </section>
  );
}

const scopeOptions: { value: WebScope; label: string; hint: string }[] = [
  {
    value: "site",
    label: "Whole site (up to 50 pages)",
    hint: "Follows links on the site, reads its sitemap and tries six common login addresses.",
  },
  {
    value: "page",
    label: "Just this page",
    hint: "Checks only the address you enter.",
  },
];

function ScopeChoice({
  scope,
  onChange,
}: {
  scope: WebScope;
  onChange: (scope: WebScope) => void;
}) {
  return (
    <fieldset className="space-y-2">
      <legend className="mb-2 text-[0.875rem] font-medium text-ink">
        What to check
      </legend>
      {scopeOptions.map((option) => (
        <label
          key={option.value}
          className={cx(
            "flex min-h-11 cursor-pointer gap-3 rounded-xl border px-3 py-2.5 transition-colors duration-150 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-(--focus) motion-reduce:transition-none",
            scope === option.value
              ? "border-ink bg-surface-solid"
              : "border-line bg-inset hover:bg-surface-solid",
          )}
        >
          <input
            type="radio"
            name="webcheck-scope"
            value={option.value}
            checked={scope === option.value}
            onChange={() => {
              onChange(option.value);
            }}
            className="mt-1 size-4 flex-none accent-(--accent)"
          />
          <span>
            <span className="font-medium">{option.label}</span>
            <span className="hint block">{option.hint}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

function HelpColumns({ hosted }: { hosted: boolean }) {
  return (
    <div className="grid gap-6 @2xl:grid-cols-2">
      <div>
        <h3 className="font-semibold">What the report contains</h3>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
          <li>A grade from A to F with the score and how it was worked out.</li>
          <li>
            Findings with the failed checks first, each with the evidence seen
            and how to fix it.
          </li>
          <li>
            The certificate and TLS result, the redirect chain and a profile of
            the site.
          </li>
          <li>
            For a whole-site check, a table of the pages checked and which pages
            each finding was seen on.
          </li>
        </ul>
      </div>
      <div>
        <h3 className="font-semibold">What the check does</h3>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
          <li>
            Whole site (the default): up to 50 read-only GET requests, one at a
            time, to the page you name, the pages it links to, the pages in its
            sitemap and six common login addresses (/login, /signin, /admin,
            /admin/login, /account, /wp-login.php), plus one TLS handshake.
          </li>
          <li>
            Just this page: one GET request (plus any redirects) and one TLS
            handshake.
          </li>
          <li>
            It reads HTTPS, the certificate, security headers and cookies. It
            never submits a form, logs in, follows a link to another site or
            attacks anything.
          </li>
          {hosted ? (
            <li>Public addresses only. Private and local addresses are refused on the hosted service.</li>
          ) : (
            <li>Private and local addresses are refused unless you allow them under Optional settings.</li>
          )}
        </ul>
      </div>
    </div>
  );
}

export default function WebcheckPage() {
  const hosted = isHosted();
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [siteType, setSiteType] = useState<SiteKind | "">("");
  const [scope, setScope] = useState<WebScope>("site");
  const scan = useMutation({
    mutationFn: (input: {
      url: string;
      allowPrivate: boolean;
      siteType: SiteKind | null;
      scope: WebScope;
    }) =>
      hosted
        ? api.webcheckHosted(input.url, input.siteType, input.scope)
        : api.webcheck(
            input.url,
            input.allowPrivate,
            input.siteType,
            input.scope,
          ),
  });
  const pendingTitle = scan.isPending
    ? scan.variables.scope === "site"
      ? `Checking up to 50 pages on ${hostOf(scan.variables.url)}…`
      : `Checking ${hostOf(scan.variables.url)}…`
    : "";
  const canScan = authorized && url.trim().length > 0 && !scan.isPending;

  function run() {
    if (!canScan) return;
    const target = /^[a-z][a-z0-9+.-]*:\/\//i.test(url.trim())
      ? url.trim()
      : `https://${url.trim()}`;
    scan.mutate({
      url: target,
      allowPrivate,
      siteType: siteType || null,
      scope,
    });
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    run();
  }

  const input = (
    <Panel as="section">
      <form
        onSubmit={submit}
        className="space-y-4"
        aria-describedby="webcheck-notice"
      >
        <Field
          htmlFor="webcheck-url"
          label="Website address"
          hint="For example example.com or https://example.com/login"
        >
          <input
            id="webcheck-url"
            className="field"
            type="text"
            inputMode="url"
            autoComplete="url"
            spellCheck={false}
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
            }}
            placeholder="https://"
          />
        </Field>

        <ScopeChoice scope={scope} onChange={setScope} />

        <label className="flex cursor-pointer gap-3">
          <input
            type="checkbox"
            className="check"
            checked={authorized}
            onChange={(e) => {
              setAuthorized(e.target.checked);
            }}
          />
          <span>
            <span className="font-medium">
              {hosted ? "I own this website or am authorized to test it" : "I own this site or am authorized to test it"}
            </span>
            <span className="hint block">Required. Scanning sites without permission may break their terms or the law.</span>
          </span>
        </label>

        <Disclosure summary="Optional settings">
          <div className="space-y-4">
            <Field
              htmlFor="webcheck-site-type"
              label="What is this site?"
              optional
              hint="Detected from the pages if left blank. Choosing a type can only make the check stricter, never more lenient."
            >
              <select
                id="webcheck-site-type"
                className="field"
                value={siteType}
                onChange={(e) => {
                  setSiteType(e.target.value as SiteKind | "");
                }}
              >
                <option value="">Detect from the pages</option>
                <option value="static">Pages only: no logins or forms</option>
                <option value="static_api">
                  A site with a form: a contact form or API calls, no accounts
                </option>
                <option value="dynamic">
                  A site with logins: accounts, sessions or checkout
                </option>
              </select>
            </Field>
            {hosted ? null : (
              <label className="flex cursor-pointer gap-3">
                <input
                  type="checkbox"
                  className="check"
                  checked={allowPrivate}
                  onChange={(e) => {
                    setAllowPrivate(e.target.checked);
                  }}
                />
                <span>
                  <span className="font-medium">Allow private and local addresses</span>
                  <span className="hint block">For a lab or home server you own, such as 192.168.x.x or localhost.</span>
                </span>
              </label>
            )}
          </div>
        </Disclosure>

        <div className="space-y-3">
          <p
            id="webcheck-notice"
            className="flex gap-2 rounded-lg bg-inset px-3 py-2.5 text-[0.875rem] text-ink-2"
          >
            <Icon
              name="info"
              size={18}
              className="mt-0.5 flex-none text-ink-3"
            />
            {noticeFor(scope, hosted)}
          </p>
          <Button
            type="submit"
            className="w-full"
            disabled={!canScan && !scan.isPending}
            pending={scan.isPending}
            pendingLabel="Scanning…"
          >
            <Icon name="search" size={16} />
            Scan
          </Button>
          {!authorized ? <p className="hint">Confirm authorization to enable scanning.</p> : null}
        </div>
      </form>
    </Panel>
  );

  return (
    <>
      <ToolHeader page="webcheck" />
      <ToolLayout input={input}>
        <LiveStatus
          pending={scan.isPending}
          done={scan.isSuccess}
          pendingText={pendingTitle}
          doneText="Scan finished. The result is below."
        />
        {scan.isPending ? (
          <PendingPanel title={pendingTitle}>
            {scan.variables.scope === "site"
              ? "Following links, reading the sitemap and trying six common login addresses, one request at a time, then checking each page's headers and cookies. This can take up to a minute."
              : "Sending one request and one TLS handshake, then checking the certificate, headers and cookies. This usually takes a few seconds."}
          </PendingPanel>
        ) : scan.isError ? (
          <FailedRequest error={scan.error} onRetry={run} />
        ) : scan.data ? (
          <WebReportView report={scan.data} />
        ) : (
          <HelpPanel title="Check a website">
            <HelpColumns hosted={hosted} />
          </HelpPanel>
        )}
      </ToolLayout>
    </>
  );
}
