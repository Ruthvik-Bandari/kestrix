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
  WebReport,
} from "../../lib/types";

/** Mirrors webcheck.models.NOTICE; the report repeats the server's own copy. */
export const NOTICE =
  "Only check websites you own or are authorized to assess. Kestrix sends one GET request (plus redirects) and one TLS handshake.";

/** The hosted service makes the request, not the user's computer (ADR 0004). */
export const HOSTED_NOTICE =
  "Only check websites you own or are authorized to assess. Kestrix's server, not your computer, sends one GET request (plus redirects) and one TLS handshake to the site. Public addresses only.";

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
  const host = (() => {
    try {
      return new URL(report.final_url).host;
    } catch {
      return report.final_url;
    }
  })();
  const actionable = report.findings.filter(
    (f) => f.severity !== "info",
  ).length;
  if (actionable === 0)
    return `${host} earns an ${report.grade}: no issues worth fixing were found.`;
  const article = report.grade === "A" || report.grade === "F" ? "an" : "a";
  return `${host} earns ${article} ${report.grade}: ${plural(actionable, "issue")} worth fixing.`;
}

const siteKindText: Record<SiteKind, { label: string; explain: string }> = {
  static: {
    label: "Static site",
    explain: "No forms, cookies or API calls were found on this page.",
  },
  static_api: {
    label: "Static + backend",
    explain:
      "A form or API calls send data to a backend, but there is no login and no cookies.",
  },
  dynamic: {
    label: "Dynamic site",
    explain: "The page has a login (password field) or sets cookies.",
  },
};

function ProfilePanel({ profile }: { profile: SiteProfile }) {
  const text = siteKindText[profile.kind];
  const ev = profile.evidence;
  const facts: [string, number][] = [
    ["Forms", ev.forms],
    ["Password fields", ev.password_fields],
    ["Cookies set", ev.cookies],
    ["Scripts (inline / external)", ev.scripts_inline + ev.scripts_external],
    ["Third-party script hosts", ev.third_party_script_hosts.length],
    ["API calls in scripts", ev.api_markers],
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
      <p className="mt-3 text-[0.8125rem] text-ink-3">Why: {profile.reasons.join("; ")}.</p>
    </Panel>
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
    report.grade === "F" && (report.tls.status !== "ok" || !report.final_url.startsWith("https:"));

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
          <p>Grades start at 100 and lose 25 per high, 10 per medium and 4 per low finding.</p>
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
              {finding.evidence ? <Evidence label="Seen">{finding.evidence}</Evidence> : null}
              <ReasonCode>{finding.id}</ReasonCode>
            </>
          )}
        />
      )}

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

        {report.profile ? <ProfilePanel profile={report.profile} /> : null}
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

function HelpColumns({ hosted }: { hosted: boolean }) {
  return (
    <div className="grid gap-6 @2xl:grid-cols-2">
      <div>
        <h3 className="font-semibold">What the report contains</h3>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
          <li>A grade from A to F with the score and how it was worked out.</li>
          <li>Findings with the failed checks first, each with the evidence seen and how to fix it.</li>
          <li>The certificate and TLS result, the redirect chain and a profile of the site.</li>
        </ul>
      </div>
      <div>
        <h3 className="font-semibold">What the check does</h3>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
          <li>One GET request (plus any redirects) and one TLS handshake to the site you name.</li>
          <li>It reads HTTPS, the certificate, security headers and cookies. It does not crawl or attack.</li>
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
  const scan = useMutation({
    mutationFn: (input: { url: string; allowPrivate: boolean; siteType: SiteKind | null }) =>
      hosted ? api.webcheckHosted(input.url, input.siteType) : api.webcheck(input.url, input.allowPrivate, input.siteType),
  });
  const canScan = authorized && url.trim().length > 0 && !scan.isPending;

  function run() {
    if (!canScan) return;
    const target = /^[a-z][a-z0-9+.-]*:\/\//i.test(url.trim()) ? url.trim() : `https://${url.trim()}`;
    scan.mutate({ url: target, allowPrivate, siteType: siteType || null });
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    run();
  }

  const input = (
    <Panel as="section">
      <form onSubmit={submit} className="space-y-4" aria-describedby="webcheck-notice">
        <p id="webcheck-notice" className="flex gap-2 rounded-lg bg-inset px-3 py-2.5 text-[0.875rem] text-ink-2">
          <Icon name="info" size={18} className="mt-0.5 flex-none text-ink-3" />
          {hosted ? HOSTED_NOTICE : NOTICE}
        </p>
        <Field htmlFor="webcheck-url" label="Website address" hint="For example example.com or https://example.com/login">
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
              hint="Detected from the page if left blank. Choosing a type can only make the check stricter, never more lenient."
            >
              <select
                id="webcheck-site-type"
                className="field"
                value={siteType}
                onChange={(e) => {
                  setSiteType(e.target.value as SiteKind | "");
                }}
              >
                <option value="">Detect from the page</option>
                <option value="static">Static: pages only, no logins or forms</option>
                <option value="static_api">Static + backend: a contact form or API calls, no accounts</option>
                <option value="dynamic">Dynamic: logins, accounts, sessions or checkout</option>
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

        <div className="space-y-2">
          <Button type="submit" className="w-full" disabled={!canScan && !scan.isPending} pending={scan.isPending} pendingLabel="Scanning…">
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
          pendingText="Scanning the site…"
          doneText="Scan finished. The result is below."
        />
        {scan.isPending ? (
          <PendingPanel title="Connecting to the site">
            Sending one request and one TLS handshake, then checking the certificate, headers and cookies. This usually takes a few seconds.
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
