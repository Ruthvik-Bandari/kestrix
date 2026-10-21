// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useEffect, useRef, useState, type SubmitEvent } from "react";
import { Icon } from "../../components/Icon";
import {
  Badge,
  cx,
  ErrorState,
  Field,
  PageHeader,
  RawJson,
  SectionTitle,
  Spinner,
  Verdict,
} from "../../components/ui";
import {
  severityLabel,
  severityOrder,
  severityTone,
  tones,
  type Tone,
} from "../../components/tone";
import { api } from "../../lib/api";
import { isHosted } from "../../lib/mode";
import { slug } from "../../lib/download";
import { plural } from "../../lib/format";
import { scrollBehavior } from "../../lib/motion";
import type {
  SiteKind,
  SiteProfile,
  TlsStatus,
  WebFinding,
  WebReport,
} from "../../lib/types";
import { CliGuide } from "../guides/CliGuide";
import { useTitle } from "../../lib/useTitle";
import { HowItWorks, type HowItWorksContent } from "../../components/HowItWorks";

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
    <section
      aria-labelledby="profile-title"
      className="panel p-5 lg:col-span-2"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="profile-title" className="font-semibold">
          Site profile
        </h3>
        <Badge tone={profile.kind === "dynamic" ? "med" : "ok"}>
          {text.label}
        </Badge>
      </div>
      <p className="mt-2 max-w-[72ch] text-ink-2">
        {text.explain} Findings whose risk depends on what a site does are
        weighed for this profile; each one says when it was. HSTS, TLS and
        cookie flags are never lowered.
      </p>
      <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-1.5 text-[0.875rem] sm:grid-cols-3">
        {facts.map(([label, value]) => (
          <div
            key={label}
            className="flex justify-between gap-3 border-b border-line py-1"
          >
            <dt className="text-ink-3">{label}</dt>
            <dd className="font-mono">{value}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-[0.8125rem] text-ink-3">
        Why: {profile.reasons.join("; ")}.
      </p>
    </section>
  );
}

function GradeBadge({ report }: { report: WebReport }) {
  const style = tones[gradeTone[report.grade]];
  return (
    <div className="flex items-center gap-5">
      <div
        className={cx(
          "flex size-20 flex-none items-center justify-center rounded-2xl text-5xl font-semibold",
          style.soft,
        )}
        role="img"
        aria-label={`Grade ${report.grade}`}
      >
        {report.grade}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-[0.875rem] text-ink-2">Score</p>
        <p className="text-2xl font-semibold">
          {report.score}
          <span className="text-base font-normal text-ink-3"> / 100</span>
        </p>
        <div
          className="mt-2 h-2 w-full max-w-56 overflow-hidden rounded-full bg-inset"
          role="meter"
          aria-label="Score"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={report.score}
        >
          <div
            className={cx("h-full rounded-full", style.mark)}
            style={{ width: `${report.score}%` }}
          />
        </div>
      </div>
    </div>
  );
}

function FindingItem({ finding }: { finding: WebFinding }) {
  return (
    <li className="px-4 py-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={severityTone[finding.severity]}>
          {severityLabel[finding.severity]}
        </Badge>
        <h4 className="font-semibold">{finding.title}</h4>
      </div>
      <p className="mt-2 max-w-[72ch] text-ink-2">{finding.explanation}</p>
      <p className="mt-2 max-w-[72ch]">
        <span className="font-medium">How to fix: </span>
        <span className="text-ink-2">{finding.recommendation}</span>
      </p>
      {finding.context ? (
        <p className="mt-2 max-w-[72ch] text-[0.8125rem] text-ink-3">
          <span className="font-medium text-ink-2">
            Weighed for this site:{" "}
          </span>
          {finding.context}
        </p>
      ) : null}
      {finding.evidence ? (
        <p className="mt-2 text-[0.8125rem] text-ink-3">
          Seen: <code className="break-all text-ink-2">{finding.evidence}</code>
        </p>
      ) : null}
    </li>
  );
}

export function WebReportView({ report }: { report: WebReport }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    ref.current?.focus();
    ref.current?.scrollIntoView({ block: "start", behavior: scrollBehavior() });
  }, [report]);
  const tls = tlsText[report.tls.status];

  return (
    <section
      aria-labelledby="web-result"
      className="reveal mt-10 scroll-mt-6 border-t border-line pt-8"
    >
      <h2 id="web-result" ref={ref} tabIndex={-1} className="sr-only">
        Result for {report.final_url}
      </h2>
      <div className="grid gap-6 md:grid-cols-[auto_minmax(0,1fr)] md:items-center">
        <GradeBadge report={report} />
        <Verdict tone={gradeTone[report.grade]} title={headline(report)}>
          {report.grade === "F" &&
          (report.tls.status !== "ok" ||
            !report.final_url.startsWith("https:")) ? (
            <p>
              The grade is capped at F because the connection itself is not
              secure; every other protection depends on it.
            </p>
          ) : (
            <p>
              Grades start at 100 and lose 25 per high, 10 per medium and 4 per
              low finding.
            </p>
          )}
          {!report.headers_checked ? (
            <p className="mt-1">
              The page could not be fetched, so headers were not checked.
            </p>
          ) : null}
        </Verdict>
      </div>

      <div className="mt-8 grid gap-4 lg:grid-cols-2">
        <section aria-labelledby="tls-title" className="panel p-5">
          <div className="flex items-center justify-between gap-2">
            <h3 id="tls-title" className="font-semibold">
              Certificate and TLS
            </h3>
            <Badge tone={tls.tone}>{tls.label}</Badge>
          </div>
          <p className="mt-2 text-ink-2">{report.tls.detail ?? tls.explain}</p>
          <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-5 gap-y-1.5 text-[0.875rem]">
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
                  {new Date(report.tls.not_after).toLocaleDateString(
                    undefined,
                    { dateStyle: "medium" },
                  )}
                  {report.tls.days_remaining !== null ? (
                    <span
                      className={cx(
                        "ml-2",
                        report.tls.days_remaining < 14
                          ? "font-medium text-high"
                          : "text-ink-3",
                      )}
                    >
                      ({plural(report.tls.days_remaining, "day")} left)
                    </span>
                  ) : null}
                </dd>
              </>
            ) : null}
          </dl>
        </section>

        {report.profile ? <ProfilePanel profile={report.profile} /> : null}

        <section aria-labelledby="redirect-title" className="panel p-5">
          <h3 id="redirect-title" className="font-semibold">
            Redirect chain
          </h3>
          {report.redirect_chain.length === 0 ? (
            <p className="mt-2 text-ink-2">No response was received.</p>
          ) : (
            <ol className="mt-3 space-y-3">
              {report.redirect_chain.map((hop, i) => (
                <li key={`${hop.url}-${i}`} className="flex gap-3">
                  <span className="flex size-6 flex-none items-center justify-center rounded-full bg-inset text-xs font-medium text-ink-2">
                    {i + 1}
                  </span>
                  <div className="min-w-0">
                    <p className="font-mono text-[0.8125rem] break-all text-ink">
                      {hop.url}
                    </p>
                    <p className="text-[0.8125rem] text-ink-3">
                      HTTP {hop.status_code} · {hop.address} · {hop.elapsed_ms}{" "}
                      ms
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>

      <section aria-labelledby="findings-title" className="mt-10">
        <SectionTitle id="findings-title">Findings</SectionTitle>
        {report.findings.length === 0 ? (
          <p className="text-ink-2">
            Nothing to report: every header check passed.
          </p>
        ) : (
          <div className="space-y-6">
            {severityOrder.map((severity) => {
              const group = report.findings.filter(
                (f) => f.severity === severity,
              );
              if (group.length === 0) return null;
              return (
                <section key={severity} aria-labelledby={`sev-${severity}`}>
                  <h3
                    id={`sev-${severity}`}
                    className="mb-2 text-[0.9375rem] font-semibold text-ink-2"
                  >
                    {severityLabel[severity]} · {group.length}
                  </h3>
                  <ul className="divide-y divide-line rounded-lg border border-line bg-surface">
                    {group.map((finding) => (
                      <FindingItem key={finding.id} finding={finding} />
                    ))}
                  </ul>
                </section>
              );
            })}
          </div>
        )}
      </section>

      <div className="mt-10 space-y-3">
        <p className="text-[0.8125rem] text-ink-3">
          Took {report.timings.total_ms} ms (HTTP {report.timings.http_ms} ms,
          TLS {report.timings.tls_ms} ms). {report.notice}
        </p>
        <RawJson
          data={report}
          filename={`kestrix-webcheck-${slug(report.final_url)}.json`}
        />
      </div>
    </section>
  );
}

const hostedHowItWorks = (content: HowItWorksContent): HowItWorksContent => ({
  ...content,
  steps: content.steps.map((step) => step.replace("(public addresses only, unless you allow private ones)", "(public addresses only)")),
  doesNot: content.doesNot.map((line) =>
    line.startsWith("It is not offline") ? "It is not offline: Kestrix's server contacts the site you enter." : line,
  ),
});

const howItWorks: HowItWorksContent = {
  id: "webcheck",
  name: "Web check",
  purpose:
    "Grade how well a website you own, or are authorized to assess, protects its visitors at the connection and browser level.",
  steps: [
    "Enter the site's address and confirm you are allowed to check it.",
    "Kestrix validates the target (public addresses only, unless you allow private ones) and sends one GET request, following up to five redirects, plus one TLS handshake.",
    "It reads HTTPS and redirects, the certificate and its expiry, security headers and cookie flags, and profiles the page as static, static with an API, or dynamic to weigh what matters.",
    "You get an A to F grade from a fixed rubric and a concrete fix for every issue.",
  ],
  usefulWhen: [
    "After a deploy or a hosting change.",
    "To catch a certificate before it expires.",
    "To get a fix list for a small site.",
  ],
  doesNot: [
    "It does not crawl, fuzz, log in or scan ports, so it cannot find application bugs such as SQL injection.",
    "It is not offline: it contacts the site you enter, from this computer.",
  ],
};

export default function WebcheckPage() {
  useTitle("Web check");
  const hosted = isHosted();
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [siteType, setSiteType] = useState<SiteKind | "">("");
  const scan = useMutation({
    mutationFn: (input: {
      url: string;
      allowPrivate: boolean;
      siteType: SiteKind | null;
    }) =>
      hosted
        ? api.webcheckHosted(input.url, input.siteType)
        : api.webcheck(input.url, input.allowPrivate, input.siteType),
  });
  const canScan = authorized && url.trim().length > 0 && !scan.isPending;

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canScan) return;
    const target = /^[a-z][a-z0-9+.-]*:\/\//i.test(url.trim())
      ? url.trim()
      : `https://${url.trim()}`;
    scan.mutate({ url: target, allowPrivate, siteType: siteType || null });
  }

  return (
    <>
      <PageHeader
        title="Web check"
        lede="A passive check of a website's HTTPS setup and browser security headers, with a grade and a fix for every issue."
      />
      <HowItWorks content={hosted ? hostedHowItWorks(howItWorks) : howItWorks} />
      <form
        onSubmit={submit}
        className="panel max-w-3xl space-y-5 p-5 sm:p-6"
        aria-describedby="webcheck-notice"
      >
        <p
          id="webcheck-notice"
          className="flex gap-2 rounded-lg bg-inset px-3 py-2.5 text-[0.875rem] text-ink-2"
        >
          <Icon name="info" size={18} className="mt-0.5 flex-none text-ink-3" />
          {hosted ? HOSTED_NOTICE : NOTICE}
        </p>
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
            aria-describedby="webcheck-url-hint"
            placeholder="https://"
          />
        </Field>
        <Field
          htmlFor="webcheck-site-type"
          label="What is this site? (optional)"
          hint="Detected from the page if left blank. Choosing a type can only make the check stricter, never more lenient."
        >
          <select
            id="webcheck-site-type"
            className="field"
            value={siteType}
            aria-describedby="webcheck-site-type-hint"
            onChange={(e) => {
              setSiteType(e.target.value as SiteKind | "");
            }}
          >
            <option value="">Detect from the page</option>
            <option value="static">
              Static: pages only, no logins or forms
            </option>
            <option value="static_api">
              Static + backend: a contact form or API calls, no accounts
            </option>
            <option value="dynamic">
              Dynamic: logins, accounts, sessions or checkout
            </option>
          </select>
        </Field>
        <div className="space-y-3">
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
                {hosted
                  ? "I own this website or am authorized to test it"
                  : "I own this site or am authorized to test it"}
              </span>
              <span className="hint block">
                Required. Scanning sites without permission may break their
                terms or the law.
              </span>
            </span>
          </label>
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
                <span className="font-medium">
                  Allow private and local addresses
                </span>
                <span className="hint block">
                  For a lab or home server you own, such as 192.168.x.x or
                  localhost.
                </span>
              </span>
            </label>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button type="submit" className="btn btn-primary" disabled={!canScan}>
            {scan.isPending ? <Spinner /> : <Icon name="search" size={16} />}
            {scan.isPending ? "Scanning…" : "Scan"}
          </button>
          {!authorized ? (
            <span className="hint">
              Confirm authorization to enable scanning.
            </span>
          ) : null}
        </div>
      </form>

      <div aria-live="polite" className="sr-only">
        {scan.isPending
          ? "Scanning the site…"
          : scan.isSuccess
            ? "Scan finished. Results below."
            : ""}
      </div>
      {scan.isError ? (
        <div className="mt-8">
          <ErrorState error={scan.error} />
        </div>
      ) : null}
      {scan.data ? <WebReportView report={scan.data} /> : null}
      {isHosted() ? null : (
        <div className="mt-12">
          <CliGuide tool="webcheck" />
        </div>
      )}
    </>
  );
}
