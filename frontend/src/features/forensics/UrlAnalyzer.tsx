// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useState, type SubmitEvent } from "react";
import { DataNote } from "../../components/DataNote";
import { Icon } from "../../components/Icon";
import {
  FailedRequest,
  FindingList,
  FindingTally,
  LiveStatus,
  PendingPanel,
  ReasonCode,
  ReportSection,
  ToolLayout,
  useFocusOnArrival,
  VerdictCard,
} from "../../components/report";
import { ReportOutline, stageOf, Workspace } from "../../components/toolframe";
import type { Tone } from "../../components/tone";
import { Badge, Button, CopyButton, Field, RawJson } from "../../components/ui";
import { api } from "../../lib/api";
import { slug } from "../../lib/download";
import type { UrlReport } from "../../lib/types";
import { outlines } from "../tools/frame";

export const levelMeta: Record<UrlReport["level"], { tone: Tone; label: string; heading: string; title: string }> = {
  none: {
    tone: "neutral",
    label: "No signals",
    heading: "No signals fired",
    title: "None of the phishing checks fired for this link. That is not a guarantee it is safe.",
  },
  low: { tone: "low", label: "Low", heading: "Low suspicion", title: "A few weak warning signs. Look closely before you trust it." },
  medium: { tone: "med", label: "Medium", heading: "Medium suspicion", title: "Several warning signs. Treat this link with suspicion." },
  high: {
    tone: "crit",
    label: "High",
    heading: "High suspicion",
    title: "Strong phishing signals. Don't enter passwords or payment details here.",
  },
};

/** The part of the host before the registered domain, for example "login" in login.example.com. */
function subdomainOf(report: UrlReport): string | null {
  const domain = report.registrable_domain;
  if (!domain || !report.host.endsWith(`.${domain}`)) return null;
  return report.host.slice(0, report.host.length - domain.length - 1) || null;
}

export function UrlReportView({ report }: { report: UrlReport }) {
  const heading = useFocusOnArrival(report);
  const meta = levelMeta[report.level];
  const international = report.unicode_host !== report.host;
  const subdomain = subdomainOf(report);
  return (
    <section aria-labelledby="url-result" className="@container reveal scroll-mt-6 space-y-6">
      <VerdictCard
        tone={meta.tone}
        label={meta.heading}
        headingId="url-result"
        headingRef={heading}
        title={meta.title}
        aside={
          <div className="space-y-3">
            <FindingTally findings={report.findings} />
            <p className="text-[0.8125rem] text-ink-2">
              Heuristic score <span className="font-medium text-ink">{report.score} / 100</span>, not a probability
            </p>
          </div>
        }
      >
        <p>{report.score_note}</p>
      </VerdictCard>

      <ReportSection id="url-parts" icon="link" title="How the link breaks down">
        <p className="hint">The link is analyzed as text. It was not opened or fetched.</p>
        <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-5 gap-y-2 text-[0.875rem]">
          <dt className="text-ink-3">Link</dt>
          <dd className="min-w-0">
            <code className="block rounded-md border border-line bg-inset px-2 py-1.5 break-all text-ink">{report.url}</code>
            <CopyButton text={report.url} label="Copy the link as text" className="-ml-2 mt-1" />
          </dd>
          <dt className="text-ink-3">Scheme</dt>
          <dd>{report.scheme ?? "none given"}</dd>
          <dt className="text-ink-3">Subdomain</dt>
          <dd className="font-mono break-all">{subdomain ?? "none"}</dd>
          <dt className="text-ink-3">Registered domain</dt>
          <dd className="font-mono break-all">{report.registrable_domain ?? "— (IP address)"}</dd>
          <dt className="text-ink-3">Host</dt>
          <dd className="font-mono break-all">{report.host}</dd>
          <dt className="text-ink-3">Displayed as</dt>
          <dd className="break-all">
            {report.unicode_host}
            {international ? (
              <span className="ml-2">
                <Badge tone="high">International characters</Badge>
              </span>
            ) : null}
          </dd>
        </dl>
      </ReportSection>

      {report.findings.length > 0 ? (
        <FindingList
          id="url-findings"
          heading="Signals that fired"
          findings={report.findings}
          keyOf={(finding) => finding.id}
          renderDetail={(finding) => (
            <>
              <p className="max-w-[68ch] text-ink-2">{finding.explanation}</p>
              <ReasonCode>{finding.id}</ReasonCode>
            </>
          )}
        />
      ) : null}
      <RawJson data={report} filename={`kestrix-url-${slug(report.host)}.json`} />
    </section>
  );
}

export function UrlAnalyzer() {
  const [url, setUrl] = useState("");
  const check = useMutation({ mutationFn: api.analyzeUrl });

  function run() {
    if (url.trim()) check.mutate(url.trim());
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    run();
  }

  const input = (
    <form onSubmit={submit} aria-label="Check a link">
      <Workspace
        steps={[
          {
            key: "link",
            title: "Paste the link",
            children: (
              <Field
                htmlFor="url-input"
                label="Link to check"
                hint="Paste a link from an email or message. It is analyzed as text only and never opened."
              >
                <input
                  id="url-input"
                  className="field font-mono"
                  type="text"
                  inputMode="url"
                  spellCheck={false}
                  autoComplete="off"
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
                  }}
                  placeholder="https://"
                />
              </Field>
            ),
          },
          {
            key: "run",
            title: "Check it",
            run: true,
            children: (
              <>
                <Button type="submit" className="w-full" disabled={!url.trim()} pending={check.isPending} pendingLabel="Checking…">
                  <Icon name="search" size={16} />
                  Check link
                </Button>
                <DataNote subject="The link" />
              </>
            ),
          },
        ]}
      />
    </form>
  );

  const stage = stageOf({ ready: url.trim().length > 0, pending: check.isPending, failed: check.isError, done: Boolean(check.data) });

  return (
    <ToolLayout input={input} stage={stage}>
      <LiveStatus
        pending={check.isPending}
        done={check.isSuccess}
        pendingText="Checking the link…"
        doneText="Check finished. The result is below."
      />
      {check.isPending ? (
        <PendingPanel title="Checking the link">
          Splitting the address into its parts and looking for common phishing signs. Nothing is fetched.
        </PendingPanel>
      ) : check.isError ? (
        <FailedRequest error={check.error} onRetry={run} />
      ) : check.data ? (
        <UrlReportView report={check.data} />
      ) : (
        <ReportOutline sections={outlines["forensics-url"]}>
          <div>
            <h3 className="font-semibold">Good to know</h3>
            <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
              <li>The link is never opened, fetched or resolved, so a page that has since changed is not seen.</li>
              <li>No signals is not a guarantee the link is safe.</li>
              <li>The level and score are a rule-based estimate, not a probability.</li>
              <li>Prefer typing a known address yourself over following an unexpected link.</li>
            </ul>
          </div>
        </ReportOutline>
      )}
    </ToolLayout>
  );
}
