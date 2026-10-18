import { useMutation } from "@tanstack/react-query";
import { useState, type SubmitEvent } from "react";
import { Icon } from "../../components/Icon";
import { Badge, ErrorState, Field, RawJson, SectionTitle, Spinner, Verdict } from "../../components/ui";
import type { Tone } from "../../components/tone";
import { api } from "../../lib/api";
import { slug } from "../../lib/download";
import type { UrlReport } from "../../lib/types";
import { FindingsList } from "./FindingsList";

const levelMeta: Record<UrlReport["level"], { tone: Tone; label: string; title: string }> = {
  none: { tone: "neutral", label: "No signals", title: "None of the phishing checks fired for this link." },
  low: { tone: "low", label: "Low", title: "A few weak warning signs. Look closely before you trust it." },
  medium: { tone: "med", label: "Medium", title: "Several warning signs. Treat this link with suspicion." },
  high: { tone: "crit", label: "High", title: "Strong phishing signals. Don't enter passwords or payment details here." },
};

function Report({ report }: { report: UrlReport }) {
  const meta = levelMeta[report.level];
  const lookalike = report.unicode_host !== report.host;
  return (
    <section aria-label="Link check result" className="reveal mt-8 space-y-6">
      <Verdict tone={meta.tone} title={meta.title}>
        <p>{report.score_note}</p>
      </Verdict>
      <div className="grid gap-4 md:grid-cols-[auto_minmax(0,1fr)]">
        <div className="panel min-w-48 p-5">
          <p className="text-[0.875rem] text-ink-2">Heuristic score, not a probability</p>
          <p className="mt-1 text-3xl font-semibold">
            {report.score}
            <span className="text-base font-normal text-ink-3"> / 100</span>
          </p>
          <div className="mt-2">
            <Badge tone={meta.tone}>{meta.label}</Badge>
          </div>
        </div>
        <dl className="panel grid grid-cols-[auto_1fr] content-start gap-x-5 gap-y-1.5 p-5 text-[0.875rem]">
          <dt className="text-ink-3">Host</dt>
          <dd className="font-mono break-all">{report.host}</dd>
          <dt className="text-ink-3">Displayed as</dt>
          <dd className="break-all">
            {report.unicode_host}
            {lookalike ? (
              <span className="ml-2">
                <Badge tone="high">International characters</Badge>
              </span>
            ) : null}
          </dd>
          <dt className="text-ink-3">Registered domain</dt>
          <dd className="font-mono break-all">{report.registrable_domain ?? "— (IP address)"}</dd>
          <dt className="text-ink-3">Scheme</dt>
          <dd>{report.scheme ?? "none given"}</dd>
        </dl>
      </div>
      {report.findings.length > 0 ? (
        <section aria-labelledby="url-findings">
          <SectionTitle id="url-findings">Signals that fired</SectionTitle>
          <FindingsList findings={report.findings} />
        </section>
      ) : null}
      <RawJson data={report} filename={`kestrix-url-${slug(report.host)}.json`} />
    </section>
  );
}

export function UrlAnalyzer() {
  const [url, setUrl] = useState("");
  const check = useMutation({ mutationFn: api.analyzeUrl });

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (url.trim()) check.mutate(url.trim());
  }

  return (
    <>
      <form onSubmit={submit} className="panel max-w-3xl space-y-4 p-5 sm:p-6">
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
            aria-describedby="url-input-hint"
            placeholder="https://"
          />
        </Field>
        <button type="submit" className="btn btn-primary" disabled={!url.trim() || check.isPending}>
          {check.isPending ? <Spinner /> : <Icon name="search" size={16} />}
          Check link
        </button>
      </form>
      <div aria-live="polite">
        {check.isError ? (
          <div className="mt-6">
            <ErrorState error={check.error} />
          </div>
        ) : null}
        {check.data ? <Report report={check.data} /> : null}
      </div>
    </>
  );
}
