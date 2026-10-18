// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, type ReactNode } from "react";
import { Icon } from "../../components/Icon";
import { Badge, CodeBlock, CopyButton, cx, Disclosure, RawJson, SectionTitle } from "../../components/ui";
import { downloadText, slug } from "../../lib/download";
import { shortHash } from "../../lib/format";
import { scrollBehavior } from "../../lib/motion";
import type { CandidateEntry, DetectReport, FieldCoverage, ReplayResult } from "../../lib/types";
import { CountsTable, type SplitCounts } from "./CountsTable";
import { DiffViewer } from "./DiffViewer";
import { OutcomeBanner } from "./OutcomeBanner";
import { describePatch, familyMeta, outcomeMeta, policyFailureText, selectedCandidate } from "./describe";

function Block({ title, children, id }: { title: string; children: ReactNode; id: string }) {
  return (
    <section aria-labelledby={id} className="mt-10">
      <SectionTitle id={id}>{title}</SectionTitle>
      {children}
    </section>
  );
}

function countsLine(result: ReplayResult): string {
  if (result.error) return "replay failed";
  const c = result.counts;
  return `caught ${c.tp}, missed ${c.fn}, false alarms ${c.fp}`;
}

function CoverageTable({ rows }: { rows: FieldCoverage[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Rule field</th>
            <th scope="col">Looked up as</th>
            <th scope="col">In your events</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const share = row.total ? row.present / row.total : 0;
            const tone = row.present === 0 ? "crit" : share < 1 ? "med" : "ok";
            return (
              <tr key={row.sigma_field}>
                <th scope="row" className="font-mono text-[0.8125rem]">
                  {row.sigma_field}
                </th>
                <td className="font-mono text-[0.8125rem] break-all">
                  {row.index_field}
                  {row.mapped ? null : <span className="ml-2 font-sans text-ink-3">(default, not in mapping)</span>}
                </td>
                <td>
                  <Badge tone={tone}>
                    {row.present === 0 ? "Missing" : share < 1 ? "Partly present" : "Present"} · {row.present}/{row.total}
                  </Badge>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function CandidateItem({
  entry,
  selected,
  hasValidation,
}: {
  entry: CandidateEntry;
  selected: boolean;
  hasValidation: boolean;
}) {
  const { candidate } = entry;
  const validated = entry.passed !== undefined;
  return (
    <li className={cx("px-4 py-4", selected && "bg-accent-soft/40")}>
      <div className="flex flex-wrap items-center gap-2">
        <code className="text-ink">{candidate.proposal_id}</code>
        {selected ? <Badge tone="accent" icon="check">Selected</Badge> : null}
        {validated ? (
          entry.passed ? (
            <Badge tone="ok">Passed policy</Badge>
          ) : (
            <Badge tone="crit" icon="xCircle">Failed policy</Badge>
          )
        ) : (
          <Badge tone="neutral" icon="info">
            {hasValidation ? "Ranked lower, not validated" : "Development screening only"}
          </Badge>
        )}
        <span className="text-[0.8125rem] text-ink-3">{candidate.patch_kind === "mapping" ? "Mapping change" : "Rule change"}</span>
      </div>
      <ul className="mt-2 space-y-1">
        {candidate.patch.map((p, i) => (
          <li key={i} className="break-words text-ink">
            {describePatch(p)}
          </li>
        ))}
      </ul>
      <p className="mt-2 text-[0.875rem] text-ink-2">
        Development: {countsLine(entry.development)}
        {entry.validation ? ` · Validation: ${countsLine(entry.validation)}` : ""}
      </p>
      {entry.policy_failures && entry.policy_failures.length > 0 ? (
        <ul className="mt-2 space-y-1 text-[0.875rem]">
          {entry.policy_failures.map((code) => (
            <li key={code} className="flex gap-2 text-crit">
              <Icon name="xCircle" size={16} className="mt-0.5 flex-none" />
              <span>
                {policyFailureText(code)} <code className="text-xs text-ink-3">{code}</code>
              </span>
            </li>
          ))}
        </ul>
      ) : null}
      <details className="mt-2 text-[0.875rem]">
        <summary className="inline-flex min-h-8 items-center text-ink-2 hover:text-ink">Engine query</summary>
        <div className="mt-2">
          <CodeBlock label={`Lucene query for ${candidate.proposal_id}`} maxHeight="10rem">
            {(entry.validation ?? entry.development).query ?? "(no query)"}
          </CodeBlock>
        </div>
      </details>
    </li>
  );
}

function evidenceName(report: DetectReport): string {
  const subject = report.case?.case_id ?? report.rule?.title ?? "rule";
  return `kestrix-detect-${slug(subject)}-${report.outcome}.json`;
}

export function ReportView({ report }: { report: DetectReport }) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    headingRef.current?.focus();
    headingRef.current?.scrollIntoView({ block: "start", behavior: scrollBehavior() });
  }, [report]);

  const chosen = selectedCandidate(report);
  const splits: SplitCounts[] = [];
  if (report.original) {
    splits.push({ split: "development", before: report.original.development, after: chosen?.development });
    if (report.original.validation)
      splits.push({ split: "validation", before: report.original.validation, after: chosen?.validation });
  }
  const json = JSON.stringify(report, null, 2);
  const artifactName = report.artifact?.kind === "mapping" ? "mapping.yml" : "rule.yml";

  return (
    <section aria-labelledby="report-title" className="reveal mt-10 scroll-mt-6 border-t border-line pt-8">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="report-title" ref={headingRef} tabIndex={-1} className="text-xl font-semibold tracking-[-0.01em] outline-none">
            {report.case?.title ?? report.rule?.title ?? "Repair result"}
          </h2>
          <p className="mt-1 text-[0.875rem] text-ink-2">
            Outcome <span className="font-medium text-ink">{outcomeMeta[report.outcome].label}</span>
            {report.mapping ? (
              <>
                {" "}· mapping <code>{report.mapping.name}</code>
              </>
            ) : null}
            {typeof report.manifest.elapsed_ms === "number" ? ` · ${report.manifest.elapsed_ms} ms` : null}
          </p>
        </div>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => {
            downloadText(evidenceName(report), json);
          }}
        >
          <Icon name="download" size={16} />
          Download evidence JSON
        </button>
      </div>

      <OutcomeBanner report={report} />

      {report.diff && report.artifact ? (
        <Block title="What changed" id="report-diff">
          <DiffViewer diff={report.diff} label={artifactName} />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => {
                if (report.artifact) downloadText(artifactName, report.artifact.content, "application/yaml");
              }}
            >
              <Icon name="download" size={15} />
              Download fixed {artifactName}
            </button>
            <CopyButton text={report.artifact.content} label={`Copy fixed ${artifactName}`} />
            <span className="text-[0.8125rem] text-ink-3">
              SHA-256 <code title={report.artifact.sha256}>{shortHash(report.artifact.sha256)}</code>
            </span>
          </div>
        </Block>
      ) : null}

      {splits.length > 0 ? (
        <Block title="Before and after" id="report-counts">
          <p className="mb-3 max-w-[68ch] text-ink-2">
            Counts come from replaying the rule on the pinned engine against labeled events. Validation events are a
            separate set that decides acceptance; development events only screen ideas.
          </p>
          <CountsTable splits={splits} />
        </Block>
      ) : null}

      {report.telemetry_recommendations && report.telemetry_recommendations.length > 0 ? (
        <Block title="What to collect" id="report-telemetry">
          <ul className="space-y-3">
            {report.telemetry_recommendations.map((rec) => (
              <li key={rec.field} className="rounded-lg border border-line bg-surface px-4 py-3">
                <p className="font-medium">
                  Collect <code>{rec.field}</code>
                </p>
                <p className="mt-1 text-ink-2">{rec.guidance}</p>
              </li>
            ))}
          </ul>
        </Block>
      ) : null}

      {report.hypotheses && report.hypotheses.length > 0 ? (
        <Block title="Diagnosis" id="report-hypotheses">
          <ul className="space-y-3">
            {report.hypotheses.map((h, i) => (
              <li key={i} className="rounded-lg border border-line bg-surface px-4 py-3">
                <p className="font-medium">{familyMeta[h.family].label}</p>
                <p className="mt-0.5 text-ink-2">{familyMeta[h.family].explain}</p>
                <dl className="mt-2 grid gap-x-6 gap-y-1 text-[0.875rem] sm:grid-cols-[auto_1fr]">
                  {h.fields.length > 0 ? (
                    <>
                      <dt className="text-ink-3">Fields</dt>
                      <dd className="font-mono break-all">{h.fields.join(", ")}</dd>
                    </>
                  ) : null}
                  {h.alternative_index_fields.length > 0 ? (
                    <>
                      <dt className="text-ink-3">Seen instead</dt>
                      <dd className="font-mono break-all">{h.alternative_index_fields.join(", ")}</dd>
                    </>
                  ) : null}
                  {h.evidence_event_ids.length > 0 ? (
                    <>
                      <dt className="text-ink-3">Evidence events</dt>
                      <dd className="font-mono break-all">{h.evidence_event_ids.join(", ")}</dd>
                    </>
                  ) : null}
                  <dt className="text-ink-3">Reason codes</dt>
                  <dd className="font-mono break-all">{h.reason_codes.join(", ")}</dd>
                </dl>
              </li>
            ))}
          </ul>
        </Block>
      ) : null}

      {report.coverage && report.coverage.length > 0 ? (
        <Block title="Field coverage" id="report-coverage">
          <CoverageTable rows={report.coverage} />
        </Block>
      ) : null}

      {report.candidates && report.candidates.length > 0 ? (
        <Block title={`Candidates tried (${report.candidates.length})`} id="report-candidates">
          <p className="mb-3 max-w-[68ch] text-ink-2">
            Each candidate is a small, bounded edit that improved development replay. They are ranked on development
            events, and only the top one is replayed on validation events, so the acceptance policy sees the validation
            set exactly once.
          </p>
          <ol className="divide-y divide-line overflow-hidden rounded-lg border border-line bg-surface">
            {report.candidates.map((entry) => (
              <CandidateItem
                key={entry.candidate.proposal_id}
                entry={entry}
                selected={entry.candidate.proposal_id === report.selected}
                hasValidation={Boolean(report.datasets?.validation)}
              />
            ))}
          </ol>
        </Block>
      ) : null}

      <Block title="Technical detail" id="report-technical">
        <div className="space-y-3">
          <Disclosure summary="Run provenance and hashes">
            <dl className="grid gap-x-6 gap-y-2 text-[0.875rem] sm:grid-cols-[auto_1fr]">
              {report.rule ? (
                <>
                  <dt className="text-ink-3">Rule SHA-256</dt>
                  <dd className="font-mono break-all">{report.rule.sha256}</dd>
                </>
              ) : null}
              {report.mapping ? (
                <>
                  <dt className="text-ink-3">Mapping SHA-256</dt>
                  <dd className="font-mono break-all">{report.mapping.sha256}</dd>
                </>
              ) : null}
              {report.datasets ? (
                <>
                  <dt className="text-ink-3">Development set</dt>
                  <dd className="font-mono break-all">{report.datasets.development}</dd>
                  <dt className="text-ink-3">Validation set</dt>
                  <dd className="font-mono break-all">{report.datasets.validation ?? "not supplied"}</dd>
                </>
              ) : null}
              {report.original?.development.query ? (
                <>
                  <dt className="text-ink-3">Original query</dt>
                  <dd className="font-mono break-all">{report.original.development.query}</dd>
                </>
              ) : null}
              {Object.entries(report.manifest).map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-ink-3">{key}</dt>
                  <dd className="font-mono break-all">{value === null ? "—" : String(value as string | number)}</dd>
                </div>
              ))}
            </dl>
          </Disclosure>
          <RawJson data={report} filename={evidenceName(report)} summary="Full evidence JSON" />
        </div>
      </Block>
    </section>
  );
}
