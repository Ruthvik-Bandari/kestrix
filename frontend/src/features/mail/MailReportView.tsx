// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { IconName } from "../../components/Icon";
import {
  Evidence,
  FindingList,
  FindingTally,
  NextStep,
  ReasonCode,
  ReportSection,
  useFocusOnArrival,
  VerdictCard,
} from "../../components/report";
import type { Tone } from "../../components/tone";
import { CopyButton, RawJson } from "../../components/ui";
import { plural } from "../../lib/format";
import type { MailAnalyzer, MailReport, MailVerdict } from "../../lib/types";

export const analyzerLabel: Record<MailAnalyzer, string> = {
  auth: "Sender authentication",
  sender: "Sender addresses",
  lookalike: "Look-alike domain",
  links: "Links",
  attachments: "Attachments",
  intent: "Wording (heuristic)",
};

interface VerdictCopy {
  tone: Tone;
  icon: IconName;
  label: string;
  /** One sentence under the label. */
  title: string;
  body: string;
  /** Reviewed advice for this verdict; presentation copy, not an API field. */
  next: string;
}

export const verdictMeta: Record<MailVerdict, VerdictCopy> = {
  malicious: {
    tone: "crit",
    icon: "octagon",
    label: "Malicious",
    title: "Strong signs of phishing, impersonation or malware.",
    body: "Read the findings before you take any action on this message.",
    next: "Don't click its links, open its attachments or reply. If it claims to come from someone you know or a company you use, contact them another way, such as a phone number or website you already trust. Consider reporting it to your mail provider or IT team.",
  },
  suspicious: {
    tone: "med",
    icon: "alert",
    label: "Suspicious",
    title: "Some checks raised warnings.",
    body: "Warnings are not proof. Weigh them against what you expected from this sender.",
    next: "Hold off on links, attachments and replies until the findings are explained. Verify any request for money, sign-in details or personal information through a separate, trusted channel.",
  },
  insufficient_evidence: {
    tone: "neutral",
    icon: "help",
    label: "Insufficient evidence",
    title: "The sender could not be checked, so there is no verdict either way.",
    body: "The message has no authentication results Kestrix can trust, often because it was forwarded or saved from an app that drops them. This is not a clean result: nothing else fired, but that is not the same as safe.",
    next: "Confirm the sender another way before you act on it. If the message was forwarded, save the original from the mailbox that first received it and check that copy.",
  },
  clean: {
    tone: "ok",
    icon: "checkCircle",
    label: "No checks fired",
    title: "None of the checks found a warning sign.",
    body: "This means no warning sign was found, not that the message is safe. Heuristic checks miss things.",
    next: "Stay careful with unexpected requests for money, sign-in details or urgency, even when nothing fired. If something feels wrong, confirm it with the sender through a channel you already trust.",
  },
};

function MessagePanel({ report }: { report: MailReport }) {
  const { counts } = report;
  return (
    <ReportSection as="aside" id="mail-message" icon="mail" title="Message">
      <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-3 gap-y-2.5 text-[0.875rem]">
        <dt className="text-ink-3">Subject</dt>
        <dd className="break-words text-ink">{report.subject ?? "(no subject)"}</dd>
        <dt className="text-ink-3">From</dt>
        <dd className="break-all text-ink">{report.from_address ?? "no address found"}</dd>
        <dt className="text-ink-3">Contents</dt>
        <dd className="text-ink">
          {plural(counts.parts, "MIME part")}, {plural(counts.links, "link")}, {plural(counts.attachments, "attachment")}
        </dd>
        <dt className="text-ink-3">SHA-256</dt>
        <dd className="min-w-0">
          <code className="block rounded-md border border-line bg-inset px-2 py-1.5 text-[0.75rem] break-all text-ink">{report.sha256}</code>
          <CopyButton text={report.sha256} label="Copy SHA-256 of the message" className="-ml-2 mt-1" />
        </dd>
      </dl>
      <p className="mt-3 text-[0.8125rem] text-ink-3">
        The report keeps these details and the findings. The message body, Reply-To and date are not part of it.
      </p>
    </ReportSection>
  );
}

function Limitations({ report }: { report: MailReport }) {
  return (
    <ReportSection id="mail-limits" icon="info" title="What this check can tell you">
      <p className="text-[0.875rem] text-ink-2">{report.notice}</p>
    </ReportSection>
  );
}

export function MailReportView({ report }: { report: MailReport }) {
  const heading = useFocusOnArrival(report);
  const meta = verdictMeta[report.verdict];
  const { counts } = report;
  return (
    <section aria-labelledby="mail-result" className="@container reveal scroll-mt-6 space-y-6">
      <VerdictCard
        tone={meta.tone}
        icon={meta.icon}
        label={meta.label}
        headingId="mail-result"
        headingRef={heading}
        title={meta.title}
        aside={
          <div className="space-y-3">
            <FindingTally findings={report.findings} />
            <p className="text-[0.8125rem] text-ink-2">
              Heuristic score <span className="font-medium text-ink">{report.heuristic_score} / 100</span>, not a probability
            </p>
          </div>
        }
      >
        <p>{meta.body}</p>
        {report.verdict_reason ? (
          <p className="mt-2 text-[0.875rem] text-ink-2">
            <span className="font-medium text-ink">Why: </span>
            {report.verdict_reason}
          </p>
        ) : null}
      </VerdictCard>

      <NextStep>{meta.next}</NextStep>

      {counts.text_truncated || counts.links_truncated ? (
        <p className="max-w-[68ch] text-[0.875rem] text-ink-2">
          This message is very large, so only part of it was checked:
          {counts.text_truncated ? " the text was cut at the scan limit" : ""}
          {counts.text_truncated && counts.links_truncated ? " and" : ""}
          {counts.links_truncated ? " only the first links were checked" : ""}.
        </p>
      ) : null}

      <div className="grid items-start gap-6 @4xl:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0">
          {report.findings.length > 0 ? (
            <FindingList
              id="mail-findings"
              heading="What Kestrix found"
              findings={report.findings}
              keyOf={(finding, index) => `${finding.id}-${index.toString()}`}
              renderDetail={(finding) => (
                <>
                  <p className="max-w-[68ch] text-ink-2">{finding.explanation}</p>
                  {finding.evidence ? <Evidence>{finding.evidence}</Evidence> : null}
                  <ReasonCode>
                    {analyzerLabel[finding.analyzer]} · {finding.id}
                  </ReasonCode>
                </>
              )}
            />
          ) : (
            <ReportSection id="mail-no-findings" icon="listChecks" title="What Kestrix found" count={0} flat>
              <p className="max-w-[68ch] text-ink-2">No findings. None of the checks fired for this message.</p>
            </ReportSection>
          )}
        </div>
        <div className="grid min-w-0 items-start gap-4 @2xl:grid-cols-2 @4xl:grid-cols-1">
          <MessagePanel report={report} />
          <Limitations report={report} />
        </div>
      </div>

      <RawJson data={report} filename={`kestrix-mail-${report.sha256.slice(0, 12)}.json`} />
    </section>
  );
}
