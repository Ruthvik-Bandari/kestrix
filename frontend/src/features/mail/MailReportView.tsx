// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef } from "react";
import type { IconName } from "../../components/Icon";
import { Badge, CopyButton, RawJson, SectionTitle, Verdict } from "../../components/ui";
import type { Tone } from "../../components/tone";
import { plural } from "../../lib/format";
import { scrollBehavior } from "../../lib/motion";
import type { MailReport, MailVerdict } from "../../lib/types";
import { MailFindings } from "./MailFindings";

export const verdictMeta: Record<MailVerdict, { tone: Tone; icon: IconName; label: string; title: string; body: string }> = {
  malicious: {
    tone: "crit",
    icon: "octagon",
    label: "Malicious",
    title: "Malicious: strong signs of phishing, impersonation or malware.",
    body: "Don't click its links, open its attachments or reply. If it claims to come from someone you know, contact them another way.",
  },
  suspicious: {
    tone: "med",
    icon: "alert",
    label: "Suspicious",
    title: "Suspicious: some checks raised warnings.",
    body: "Read the findings below before you act on this message. Verify any request for money or sign-in details another way.",
  },
  insufficient_evidence: {
    tone: "neutral",
    icon: "help",
    label: "Insufficient evidence",
    title: "Insufficient evidence: the sender could not be checked.",
    body: "The message has no authentication results Kestrix can trust, often because it was forwarded or saved from an app that drops them. Nothing else fired, but that is not the same as safe.",
  },
  clean: {
    tone: "ok",
    icon: "checkCircle",
    label: "Clean",
    title: "Clean: none of the checks fired.",
    body: "This means no warning sign was found, not that the message is safe. Stay careful with unexpected requests.",
  },
};

export function MailReportView({ report }: { report: MailReport }) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    ref.current?.focus();
    ref.current?.scrollIntoView({ block: "start", behavior: scrollBehavior() });
  }, [report]);
  const meta = verdictMeta[report.verdict];
  const { counts } = report;
  return (
    <section aria-labelledby="mail-result" className="reveal mt-10 scroll-mt-6 border-t border-line pt-8">
      <h2 id="mail-result" ref={ref} tabIndex={-1} className="mb-4 text-xl font-semibold break-words outline-none">
        {report.subject ?? "(no subject)"}
      </h2>
      <Verdict tone={meta.tone} icon={meta.icon} title={meta.title}>
        <p>{meta.body}</p>
      </Verdict>

      <div className="mt-6 grid gap-4 md:grid-cols-[auto_minmax(0,1fr)]">
        <div className="panel min-w-48 p-5">
          <p className="text-[0.875rem] text-ink-2">Heuristic score, not a probability</p>
          <p className="mt-1 text-3xl font-semibold">
            {report.heuristic_score}
            <span className="text-base font-normal text-ink-3"> / 100</span>
          </p>
          <div className="mt-2">
            <Badge tone={meta.tone} icon={meta.icon}>
              {meta.label}
            </Badge>
          </div>
        </div>
        <dl className="panel grid grid-cols-[auto_1fr] content-start gap-x-5 gap-y-1.5 p-5 text-[0.875rem]">
          <dt className="text-ink-3">From</dt>
          <dd className="break-all">{report.from_address ?? "no address found"}</dd>
          <dt className="text-ink-3">Contents</dt>
          <dd>
            {plural(counts.parts, "MIME part")}, {plural(counts.links, "link")}, {plural(counts.attachments, "attachment")}
          </dd>
          <dt className="text-ink-3">Findings</dt>
          <dd>{plural(report.findings.length, "finding")}</dd>
          <dt className="text-ink-3">SHA-256</dt>
          <dd className="flex items-start gap-2">
            <code className="min-w-0 flex-1 pt-1.5 text-[0.75rem] break-all">{report.sha256}</code>
            <CopyButton text={report.sha256} label="Copy SHA-256 of the message" className="flex-none" />
          </dd>
        </dl>
      </div>
      {counts.text_truncated || counts.links_truncated ? (
        <p className="mt-3 text-[0.875rem] text-ink-2">
          This message is very large, so only part of it was checked:
          {counts.text_truncated ? " the text was cut at the scan limit" : ""}
          {counts.text_truncated && counts.links_truncated ? " and" : ""}
          {counts.links_truncated ? " only the first links were checked" : ""}.
        </p>
      ) : null}

      <section aria-labelledby="mail-findings" className="mt-10">
        <SectionTitle id="mail-findings">What Kestrix found</SectionTitle>
        {report.findings.length > 0 ? (
          <MailFindings findings={report.findings} />
        ) : (
          <p className="text-ink-2">No findings. None of the checks fired for this message.</p>
        )}
      </section>

      <p className="mt-8 max-w-[72ch] text-[0.875rem] text-ink-3">{report.notice}</p>
      <div className="mt-4">
        <RawJson data={report} filename={`kestrix-mail-${report.sha256.slice(0, 12)}.json`} />
      </div>
    </section>
  );
}
