// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Icon } from "../../../components/Icon";
import type { Severity } from "../../../lib/types";
import { Compare, useSide } from "../Compare";
import { FakeCursor, FindingList, Mark, Pane, Stamp, Story } from "../parts";
import { emailSample, type EmailFinding } from "../samples";

const { message, report } = emailSample;

/** The part of the message each real finding is about, so its pin lands on that part. */
export type EmailAnchor = "from" | "replyTo" | "subject" | "body" | "link" | "attachment";

export function anchorFor(finding: EmailFinding): EmailAnchor {
  const evidence = (finding.evidence ?? "").toLowerCase();
  if (finding.id === "mail.sender.reply_to_mismatch") return "replyTo";
  if (finding.analyzer === "links" || evidence.startsWith("link host")) return "link";
  if (finding.analyzer === "attachments") return "attachment";
  if (finding.id === "mail.intent.urgency") return "subject";
  if (finding.analyzer === "intent") return "body";
  return "from";
}

const RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

// Pins are numbered in the order their parts first appear in the (severity-ordered) list.
const present = [...new Set(report.findings.map(anchorFor))];
const pinOf = Object.fromEntries(present.map((anchor, i) => [anchor, i + 1])) as Partial<Record<EmailAnchor, number>>;
const worst = Object.fromEntries(
  present.map((anchor) => [
    anchor,
    report.findings
      .filter((f) => anchorFor(f) === anchor)
      .map((f) => f.severity)
      .sort((a, b) => RANK[a] - RANK[b])[0] ?? "info",
  ]),
) as Partial<Record<EmailAnchor, Severity>>;

const highCount = report.findings.filter((f) => f.severity === "high").length;

function Part({ anchor, children, className }: { anchor: EmailAnchor; children: ReactNode; className?: string }) {
  const { side } = useSide();
  const pin = pinOf[anchor];
  const on = side === "with" && pin !== undefined;
  return (
    <Mark on={on} severity={worst[anchor] ?? "info"} {...(pin === undefined ? {} : { pin })} {...(className ? { className } : {})}>
      {children}
    </Mark>
  );
}

function MailClient() {
  const { side, visible, still } = useSide();
  const showCursor = side === "without" && visible && !still;
  return (
    <div className="device mail-client overflow-hidden rounded-2xl" aria-hidden={side === "with" ? true : undefined}>
      <div className="flex items-center gap-2 border-b border-line px-4 py-2.5">
        <span className="flex gap-1.5" aria-hidden="true">
          <span className="size-2.5 rounded-full bg-crit-mark/70" />
          <span className="size-2.5 rounded-full bg-med-mark/70" />
          <span className="size-2.5 rounded-full bg-ok-mark/70" />
        </span>
        <span className="ml-2 text-[0.8125rem] font-semibold text-ink-2">Inbox</span>
        <span className="ml-auto hidden gap-1 text-[0.75rem] text-ink-3 sm:flex" aria-hidden="true">
          <span className="rounded-md border border-line px-2 py-0.5">Reply</span>
          <span className="rounded-md border border-line px-2 py-0.5">Forward</span>
        </span>
      </div>
      <div className="p-4 sm:p-5">
        <p className="text-[1.0625rem] font-bold text-ink sm:text-xl">
          <Part anchor="subject">{message.subject}</Part>
        </p>
        <div className="mt-4 flex items-start gap-3">
          <span className="flex size-10 flex-none items-center justify-center rounded-full bg-[linear-gradient(135deg,oklch(0.55_0.12_250),oklch(0.45_0.14_265))] text-[0.8125rem] font-bold text-white">
            NB
          </span>
          <div className="min-w-0 flex-1 text-[0.875rem]">
            <p className="flex flex-wrap items-baseline gap-x-2">
              <Part anchor="from">
                <span className="font-semibold text-ink">{message.from_name}</span>{" "}
                <span className="break-all text-ink-3">&lt;{message.from_address}&gt;</span>
              </Part>
            </p>
            <p className="mt-0.5 text-ink-3">
              to {message.to} · {message.date}
            </p>
            <p className="mt-0.5 text-ink-3">
              <Part anchor="replyTo">
                <span>
                  reply-to <span className="break-all">{message.reply_to}</span>
                </span>
              </Part>
            </p>
          </div>
        </div>
        <div className="mt-5 grid gap-3 text-[0.9375rem] text-ink">
          <p>{message.paragraphs[0]}</p>
          <p>
            <Part anchor="body">{message.paragraphs[1]}</Part>
          </p>
          <p>{message.paragraphs[2]}</p>
          <p>
            {message.paragraphs[3]}{" "}
            <Part anchor="link">
              <span className="font-medium text-low underline underline-offset-2">{message.link_text}</span>
            </Part>
          </p>
          <p className="text-ink-2">{message.paragraphs[4]}</p>
        </div>
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <Part anchor="attachment">
            <span className="attachment relative inline-flex items-center gap-2.5 rounded-xl border border-line-strong bg-surface-solid px-3 py-2">
              <span className="flex h-9 w-7 items-center justify-center rounded-md bg-[oklch(0.55_0.2_25)] text-[0.5625rem] font-black text-white">PDF</span>
              <span className="text-[0.8125rem]">
                <span className="block font-semibold text-ink">{message.attachment}</span>
                <span className="block text-ink-3">Attachment · click to open</span>
              </span>
              {showCursor ? <FakeCursor /> : null}
            </span>
          </Part>
        </div>
      </div>
    </div>
  );
}

function WithAside() {
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center gap-4">
        <Stamp label={report.verdict} sub={`${String(report.findings.length)} reasons · ${String(highCount)} high`} />
        <p className="max-w-[26ch] text-[0.8125rem] text-ink-2">
          Heuristic score <strong className="text-ink">{report.heuristic_score}</strong>/100 · a ranking aid, not a probability
        </p>
      </div>
      <FindingList
        label="Email findings"
        findings={report.findings.map((f) => {
          const pin = pinOf[anchorFor(f)];
          return { id: f.id, severity: f.severity, title: f.title, detail: f.evidence, ...(pin === undefined ? {} : { pin }) };
        })}
      />
      <p className="flex gap-2 rounded-xl border border-line bg-inset p-3 text-[0.8125rem] text-ink-2">
        <Icon name="lock" size={16} className="mt-0.5 flex-none text-h1" />
        Nothing left this computer: the link was read as text, never visited, and the attachment was never opened.
      </p>
    </div>
  );
}

export function EmailScene() {
  return (
    <Compare
      name="the invoice email"
      without={
        <Pane
          device={<MailClient />}
          aside={
            <Story
              steps={[
                { icon: "mail", text: `It looks like ${message.from_name}, about an invoice you were expecting.` },
                { icon: "file", text: `You open ${message.attachment} to check the amount. It is a program, and it runs.` },
                { icon: "arrowRight", text: `Then you follow ${message.link_text} and enter the new account details.` },
              ]}
              outcome={{ title: "The payment goes to the wrong account", text: "Nothing on screen told you who really sent it." }}
            />
          }
        />
      }
      withKestrix={<Pane device={<MailClient />} aside={<WithAside />} />}
    />
  );
}
