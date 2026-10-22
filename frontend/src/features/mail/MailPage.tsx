// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useState, type SubmitEvent } from "react";
import { DataNote } from "../../components/DataNote";
import {
  FailedRequest,
  FileDrop,
  LiveStatus,
  LocalProblem,
  PendingPanel,
  ToolLayout,
} from "../../components/report";
import { ReportOutline, stageOf, Workspace } from "../../components/toolframe";
import { Button, Disclosure, Field } from "../../components/ui";
import { api } from "../../lib/api";
import { formatBytes } from "../../lib/format";
import type { MailOptions } from "../../lib/types";
import { maxMessageBytes } from "../../lib/limits";
import { outlines } from "../tools/frame";
import { ToolFrame } from "../tools/ToolHeader";
import { MailReportView } from "./MailReportView";

/** The server's message cap: 25 MB locally, 10 MB on the hosted service. */
export function maxMessage(): number {
  return maxMessageBytes();
}
export const MAX_PROTECTED_DOMAINS = 20;

/** Split a comma- or space-separated list, lower-cased and without duplicates. */
export function parseDomains(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((d) => d.trim().toLowerCase()).filter(Boolean))];
}

/** Outlook's binary .msg format, which the checker cannot read; anything else goes to the server to judge. */
function isOutlookMsg(file: File): boolean {
  return /\.msg$/i.test(file.name) || file.type === "application/vnd.ms-outlook";
}

function HelpColumns() {
  return (
    <div className="grid gap-6 @2xl:grid-cols-2">
      <div>
        <h3 className="font-semibold">Save a message as an .eml file</h3>
        <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-ink-2">
          <li>
            <span className="font-medium text-ink">Gmail:</span> open the message, choose ⋮ (More), then{" "}
            <span className="font-medium text-ink">Download message</span>.
          </li>
          <li>
            <span className="font-medium text-ink">Outlook:</span> choose{" "}
            <span className="font-medium text-ink">File, Save as</span>, or drag the message to your desktop.
          </li>
          <li>Come back here and choose the saved file.</li>
        </ol>
      </div>
      <div>
        <h3 className="font-semibold">Good to know</h3>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
          <li>Links are not visited and attachments are not opened.</li>
          <li>The score is a heuristic, not a probability.</li>
          <li>The report keeps the subject, sender address and SHA-256, not the message body.</li>
        </ul>
      </div>
    </div>
  );
}

export default function MailPage() {
  const [file, setFile] = useState<File | null>(null);
  const [domains, setDomains] = useState("");
  const [authservId, setAuthservId] = useState("");
  const [localError, setLocalError] = useState<{ title: string; detail: string } | null>(null);
  const analyze = useMutation({
    mutationFn: ({ message, options }: { message: File; options: MailOptions }) => api.analyzeMail(message, options),
  });

  function choose(next: File) {
    analyze.reset();
    const limit = maxMessage();
    if (isOutlookMsg(next)) {
      setFile(null);
      setLocalError({
        title: "Outlook .msg files can't be checked",
        detail: `${next.name} is an Outlook .msg file. Save the message as an .eml file instead.`,
      });
      return;
    }
    if (next.size > limit) {
      setFile(null);
      setLocalError({
        title: "That message is too large",
        detail: `${next.name} is ${formatBytes(next.size)}. The limit is ${formatBytes(limit)}.`,
      });
      return;
    }
    setLocalError(null);
    setFile(next);
  }

  function run() {
    if (!file) return;
    const protectedDomains = parseDomains(domains);
    if (protectedDomains.length > MAX_PROTECTED_DOMAINS) {
      analyze.reset();
      setLocalError({
        title: "Too many protected domains",
        detail: `You listed ${protectedDomains.length.toString()}. Kestrix checks at most ${MAX_PROTECTED_DOMAINS.toString()}.`,
      });
      return;
    }
    setLocalError(null);
    analyze.mutate({ message: file, options: { protectedDomains, trustedAuthservId: authservId.trim() || null } });
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    run();
  }

  const input = (
    <form onSubmit={submit} aria-label="Check a saved email">
      <Workspace
        steps={[
          {
            key: "message",
            title: "Choose the message",
            children: (
              <>
                <FileDrop
                  icon="mail"
                  idleTitle="Drop an .eml file here, or choose one"
                  hint={`An .eml file, up to ${formatBytes(maxMessage())}.`}
                  chooseLabel="Choose an .eml file"
                  chooseAnotherLabel="Choose another .eml file"
                  accept=".eml,message/rfc822"
                  file={file}
                  onFile={choose}
                  onClear={() => {
                    setFile(null);
                    setLocalError(null);
                    analyze.reset();
                  }}
                />
                {localError ? <LocalProblem title={localError.title} detail={localError.detail} /> : null}
              </>
            ),
          },
          {
            key: "options",
            title: "Options",
            optional: true,
            children: (
              <Disclosure summary="Advanced options">
                <div className="space-y-4">
                  <Field
                    htmlFor="mail-protected"
                    label="Protected domains"
                    optional
                    hint="Domains you care about, such as your bank or employer, separated by commas. Look-alikes of them and their names in sender names are flagged. Up to 20."
                  >
                    <input
                      id="mail-protected"
                      className="field font-mono"
                      type="text"
                      spellCheck={false}
                      autoComplete="off"
                      value={domains}
                      onChange={(e) => {
                        setDomains(e.target.value);
                      }}
                      placeholder="example-bank.com, example.com"
                    />
                  </Field>
                  <Field
                    htmlFor="mail-authserv"
                    label="Trusted authserv-id"
                    optional
                    hint="Your mail provider's name in the Authentication-Results header, for example mx.google.com. Leave empty to trust the topmost header."
                  >
                    <input
                      id="mail-authserv"
                      className="field font-mono"
                      type="text"
                      spellCheck={false}
                      autoComplete="off"
                      value={authservId}
                      onChange={(e) => {
                        setAuthservId(e.target.value);
                      }}
                    />
                  </Field>
                </div>
              </Disclosure>
            ),
          },
          {
            key: "run",
            title: "Check it",
            run: true,
            children: (
              <>
                <Button type="submit" icon="search" className="w-full" disabled={!file} pending={analyze.isPending} pendingLabel="Checking…">
                  Check message
                </Button>
                <DataNote subject="The message" />
              </>
            ),
          },
        ]}
      />
    </form>
  );

  const stage = stageOf({ ready: file !== null, pending: analyze.isPending, failed: analyze.isError, done: Boolean(analyze.data) });

  return (
    <ToolFrame page="mail">
      <ToolLayout input={input} stage={stage}>
        <LiveStatus
          pending={analyze.isPending}
          done={analyze.isSuccess}
          pendingText="Checking the message…"
          doneText="Check finished. The result is below."
        />
        {analyze.isPending ? (
          <PendingPanel title="Checking the message">
            Reading the headers, sender, links and attachments. Links are not visited and attachments are not opened.
          </PendingPanel>
        ) : analyze.isError ? (
          <FailedRequest error={analyze.error} onRetry={run} />
        ) : analyze.data ? (
          <MailReportView report={analyze.data} />
        ) : (
          <ReportOutline sections={outlines.mail}>
            <HelpColumns />
          </ReportOutline>
        )}
      </ToolLayout>
    </ToolFrame>
  );
}
