// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useState, type DragEvent, type SubmitEvent } from "react";
import { FileButton } from "../../components/FileButton";
import { HowItWorks, type HowItWorksContent } from "../../components/HowItWorks";
import { Icon } from "../../components/Icon";
import { cx, ErrorState, Field, PageHeader, Spinner, Verdict } from "../../components/ui";
import { api } from "../../lib/api";
import { formatBytes } from "../../lib/format";
import type { MailOptions } from "../../lib/types";
import { isHosted } from "../../lib/mode";
import { useTitle } from "../../lib/useTitle";
import { MailReportView } from "./MailReportView";

export const MAX_MESSAGE = 25 * 1024 * 1024;
export const MAX_PROTECTED_DOMAINS = 20;

const howItWorks: HowItWorksContent = {
  id: "mail",
  name: "Email check",
  purpose:
    "Check a saved email for signs of phishing, impersonation and fake invoices before you click, reply or open anything.",
  steps: [
    "Save the message as an .eml file and drop it here. Optionally list domains you care about, such as your bank.",
    "Kestrix reads the sender authentication results (SPF, DKIM, DMARC) your provider stamped on the message, and compares the sender's addresses and display name.",
    "It looks for look-alike domains, deceptive links, risky attachments and the wording of payment and credential scams.",
    "You get a verdict (clean, suspicious, malicious or insufficient evidence) with a reason for every finding.",
  ],
  usefulWhen: [
    "An invoice or a bank-details change that feels off.",
    "A sign-in or verify-your-account message.",
    "An attachment you were not expecting.",
  ],
  doesNot: [
    "It does not visit links, render the message or open attachments.",
    "It is a set of heuristics, not a classifier: a clean verdict means no check fired.",
    "Its scam-wording lists are English and miss paraphrases.",
    "No detection or false-positive rates have been measured yet.",
  ],
};

/** Split a comma- or space-separated list, lower-cased and without duplicates. */
export function parseDomains(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((d) => d.trim().toLowerCase()).filter(Boolean))];
}

export default function MailPage() {
  useTitle("Email check");
  const [file, setFile] = useState<File | null>(null);
  const [domains, setDomains] = useState("");
  const [authservId, setAuthservId] = useState("");
  const [dragging, setDragging] = useState(false);
  const [localError, setLocalError] = useState<{ title: string; detail: string } | null>(null);
  const analyze = useMutation({
    mutationFn: ({ message, options }: { message: File; options: MailOptions }) => api.analyzeMail(message, options),
  });

  function choose(next: File | undefined) {
    if (!next) return;
    analyze.reset();
    if (next.size > MAX_MESSAGE) {
      setFile(null);
      setLocalError({
        title: "That message is too large",
        detail: `${next.name} is ${formatBytes(next.size)}. The limit is ${formatBytes(MAX_MESSAGE)}.`,
      });
      return;
    }
    setLocalError(null);
    setFile(next);
  }

  function onDrop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    choose(event.dataTransfer.files[0]);
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
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

  return (
    <>
      <PageHeader
        title="Email check"
        lede="Check a saved email for signs of phishing, impersonation and fake invoices. Every warning comes with the reason behind it."
      />
      <HowItWorks content={howItWorks} />

      <div className="mb-6 grid max-w-3xl gap-3 text-ink-2">
        <p className="flex gap-2">
          <Icon name="lock" size={16} className="mt-1 flex-none text-ink-3" />
          <span>
            {isHosted()
              ? "The message is analyzed in memory on Kestrix's server and never stored; the report is not kept. "
              : "The check runs offline on this computer and nothing leaves it. "}
            Links are never visited, the message is never displayed as a web page, and attachments are never opened.
          </span>
        </p>
        <p className="flex gap-2">
          <Icon name="info" size={16} className="mt-1 flex-none text-ink-3" />
          <span>
            First save the message as an <code>.eml</code> file. In Gmail, open it and choose ⋮ (More) →{" "}
            <span className="font-medium text-ink">Download message</span>. In Outlook, use{" "}
            <span className="font-medium text-ink">File → Save as</span> (or drag the message to your desktop).
          </span>
        </p>
      </div>

      <form onSubmit={submit} className="panel max-w-3xl space-y-5 p-5 sm:p-6" aria-label="Check a saved email">
        {/* Drag and drop is a pointer shortcut; the file button inside is the keyboard path. */}
        {/* eslint-disable-next-line jsx-a11y/no-static-element-interactions */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => {
            setDragging(false);
          }}
          onDrop={onDrop}
          className={cx(
            "flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-8 text-center transition-colors duration-150",
            dragging ? "border-accent bg-accent-soft" : "border-line-strong bg-surface",
          )}
        >
          <Icon name="mail" size={28} className="text-ink-3" />
          <p className="font-medium text-ink">{file ? file.name : "Drop an .eml file here, or choose one"}</p>
          <p className="hint">{file ? formatBytes(file.size) : `Up to ${formatBytes(MAX_MESSAGE)}.`}</p>
          <FileButton
            label={file ? "Choose another .eml file" : "Choose an .eml file"}
            accept=".eml,message/rfc822"
            onFile={choose}
          />
        </div>

        <Field
          htmlFor="mail-protected"
          label="Protected domains (optional)"
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
            aria-describedby="mail-protected-hint"
            placeholder="example-bank.com, example.com"
          />
        </Field>

        <Field
          htmlFor="mail-authserv"
          label="Trusted authserv-id (optional)"
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
            aria-describedby="mail-authserv-hint"
          />
        </Field>

        <button type="submit" className="btn btn-primary" disabled={!file || analyze.isPending}>
          {analyze.isPending ? <Spinner /> : <Icon name="search" size={16} />}
          Check message
        </button>
      </form>

      <div aria-live="polite" className="sr-only">
        {analyze.isPending ? "Checking the message…" : analyze.isSuccess ? "Check finished. Results below." : ""}
      </div>
      {localError ? (
        <div className="mt-6" role="alert">
          <Verdict tone="crit" icon="xCircle" title={localError.title}>
            {localError.detail}
          </Verdict>
        </div>
      ) : null}
      {analyze.isError ? (
        <div className="mt-6">
          <ErrorState error={analyze.error} />
        </div>
      ) : null}
      {analyze.data ? <MailReportView report={analyze.data} /> : null}
    </>
  );
}
