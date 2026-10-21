// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useId, useState } from "react";
import { ByteHistogram, byteLabel } from "../../components/charts/ByteHistogram";
import { EntropyChart } from "../../components/charts/EntropyChart";
import { DataNote } from "../../components/DataNote";
import { Icon } from "../../components/Icon";
import {
  FailedRequest,
  FileDrop,
  FindingList,
  FindingTally,
  HelpPanel,
  LiveStatus,
  LocalProblem,
  PendingPanel,
  ReasonCode,
  ToolLayout,
  useFocusOnArrival,
  VerdictCard,
} from "../../components/report";
import { Badge, CopyButton, Disclosure, Panel, RawJson, SectionTitle, Verdict } from "../../components/ui";
import { severityTone, type Tone } from "../../components/tone";
import { api } from "../../lib/api";
import { slug } from "../../lib/download";
import { formatBytes, hexOffset, plural } from "../../lib/format";
import { isHosted } from "../../lib/mode";
import type { ExifStatus, FileReport, Severity } from "../../lib/types";

/** The server's upload cap: 50 MB locally, 10 MB on the hosted service. */
function maxUpload(): number {
  return (isHosted() ? 10 : 50) * 1024 * 1024;
}

const exifText: Record<Exclude<ExifStatus, "ok">, string> = {
  no_exif: "This image carries no EXIF metadata.",
  not_image: "This file is not a format that carries EXIF metadata.",
  pillow_not_installed: "Reading image metadata needs the optional extra: pip install \"kestrix[exif]\".",
  unreadable: "The image metadata is malformed and could not be read.",
  too_many_pixels: "The image declares implausibly large dimensions, so it was not opened.",
};

function worst(findings: { severity: Severity }[]): Severity | null {
  for (const s of ["high", "medium", "low"] as const) if (findings.some((f) => f.severity === s)) return s;
  return null;
}

function headline(report: FileReport): { tone: Tone; label: string; title: string } {
  const t = report.file_type;
  const attention = report.findings.filter((f) => f.severity !== "info").length;
  if (t.extension_mismatch) {
    return {
      tone: "crit",
      label: "Type mismatch",
      title: `${report.filename} claims to be .${t.extension ?? "?"}, but its content is detected as ${t.label}.`,
    };
  }
  const level = worst(report.findings);
  const what = t.id === "unknown" ? "isn't a format Kestrix recognizes" : `is detected as ${t.label}`;
  return {
    tone: level ? severityTone[level] : "ok",
    label: attention === 0 ? "No findings" : `${plural(attention, "finding")} to review`,
    title:
      attention === 0
        ? `${report.filename} ${what}. Nothing here needs your attention.`
        : `${report.filename} ${what}. ${plural(attention, "thing")} ${attention === 1 ? "deserves" : "deserve"} a look.`,
  };
}

export function FileReportView({ report }: { report: FileReport }) {
  const heading = useFocusOnArrival(report);
  const [log, setLog] = useState(true);
  const logId = useId();
  const verdict = headline(report);
  const t = report.file_type;
  const top = report.byte_histogram
    .map((count, value) => ({ value, count }))
    .filter((b) => b.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  return (
    <section aria-labelledby="file-result" className="@container reveal scroll-mt-6 space-y-8">
      <VerdictCard
        tone={verdict.tone}
        label={verdict.label}
        headingId="file-result"
        headingRef={heading}
        title={verdict.title}
        aside={report.findings.length > 0 ? <FindingTally findings={report.findings} /> : undefined}
      >
        <p>
          Detected from the file&apos;s content, not its name. No findings is not a guarantee that a file is safe.{" "}
          {t.executable ? "This is a program or script that can run on a computer; open it only if you trust its source." : null}
        </p>
      </VerdictCard>

      {report.findings.length > 0 ? (
        <FindingList
          id="file-findings"
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

      <div className="grid items-start gap-4 @4xl:grid-cols-2">
        <Panel as="section">
          <h3 id="type-title" className="font-semibold">
            File type
          </h3>
          <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-5 gap-y-1.5 text-[0.875rem]">
            <dt className="text-ink-3">File</dt>
            <dd className="break-all">
              {report.filename} <span className="text-ink-3">({formatBytes(report.size)})</span>
            </dd>
            <dt className="text-ink-3">Content</dt>
            <dd>
              {t.label} <code className="text-ink-3">{t.id}</code>
            </dd>
            <dt className="text-ink-3">Name says</dt>
            <dd>{t.extension ? <code>.{t.extension}</code> : "no extension"}</dd>
            <dt className="text-ink-3">Usually</dt>
            <dd>{t.expected_extensions.length ? t.expected_extensions.map((e) => `.${e}`).join(", ") : "—"}</dd>
            <dt className="text-ink-3">Runnable</dt>
            <dd>{t.executable ? <Badge tone="high">Yes</Badge> : "No"}</dd>
            <dt className="text-ink-3">Name matches</dt>
            <dd>
              {t.extension_mismatch ? (
                <Badge tone="crit">Mismatch</Badge>
              ) : (
                <Badge tone="ok" icon="check">
                  Consistent
                </Badge>
              )}
            </dd>
            <dt className="text-ink-3">Printable</dt>
            <dd>{Math.round(report.printable_ratio * 100)}% of bytes are plain text</dd>
          </dl>
        </Panel>

        <Panel as="section">
          <h3 id="hash-title" className="font-semibold">
            Fingerprints
          </h3>
          <p className="hint mt-1">Search the SHA-256 in a malware database to see if others have reported this file.</p>
          <ul className="mt-3 space-y-3">
            {(["sha256", "sha1", "md5", "sha512"] as const).map((name) => (
              <li key={name}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[0.8125rem] font-medium text-ink-2">
                    {name === "sha256" ? "SHA-256" : name === "sha1" ? "SHA-1" : name === "sha512" ? "SHA-512" : "MD5"}
                  </span>
                  <CopyButton text={report.hashes[name]} label={`Copy ${name.toUpperCase()} hash`} />
                </div>
                <code className="block text-[0.75rem] break-all text-ink">{report.hashes[name]}</code>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <section aria-labelledby="entropy-title">
        <SectionTitle id="entropy-title">Entropy across the file</SectionTitle>
        <p className="mb-3 max-w-[68ch] text-ink-2">
          Entropy measures how random the bytes look, from 0 to 8 bits per byte. Text sits around 4 to 5; compressed or
          encrypted data sits near 8. Overall: <span className="font-medium text-ink">{report.entropy.overall.toFixed(2)}</span>.
          {report.entropy.high_entropy_region_count > 0
            ? ` ${plural(report.entropy.high_entropy_region_count, "random-looking region")} cover ${formatBytes(report.entropy.high_entropy_bytes)} (shaded).`
            : " No random-looking regions."}
        </p>
        <div className="panel p-4">
          <EntropyChart entropy={report.entropy} size={report.size} />
        </div>
        <div className="mt-3">
          <Disclosure summary="Entropy data table">
            <p className="hint mb-2">
              Each row averages {plural(report.entropy.points_span_blocks, "block")} of {formatBytes(report.entropy.block_size)}.
            </p>
            <div className="max-h-72 overflow-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">Offset</th>
                    <th scope="col" className="num">
                      Bits per byte
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {report.entropy.points.map((p) => (
                    <tr key={p.offset}>
                      <td className="font-mono">{hexOffset(p.offset)}</td>
                      <td className="num">{p.entropy.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Disclosure>
        </div>
      </section>

      <section aria-labelledby="hist-title">
        <SectionTitle
          id="hist-title"
          aside={
            <label htmlFor={logId} className="flex cursor-pointer items-center gap-2 text-[0.875rem] text-ink-2">
              <input
                id={logId}
                type="checkbox"
                className="check mt-0"
                checked={log}
                onChange={(e) => {
                  setLog(e.target.checked);
                }}
              />
              Logarithmic scale
            </label>
          }
        >
          Byte values
        </SectionTitle>
        <p className="mb-3 max-w-[68ch] text-ink-2">
          How often each of the 256 possible byte values appears. Text clusters in the printable band; encrypted data is
          flat across all of them.
        </p>
        <div className="panel p-4">
          <ByteHistogram counts={report.byte_histogram} log={log} />
        </div>
        <div className="mt-3">
          <Disclosure summary="Most common byte values">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Byte</th>
                  <th scope="col" className="num">
                    Count
                  </th>
                  <th scope="col" className="num">
                    Share
                  </th>
                </tr>
              </thead>
              <tbody>
                {top.map((b) => (
                  <tr key={b.value}>
                    <td className="font-mono">{byteLabel(b.value)}</td>
                    <td className="num">{b.count.toLocaleString()}</td>
                    <td className="num">{((b.count / Math.max(1, report.size)) * 100).toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Disclosure>
        </div>
      </section>

      <section aria-labelledby="exif-title">
        <SectionTitle id="exif-title">Image metadata (EXIF)</SectionTitle>
        {report.exif_status !== "ok" || !report.exif ? (
          <p className="text-ink-2">{report.exif_status === "ok" ? exifText.no_exif : exifText[report.exif_status]}</p>
        ) : (
          <div className="space-y-3">
            {report.exif.gps_present ? (
              <Verdict tone="high" icon="pin" title="This photo records where it was taken">
                <p>
                  {report.exif.gps
                    ? `GPS coordinates ${report.exif.gps.latitude.toFixed(5)}, ${report.exif.gps.longitude.toFixed(5)} are embedded. `
                    : "GPS tags are embedded. "}
                  Anyone you share the original file with can read them. Remove location data before posting or sending it.
                </p>
              </Verdict>
            ) : (
              <p className="text-ink-2">No location data. {plural(Object.keys(report.exif.tags).length, "tag")} found.</p>
            )}
            <Disclosure summary={`All EXIF tags (${Object.keys(report.exif.tags).length}${report.exif.tags_truncated ? ", truncated" : ""})`}>
              <div className="max-h-80 overflow-auto">
                <table className="data-table">
                  <tbody>
                    {Object.entries(report.exif.tags).map(([tag, value]) => (
                      <tr key={tag}>
                        <th scope="row" className="font-mono text-[0.8125rem]">
                          {tag}
                        </th>
                        <td className="break-all">{value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Disclosure>
          </div>
        )}
      </section>

      <RawJson data={report} filename={`kestrix-forensics-${slug(report.filename)}.json`} />
    </section>
  );
}

export function FileAnalyzer() {
  const [file, setFile] = useState<File | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const analyze = useMutation({ mutationFn: api.analyzeFile });

  function accept(next: File) {
    const limit = maxUpload();
    analyze.reset();
    if (next.size > limit) {
      setFile(null);
      setLocalError(`${next.name} is ${formatBytes(next.size)}. The limit is ${formatBytes(limit)}.`);
      return;
    }
    setLocalError(null);
    setFile(next);
    analyze.mutate(next);
  }

  const input = (
    <Panel as="section" className="space-y-4">
      <FileDrop
        icon="file"
        idleTitle="Drop a file here, or choose one"
        hint={`Any file type, up to ${formatBytes(maxUpload())}.`}
        chooseLabel="Choose a file"
        chooseAnotherLabel="Choose another file"
        file={file}
        disabled={analyze.isPending}
        onFile={accept}
        onClear={() => {
          setFile(null);
          setLocalError(null);
          analyze.reset();
        }}
      />
      {localError ? <LocalProblem title="That file is too large" detail={localError} /> : null}
      <div className="space-y-2">
        <p className="flex gap-2 text-[0.875rem] text-ink-2">
          <Icon name="shield" size={16} className="mt-0.5 flex-none text-ink-3" />
          <span>The file is read as bytes and never run. Analysis starts as soon as you choose it.</span>
        </p>
        <DataNote subject="The file" />
      </div>
    </Panel>
  );

  return (
    <ToolLayout input={input}>
      <LiveStatus
        pending={analyze.isPending}
        done={analyze.isSuccess}
        pendingText="Analyzing the file…"
        doneText="Analysis finished. The result is below."
      />
      {analyze.isPending ? (
        <PendingPanel title="Analyzing the file">
          Detecting its real type, hashing it and measuring entropy. The file is not executed.
        </PendingPanel>
      ) : analyze.isError ? (
        <FailedRequest
          error={analyze.error}
          onRetry={() => {
            if (file) analyze.mutate(file);
          }}
        />
      ) : analyze.data ? (
        <FileReportView report={analyze.data} />
      ) : (
        <HelpPanel title="Inspect a file">
          <div className="grid gap-6 @2xl:grid-cols-2">
            <div>
              <h3 className="font-semibold">What the report contains</h3>
              <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
                <li>Whether the content matches the file name, or the type is a mismatch.</li>
                <li>SHA-256, SHA-1, MD5 and SHA-512 fingerprints you can copy.</li>
                <li>Entropy across the file and the byte values, with the random-looking regions marked.</li>
                <li>Image metadata, including any embedded location, and findings with reason codes.</li>
              </ul>
            </div>
            <div>
              <h3 className="font-semibold">Good to know</h3>
              <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
                <li>The type comes from the file&apos;s bytes, not its extension.</li>
                <li>No findings is not a guarantee that a file is safe.</li>
                <li>Use Link to check a web address instead; it is analyzed as text and never opened.</li>
              </ul>
            </div>
          </div>
        </HelpPanel>
      )}
    </ToolLayout>
  );
}
