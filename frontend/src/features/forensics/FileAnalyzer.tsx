// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type DragEvent } from "react";
import { ByteHistogram, byteLabel } from "../../components/charts/ByteHistogram";
import { EntropyChart } from "../../components/charts/EntropyChart";
import { Icon } from "../../components/Icon";
import { Badge, CopyButton, cx, Disclosure, ErrorState, RawJson, SectionTitle, Spinner, Verdict } from "../../components/ui";
import { severityTone, type Tone } from "../../components/tone";
import { api } from "../../lib/api";
import { slug } from "../../lib/download";
import { formatBytes, hexOffset, plural } from "../../lib/format";
import { isHosted } from "../../lib/mode";
import { scrollBehavior } from "../../lib/motion";
import type { ExifStatus, FileReport, Severity } from "../../lib/types";
import { FindingsList } from "./FindingsList";

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

function headline(report: FileReport): { tone: Tone; title: string } {
  const t = report.file_type;
  const attention = report.findings.filter((f) => f.severity !== "info").length;
  if (t.extension_mismatch) {
    return {
      tone: "crit",
      title: `${report.filename} claims to be .${t.extension ?? "?"}, but its content is detected as ${t.label}.`,
    };
  }
  const level = worst(report.findings);
  const what = t.id === "unknown" ? "isn't a format Kestrix recognizes" : `is detected as ${t.label}`;
  return {
    tone: level ? severityTone[level] : "ok",
    title:
      attention === 0
        ? `${report.filename} ${what}. Nothing here needs your attention.`
        : `${report.filename} ${what}. ${plural(attention, "thing")} ${attention === 1 ? "deserves" : "deserve"} a look.`,
  };
}

function Report({ report }: { report: FileReport }) {
  const ref = useRef<HTMLHeadingElement>(null);
  const [log, setLog] = useState(true);
  const logId = useId();
  useEffect(() => {
    ref.current?.focus();
    ref.current?.scrollIntoView({ block: "start", behavior: scrollBehavior() });
  }, [report]);
  const verdict = headline(report);
  const t = report.file_type;
  const top = report.byte_histogram
    .map((count, value) => ({ value, count }))
    .filter((b) => b.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  return (
    <section aria-labelledby="file-result" className="reveal mt-10 scroll-mt-6 border-t border-line pt-8">
      <h2 id="file-result" ref={ref} tabIndex={-1} className="mb-4 text-xl font-semibold break-all outline-none">
        {report.filename}
        <span className="ml-2 text-base font-normal text-ink-3">{formatBytes(report.size)}</span>
      </h2>
      <Verdict tone={verdict.tone} title={verdict.title}>
        <p>
          Detected from the file's content, not its name.{" "}
          {t.executable ? "This is a program or script that can run on a computer; open it only if you trust its source." : null}
        </p>
      </Verdict>

      <div className="mt-8 grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <section aria-labelledby="type-title" className="panel p-5">
          <h3 id="type-title" className="font-semibold">
            File type
          </h3>
          <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-5 gap-y-1.5 text-[0.875rem]">
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
        </section>

        <section aria-labelledby="hash-title" className="panel p-5">
          <h3 id="hash-title" className="font-semibold">
            Fingerprints
          </h3>
          <p className="hint mt-1">Search the SHA-256 in a malware database to see if others have reported this file.</p>
          <ul className="mt-3 space-y-2">
            {(["sha256", "sha1", "md5", "sha512"] as const).map((name) => (
              <li key={name} className="flex items-start gap-2">
                <span className="w-16 flex-none pt-1.5 text-[0.8125rem] font-medium text-ink-2 uppercase">
                  {name === "sha256" ? "SHA-256" : name === "sha1" ? "SHA-1" : name === "sha512" ? "SHA-512" : "MD5"}
                </span>
                <code className="min-w-0 flex-1 pt-1.5 text-[0.75rem] break-all text-ink">{report.hashes[name]}</code>
                <CopyButton text={report.hashes[name]} label={`Copy ${name.toUpperCase()} hash`} className="flex-none" />
              </li>
            ))}
          </ul>
        </section>
      </div>

      {report.findings.length > 0 ? (
        <section aria-labelledby="file-findings" className="mt-10">
          <SectionTitle id="file-findings">Findings</SectionTitle>
          <FindingsList findings={report.findings} />
        </section>
      ) : null}

      <section aria-labelledby="entropy-title" className="mt-10">
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

      <section aria-labelledby="hist-title" className="mt-10">
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

      <section aria-labelledby="exif-title" className="mt-10">
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

      <div className="mt-10">
        <RawJson data={report} filename={`kestrix-forensics-${slug(report.filename)}.json`} />
      </div>
    </section>
  );
}

export function FileAnalyzer() {
  const [dragging, setDragging] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const inputId = useId();
  const analyze = useMutation({ mutationFn: api.analyzeFile });

  function accept(file: File | undefined) {
    if (!file) return;
    const limit = maxUpload();
    if (file.size > limit) {
      analyze.reset();
      setLocalError(`${file.name} is ${formatBytes(file.size)}. The limit is ${formatBytes(limit)}.`);
      return;
    }
    setLocalError(null);
    analyze.mutate(file);
  }

  function onDrop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    accept(event.dataTransfer.files[0]);
  }

  return (
    <>
      {/* Drag and drop is a pointer shortcut; the native file input inside is the keyboard path. */}
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions */}
      <label
        htmlFor={inputId}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => {
          setDragging(false);
        }}
        onDrop={onDrop}
        className={cx(
          "flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors duration-150 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-(--focus)",
          dragging ? "border-accent bg-accent-soft" : "border-line-strong bg-surface hover:bg-inset",
        )}
      >
        {analyze.isPending ? (
          <Spinner label="Analyzing…" />
        ) : (
          <>
            <Icon name="file" size={28} className="text-ink-3" />
            <span className="font-medium text-ink">Drop a file here, or choose one</span>
            <span className="hint">Any file type, up to {formatBytes(maxUpload())}.</span>
          </>
        )}
        <input
          id={inputId}
          type="file"
          className="sr-only"
          disabled={analyze.isPending}
          onChange={(e) => {
            accept(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
      </label>
      <p className="mt-3 flex gap-2 text-[0.875rem] text-ink-2">
        <Icon name="lock" size={16} className="mt-0.5 flex-none text-ink-3" />
        {isHosted()
          ? "Files are analyzed on Kestrix's server and are never stored or sent anywhere else. Nothing is run or saved."
          : "Files are analyzed by the Kestrix server on this computer and are never uploaded anywhere else. Nothing is run or saved."}
      </p>

      <div aria-live="polite" className="sr-only">
        {analyze.isPending ? "Analyzing the file…" : analyze.isSuccess ? "Analysis finished. Results below." : ""}
      </div>
      {localError ? (
        <div className="mt-6" role="alert">
          <Verdict tone="crit" icon="xCircle" title="That file is too large">
            {localError}
          </Verdict>
        </div>
      ) : null}
      {analyze.isError ? (
        <div className="mt-6">
          <ErrorState error={analyze.error} />
        </div>
      ) : null}
      {analyze.data ? <Report report={analyze.data} /> : null}
    </>
  );
}
