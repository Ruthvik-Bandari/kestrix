// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../../components/Icon";
import { cx } from "../../../components/ui";
import { Compare, useSide } from "../Compare";
import { FakeCursor, FindingList, Pane, Stamp, Story } from "../parts";
import { fileSample as f } from "../samples";

const bytes = f.first_bytes_hex.split(" ");
const ascii = Array.from({ length: bytes.length }, (_, i) => f.first_bytes_ascii.charAt(i));
const kib = (n: number) => `${(n / 1024).toFixed(1)} KiB`;

function DocIcon({ peeled }: { peeled: boolean }) {
  return (
    <span className={cx("doc-icon relative block h-36 w-28 sm:h-44 sm:w-34", peeled && "is-peeled")}>
      <span className="doc-page absolute inset-0 rounded-lg border border-line-strong bg-surface-solid shadow-panel">
        <span className="absolute inset-x-4 top-8 grid gap-2" aria-hidden="true">
          {[90, 70, 84, 60, 76].map((w) => (
            <span key={w} className="h-1.5 rounded bg-ink-3/25" style={{ width: `${String(w)}%` }} />
          ))}
        </span>
        <span className="absolute bottom-3 left-3 rounded-md bg-[oklch(0.55_0.2_25)] px-2 py-0.5 text-[0.6875rem] font-black text-white">PDF</span>
      </span>
      <span className="doc-fold absolute top-0 right-0 size-8 rounded-bl-lg border-b border-l border-line-strong bg-inset" aria-hidden="true" />
    </span>
  );
}

function Desktop() {
  const { side, visible, still } = useSide();
  const withK = side === "with";
  return (
    <div className="device desk relative flex min-h-[22rem] flex-col items-center justify-center gap-5 overflow-hidden rounded-2xl p-5">
      <div className="relative flex flex-col items-center gap-2">
        <DocIcon peeled={withK} />
        <span className="rounded-md bg-surface px-2 py-0.5 text-[0.875rem] font-semibold text-ink">{f.filename}</span>
        {side === "without" && visible && !still ? <FakeCursor /> : null}
      </div>
      {withK ? (
        <div className="grid w-full gap-4">
          <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2 text-center text-[0.8125rem]">
            <span className="rounded-xl border border-line bg-surface p-2">
              <span className="block text-ink-3">Name claims</span>
              <span className="font-bold text-ink">.{f.file_type.extension}</span>
            </span>
            <span className="text-2xl font-black text-crit" aria-label="does not match">
              ≠
            </span>
            <span className="rounded-xl border border-crit-mark/50 bg-crit-bg p-2">
              <span className="block text-crit">Content is</span>
              <span className="font-bold text-ink">{f.file_type.label}</span>
            </span>
          </div>
          <div className="rounded-xl border border-line bg-inset p-3">
            <p className="text-[0.75rem] text-ink-3">First {bytes.length} bytes</p>
            <div className="mt-2 grid grid-cols-8 gap-1 font-mono text-[0.75rem] sm:grid-cols-16">
              {bytes.map((b, i) => (
                <span
                  key={i}
                  className={cx(
                    "rounded px-1 py-0.5 text-center",
                    i < 2 ? "bg-crit-bg font-bold text-crit ring-1 ring-crit-mark" : "text-ink-2",
                  )}
                >
                  {b.toUpperCase()}
                  <span className="block text-[0.625rem] text-ink-3">{ascii[i] === "." ? "·" : ascii[i]}</span>
                </span>
              ))}
            </div>
            <p className="mt-2 text-[0.8125rem] text-ink-2">
              <strong className="text-crit">4D 5A</strong> spells “MZ”, the start of every Windows program. A PDF starts with “%PDF”.
            </p>
          </div>
          <EntropyStrip />
        </div>
      ) : (
        <div className="opened-window w-full max-w-sm rounded-xl border border-line-strong bg-surface-solid p-3 shadow-panel">
          <p className="flex items-center gap-2 text-[0.8125rem] font-semibold text-ink">
            <Icon name="play" size={13} className="text-crit" />
            {f.filename}
          </p>
          <p className="mt-1 text-[0.8125rem] text-ink-2">No document opens. A program starts instead, with your account’s permissions.</p>
        </div>
      )}
    </div>
  );
}

function EntropyStrip() {
  const { points, threshold, overall } = {
    points: f.entropy.points,
    threshold: f.entropy.high_entropy_threshold,
    overall: f.entropy.overall,
  };
  return (
    <figure className="rounded-xl border border-line bg-inset p-3">
      <figcaption className="flex flex-wrap items-baseline justify-between gap-2 text-[0.75rem] text-ink-3">
        <span>Entropy across the file, per {kib(f.entropy.block_size)} block</span>
        <span>
          overall <strong className="text-ink">{overall.toFixed(2)}</strong> of 8 bits/byte
        </span>
      </figcaption>
      <div className="relative mt-2 flex h-16 items-end gap-0.5" role="img" aria-label={`Entropy per block: ${points.map((p) => p.toFixed(2)).join(", ")} bits per byte; threshold ${String(threshold)}`}>
        <span className="absolute inset-x-0 border-t border-dashed border-crit-mark" style={{ bottom: `${String((threshold / 8) * 100)}%` }} aria-hidden="true" />
        {points.map((p, i) => (
          <span
            key={i}
            className={cx("entropy-bar flex-1 rounded-t-sm", p >= threshold ? "bg-[linear-gradient(180deg,var(--h3),var(--h2))]" : "bg-h1")}
            style={{ height: `${String((p / 8) * 100)}%`, animationDelay: `${String(i * 50)}ms` }}
          />
        ))}
      </div>
      <p className="mt-2 text-[0.75rem] text-ink-2">
        {kib(f.entropy.high_entropy_bytes)} of {kib(f.size)} above the {threshold} random-looking line
      </p>
    </figure>
  );
}

function WithAside() {
  const high = f.findings.filter((x) => x.severity === "high").length;
  return (
    <div className="grid gap-4">
      <Stamp label="Not a PDF" sub={`${String(f.findings.length)} findings · ${String(high)} high`} />
      <FindingList
        label="File findings"
        findings={f.findings.map((x) => ({ id: x.id, severity: x.severity, title: x.title, detail: x.explanation }))}
      />
      <p className="flex gap-2 rounded-xl border border-line bg-inset p-3 text-[0.8125rem] text-ink-2">
        <Icon name="lock" size={16} className="mt-0.5 flex-none text-h1" />
        Read byte by byte on this computer. The file was never executed.
      </p>
    </div>
  );
}

export function FileScene() {
  return (
    <Compare
      name="the quarterly report file"
      without={
        <Pane
          device={<Desktop />}
          aside={
            <Story
              steps={[
                { icon: "mail", text: `A colleague's account sends ${f.filename}. The icon and the name both say PDF.` },
                { icon: "file", text: "You double-click it to read the numbers." },
                { icon: "play", text: "Nothing that looks like a report appears. Something else has started." },
              ]}
              outcome={{ title: "A program ran as you", text: "It can do anything your user account can do." }}
            />
          }
        />
      }
      withKestrix={<Pane device={<Desktop />} aside={<WithAside />} />}
    />
  );
}
