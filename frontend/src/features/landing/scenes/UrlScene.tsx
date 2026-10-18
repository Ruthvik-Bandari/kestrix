// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../../components/Icon";
import { cx } from "../../../components/ui";
import type { Severity } from "../../../lib/types";
import { Compare, useSide } from "../Compare";
import { FindingList, Pane, Pin, Story } from "../parts";
import { urlSample as u } from "../samples";

type PartId = "scheme" | "userinfo" | "host" | "path";

/** Split the URL text exactly as written, so every character on screen is the analysed URL. */
function split(url: string): { id: PartId; text: string }[] {
  const schemeEnd = url.indexOf("://") + 3;
  const at = url.indexOf("@", schemeEnd);
  const hostStart = at >= 0 ? at + 1 : schemeEnd;
  const hostEnd = hostStart + u.host.length;
  return [
    { id: "scheme" as const, text: url.slice(0, schemeEnd) },
    { id: "userinfo" as const, text: at >= 0 ? url.slice(schemeEnd, at + 1) : "" },
    { id: "host" as const, text: url.slice(hostStart, hostEnd) },
    { id: "path" as const, text: url.slice(hostEnd) },
  ].filter((part) => part.text);
}

const PART_OF: Record<string, PartId> = {
  not_https: "scheme",
  userinfo_in_url: "userinfo",
  ip_address_host: "host",
  suspicious_keywords: "path",
};

const CAPTION: Record<PartId, string> = {
  scheme: "unencrypted",
  userinfo: "ignored by the browser",
  host: "where you actually go",
  path: "login wording",
};

const parts = split(u.url);
const pinned = parts.filter((p) => u.findings.some((f) => PART_OF[f.id] === p.id));
const pinOf = Object.fromEntries(pinned.map((p, i) => [p.id, i + 1])) as Partial<Record<PartId, number>>;
const severityOf = (id: PartId): Severity => u.findings.find((f) => PART_OF[f.id] === id)?.severity ?? "info";
const shownName = parts.find((p) => p.id === "userinfo")?.text.replace(/@$/, "") ?? u.host;

function UrlBoard() {
  const { side } = useSide();
  const withK = side === "with";
  return (
    <div className="device overflow-hidden rounded-2xl">
      <div className="flex items-center gap-2 border-b border-line px-4 py-2.5 text-[0.8125rem] text-ink-3">
        <Icon name="globe" size={14} />
        A link in a message
      </div>
      <div className="px-4 py-8 sm:px-8 sm:py-12">
        <p className="url-big font-mono text-[clamp(1.05rem,3.4vw,2.25rem)] leading-snug font-medium" aria-label={u.url}>
          {parts.map((part) => {
            const pin = pinOf[part.id];
            const sev = severityOf(part.id);
            return (
              <span
                key={part.id}
                className={cx(
                  "url-part relative inline-block max-w-full break-all",
                  !withK && part.id === "userinfo" && "eye-read",
                  !withK && part.id !== "userinfo" && "text-ink-3",
                  withK && part.id === "userinfo" && "text-ink-3 line-through decoration-crit-mark decoration-2",
                  withK && part.id === "host" && "url-host text-crit",
                  withK && part.id !== "host" && part.id !== "userinfo" && "text-ink",
                )}
                aria-hidden="true"
              >
                {part.text}
                {withK && pin !== undefined ? <Pin n={pin} severity={sev} className="absolute -top-5 left-1/2 z-10 -translate-x-1/2 scale-90" /> : null}
              </span>
            );
          })}
        </p>
        {withK ? (
          <ul className="mt-8 grid gap-2 sm:grid-cols-2" aria-label="URL anatomy">
            {pinned.map((part) => (
              <li key={part.id} className="flex items-start gap-2 text-[0.875rem]">
                <Pin n={pinOf[part.id] ?? 0} severity={severityOf(part.id)} className="mt-0.5" />
                <span>
                  <code className="break-all text-ink">{part.text}</code>
                  <span className="block text-ink-2">{CAPTION[part.id]}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="mt-8 flex items-center gap-3 text-[0.9375rem] text-ink-2">
            <span className="eye-icon flex size-10 items-center justify-center rounded-full bg-inset text-ink" aria-hidden="true">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12Z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
            </span>
            <span>
              What the eye reads: <strong className="text-ink">{shownName}</strong>
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function Meter() {
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-baseline justify-between gap-3">
        <p className="text-[0.8125rem] font-semibold text-ink-2">Heuristic score</p>
        <p className="display text-3xl text-crit tabular-nums">
          {u.score}
          <span className="text-base text-ink-3">/100 · {u.level}</span>
        </p>
      </div>
      <div className="mt-2 h-2.5 overflow-hidden rounded-full bg-inset" aria-hidden="true">
        <div className="meter-fill h-full rounded-full bg-[linear-gradient(90deg,var(--h1),var(--h2),var(--h3))]" style={{ width: `${String(u.score)}%` }} />
      </div>
      <p className="mt-2 text-[0.75rem] text-ink-3">{u.score_note}</p>
    </div>
  );
}

export function UrlScene() {
  return (
    <Compare
      name="the login link"
      without={
        <Pane
          device={<UrlBoard />}
          aside={
            <Story
              steps={[
                { icon: "search", text: `Your eye stops at the first name it knows: ${shownName}.` },
                { icon: "lock", text: "The page that opens looks like the sign-in page you expected." },
                { icon: "key", text: "You type your password." },
              ]}
              outcome={{ title: "Your password went to someone else", text: `The browser went to ${u.host}. ${shownName} was never the destination.` }}
            />
          }
        />
      }
      withKestrix={
        <Pane
          device={<UrlBoard />}
          aside={
            <div className="grid gap-4">
              <Meter />
              <FindingList
                label="Link findings"
                findings={u.findings.map((f) => {
                  const part = PART_OF[f.id];
                  const pin = part ? pinOf[part] : undefined;
                  return { id: f.id, severity: f.severity, title: f.title, detail: f.explanation, ...(pin === undefined ? {} : { pin }) };
                })}
              />
              <p className="flex gap-2 rounded-xl border border-line bg-inset p-3 text-[0.8125rem] text-ink-2">
                <Icon name="lock" size={16} className="mt-0.5 flex-none text-h1" />
                Checked as text. The link was never visited.
              </p>
            </div>
          }
        />
      }
    />
  );
}
