// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { CSSProperties, ReactNode } from "react";
import { Icon } from "../../../components/Icon";
import { cx } from "../../../components/ui";
import type { Severity } from "../../../lib/types";
import { Compare, useSide } from "../Compare";
import { FindingList, Mark, Pane, Story } from "../parts";
import { webcheckSample as w } from "../samples";

type Anchor = "address" | "page" | "cookie" | "server";

export function webAnchor(id: string): Anchor {
  if (id.startsWith("https.") || id.startsWith("hsts.") || id.startsWith("tls.")) return "address";
  if (id.startsWith("cookie.")) return "cookie";
  if (id.startsWith("disclosure.")) return "server";
  return "page";
}

const RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
const present = [...new Set(w.findings.map((f) => webAnchor(f.id)))];
const pinOf = Object.fromEntries(present.map((a, i) => [a, i + 1])) as Partial<Record<Anchor, number>>;
const worst = (a: Anchor): Severity =>
  w.findings
    .filter((f) => webAnchor(f.id) === a)
    .map((f) => f.severity)
    .sort((x, y) => RANK[x] - RANK[y])[0] ?? "info";

function Part({ anchor, children, className }: { anchor: Anchor; children: ReactNode; className?: string }) {
  const { side } = useSide();
  const pin = pinOf[anchor];
  return (
    <Mark on={side === "with" && pin !== undefined} severity={worst(anchor)} {...(pin === undefined ? {} : { pin })} {...(className ? { className } : {})}>
      {children}
    </Mark>
  );
}

function Browser() {
  const { side } = useSide();
  const withK = side === "with";
  return (
    <div className="device relative overflow-hidden rounded-2xl" aria-hidden={withK ? true : undefined}>
      <div className="flex items-center gap-2 border-b border-line px-3 py-2.5">
        <span className="flex gap-1.5">
          <span className="size-2.5 rounded-full bg-crit-mark/70" />
          <span className="size-2.5 rounded-full bg-med-mark/70" />
          <span className="size-2.5 rounded-full bg-ok-mark/70" />
        </span>
        <Part anchor="address" className="ml-2 block min-w-0 flex-1">
          <span className="flex min-w-0 items-center gap-1.5 rounded-lg bg-inset px-3 py-1 text-[0.8125rem] text-ink-2">
            <Icon name="globe" size={13} className="flex-none" />
            <span className="truncate">http://127.0.0.1 · demo site</span>
          </span>
        </Part>
      </div>
      <Part anchor="page" className="block">
        <div className={cx("demo-site relative px-5 py-8 sm:px-8", withK && "is-scanned")}>
          <p className="text-[0.75rem] font-semibold tracking-[0.14em] text-ink-3 uppercase">Demo site</p>
          <p className="mt-1 text-2xl font-bold text-ink">{w.site_title}</p>
          <div className="mt-5 grid max-w-xs gap-2.5">
            <span className="rounded-lg border border-line-strong bg-surface-solid px-3 py-2 text-[0.875rem] text-ink-3">Username</span>
            <span className="rounded-lg border border-line-strong bg-surface-solid px-3 py-2 text-[0.875rem] text-ink-3">Password</span>
            <span className="w-fit rounded-lg bg-[oklch(0.45_0.14_255)] px-4 py-2 text-[0.875rem] font-semibold text-white">Sign in</span>
          </div>
          {withK ? <span className="scan-sweep pointer-events-none absolute inset-0" /> : null}
        </div>
      </Part>
      <div className="border-t border-line bg-inset px-4 py-3 font-mono text-[0.75rem] text-ink-2">
        <p className="mb-1.5 font-sans text-[0.6875rem] font-semibold tracking-[0.1em] text-ink-3 uppercase">Response headers</p>
        {Object.entries(w.response_headers).map(([name, value]) => {
          const line = (
            <span className="break-all">
              <span className="text-ink">{name}:</span> {value}
            </span>
          );
          return (
            <p key={name} className="py-0.5">
              {name === "Set-Cookie" ? <Part anchor="cookie">{line}</Part> : name === "Server" ? <Part anchor="server">{line}</Part> : line}
            </p>
          );
        })}
      </div>
    </div>
  );
}

function Grade() {
  return (
    <div className="flex items-center gap-4">
      <span className="grade-ring relative flex size-24 flex-none items-center justify-center rounded-full" style={{ "--grade": w.score } as CSSProperties}>
        <span className="display text-5xl text-crit">{w.grade}</span>
      </span>
      <div>
        <p className="text-[0.8125rem] font-semibold text-ink-2">Grade {w.grade}</p>
        <p className="display text-2xl text-ink tabular-nums">
          {w.score}
          <span className="text-base text-ink-3">/100</span>
        </p>
        <p className="text-[0.75rem] text-ink-3">{w.findings.length} findings from one GET request</p>
      </div>
    </div>
  );
}

export function WebScene() {
  return (
    <Compare
      name="the demo website"
      without={
        <Pane
          device={<Browser />}
          aside={
            <Story
              steps={[
                { icon: "monitor", text: "The page loads. The form works. Customers sign in every day." },
                { icon: "help", text: "Which protections your server sends is invisible from the page itself." },
                { icon: "globe", text: "Anyone can read those response headers with a single request." },
              ]}
              outcome={{ title: "Gaps you can't see from the page", text: "Everything looks fine until someone checks the response." }}
            />
          }
        />
      }
      withKestrix={
        <Pane
          device={<Browser />}
          aside={
            <div className="grid gap-4">
              <Grade />
              <FindingList
                label="Website findings"
                findings={w.findings.map((f) => {
                  const pin = pinOf[webAnchor(f.id)];
                  return {
                    id: f.id,
                    severity: f.severity,
                    title: f.title,
                    detail: f.recommendation,
                    ...(pin === undefined ? {} : { pin }),
                  };
                })}
              />
              <p className="flex gap-2 rounded-xl border border-line bg-inset p-3 text-[0.8125rem] text-ink-2">
                <Icon name="info" size={16} className="mt-0.5 flex-none text-h1" />
                Demo site served on 127.0.0.1 by the sample generator. On a site you own, Kestrix sends one GET request (plus redirects) and one TLS handshake.
              </p>
            </div>
          }
        />
      }
    />
  );
}
