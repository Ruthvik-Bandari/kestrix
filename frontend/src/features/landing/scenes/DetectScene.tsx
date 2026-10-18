// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../../components/Icon";
import { cx } from "../../../components/ui";
import { Compare, useSide } from "../Compare";
import { Pane, Stamp, Story } from "../parts";
import { detectSample as d } from "../samples";

const attacks = d.events.filter((e) => e.label === "malicious").length;
const benign = d.events.length - attacks;
const patch = d.patch[0];
const missing = d.coverage.find((c) => c.present === 0);

function EventStream() {
  const { side } = useSide();
  const matched = new Set(side === "with" ? d.after.matched : d.before.matched);
  const alerts = side === "with" ? d.after.counts.tp + d.after.counts.fp : d.before.counts.tp + d.before.counts.fp;
  return (
    <div className="device siem overflow-hidden rounded-2xl">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line px-4 py-2.5 text-[0.8125rem]">
        <span className="flex items-center gap-1.5 font-semibold text-ink">
          <span className="live-dot size-2 rounded-full bg-ok-mark" aria-hidden="true" />
          Process events
        </span>
        <span className="text-ink-3">rule: {d.rule_title}</span>
        <span
          className={cx(
            "ml-auto rounded-full px-2.5 py-0.5 text-[0.75rem] font-bold",
            alerts > 0 ? "bg-crit-bg text-crit" : "bg-inset text-ink-2",
          )}
        >
          {alerts} {alerts === 1 ? "alert" : "alerts"}
        </span>
      </div>
      <div className={cx("border-b border-line px-4 py-2 text-[0.75rem]", side === "with" ? "bg-ok-bg text-ok" : "bg-high-bg text-high")}>
        {side === "with" ? (
          <span className="flex items-start gap-1.5">
            <Icon name="checkCircle" size={13} className="mt-0.5 flex-none" />
            <span className="min-w-0 break-words">
              Mapping repaired: CommandLine → <code className="text-[0.75rem] break-all">{patch?.to_field}</code>
            </span>
          </span>
        ) : (
          <span className="flex items-start gap-1.5">
            <Icon name="alert" size={13} className="mt-0.5 flex-none" />
            <span className="min-w-0 break-words">
              Pipeline update: the rule still reads <code className="text-[0.75rem] break-all">{patch?.from_field}</code>
            </span>
          </span>
        )}
      </div>
      <ol className="divide-y divide-line" aria-label="Replayed events">
        {d.events.map((event, index) => {
          const hit = matched.has(event.event_id);
          const attack = event.label === "malicious";
          return (
            <li
              key={event.event_id}
              className={cx("event-row grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 px-4 py-2", hit && "event-hit")}
              style={{ animationDelay: `${String(index * 260)}ms` }}
            >
              <span
                className={cx("size-2 rounded-full", attack ? "bg-crit-mark" : "bg-ok-mark")}
                title={attack ? "attack (synthetic label)" : "benign (synthetic label)"}
                aria-hidden="true"
              />
              <span className="min-w-0">
                <code className="block truncate text-[0.75rem] text-ink">{event.command_line}</code>
                <span className="text-[0.6875rem] text-ink-3">
                  {event.event_id} · {attack ? "attack" : "benign"}
                </span>
              </span>
              {hit ? (
                <span className="inline-flex items-center gap-1 rounded-full bg-crit-bg px-2 py-0.5 text-[0.6875rem] font-bold text-crit">
                  <Icon name="octagon" size={11} />
                  ALERT
                </span>
              ) : attack ? (
                <span className="missed rounded-full border border-dashed border-high-mark px-2 py-0.5 text-[0.6875rem] font-semibold text-high">
                  no alert
                </span>
              ) : (
                <span className="px-2 text-[0.6875rem] text-ink-3">quiet</span>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function Count({ value, label, tone }: { value: number; label: string; tone: "crit" | "ok" | "neutral" }) {
  return (
    <div className="glass rounded-xl px-3 py-2.5">
      <p
        className={cx(
          "display text-[2rem] leading-none tabular-nums",
          tone === "crit" ? "text-crit" : tone === "ok" ? "text-ok" : "text-ink",
        )}
      >
        {value}
      </p>
      <p className="mt-1 text-[0.75rem] text-ink-2">{label}</p>
    </div>
  );
}

function DiffLines() {
  const lines = d.diff.split("\n").filter((line) => /^[+-](?![+-])/.test(line));
  return (
    <pre className="overflow-x-auto rounded-xl border border-line bg-inset p-3 text-[0.75rem] leading-relaxed" role="region" aria-label="Patch" tabIndex={0}>
      <code>
        <span className="block text-ink-3">mapping.yml</span>
        {lines.map((line) => (
          <span
            key={line}
            className={cx("-mx-3 block px-3", line.startsWith("+") ? "bg-(--diff-add-bg) text-ok" : "bg-(--diff-del-bg) text-crit")}
          >
            {line}
          </span>
        ))}
      </code>
    </pre>
  );
}

function WithAside() {
  const hyp = d.hypotheses[0];
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <div className="flex flex-wrap items-center gap-4">
        <Stamp label={d.outcome} sub={`replayed on Elasticsearch ${d.engine_version}`} tone="ok" />
      </div>
      <ol className="grid min-w-0 gap-3 [&>li]:min-w-0">
        <li className="glass rounded-xl p-3">
          <p className="text-[0.75rem] font-semibold tracking-[0.1em] text-accent-text uppercase">1 · Diagnosis</p>
          <p className="mt-1 text-[0.9375rem] text-ink">
            {hyp?.family === "mapping" ? "Mapping drift" : hyp?.family}:{" "}
            {missing ? (
              <>
                <code className="text-[0.8125rem] break-all">{missing.index_field}</code> is present in {missing.present} of {missing.total} events
              </>
            ) : null}
            ; the same data arrives in <code className="text-[0.8125rem] break-all">{hyp?.alternative_index_fields[0]}</code>.
          </p>
          <p className="mt-1 text-[0.75rem] text-ink-3">reason codes: {hyp?.reason_codes.join(", ")}</p>
        </li>
        <li className="glass rounded-xl p-3">
          <p className="mb-2 text-[0.75rem] font-semibold tracking-[0.1em] text-accent-text uppercase">2 · Patch</p>
          <DiffLines />
        </li>
        <li className="glass rounded-xl p-3">
          <p className="text-[0.75rem] font-semibold tracking-[0.1em] text-accent-text uppercase">3 · Replayed on held-out events</p>
          <div className="mt-2 grid grid-cols-3 gap-2 [&>*]:min-w-0">
            <Count value={d.after.counts.tp} label={`of ${String(attacks)} attacks alerted`} tone="ok" />
            <Count value={d.after.counts.fp} label="false alarms" tone="neutral" />
            <Count value={d.after.counts.tn} label={`of ${String(benign)} benign quiet`} tone="neutral" />
          </div>
        </li>
      </ol>
    </div>
  );
}

function WithoutAside() {
  return (
    <div className="flex h-full flex-col gap-4">
      <div className="grid grid-cols-2 gap-2">
        <Count value={d.healthy.counts.tp} label="alerts before the rename" tone="ok" />
        <Count value={d.before.counts.tp} label={`alerts after, on ${String(d.before.counts.tp + d.before.counts.fn)} attacks`} tone="crit" />
      </div>
      <Story
        steps={[
          { icon: "wrench", text: "A pipeline update moves the command line to a new field. Nobody touches the rule." },
          { icon: "search", text: "The rule still looks in the old field, which is now empty. It raises no error." },
          { icon: "minus", text: "Attacks keep arriving. The dashboard stays calm." },
        ]}
        outcome={{
          title: `${String(d.before.counts.fn)} attacks, ${String(d.before.counts.tp)} alerts`,
          text: "A quiet rule looks exactly like a quiet network.",
        }}
      />
    </div>
  );
}

export function DetectScene() {
  return (
    <Compare
      name="the detection rule"
      without={<Pane device={<EventStream />} aside={<WithoutAside />} />}
      withKestrix={<Pane device={<EventStream />} aside={<WithAside />} />}
    />
  );
}
