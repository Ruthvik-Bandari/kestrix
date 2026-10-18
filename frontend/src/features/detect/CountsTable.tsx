// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { cx } from "../../components/ui";
import type { Counts, ReplayResult } from "../../lib/types";

const metrics: { key: keyof Omit<Counts, "unknown_matched">; label: string; code: string; higherIsBetter: boolean }[] = [
  { key: "tp", label: "Attacks caught", code: "TP", higherIsBetter: true },
  { key: "fn", label: "Attacks missed", code: "FN", higherIsBetter: false },
  { key: "fp", label: "False alarms", code: "FP", higherIsBetter: false },
  { key: "tn", label: "Benign events ignored", code: "TN", higherIsBetter: true },
];

export interface SplitCounts {
  split: "development" | "validation";
  before: ReplayResult;
  after?: ReplayResult | undefined;
}

function Change({ before, after, higherIsBetter }: { before: number; after: number; higherIsBetter: boolean }) {
  const delta = after - before;
  if (delta === 0) return <span className="text-ink-3">no change</span>;
  const better = higherIsBetter ? delta > 0 : delta < 0;
  return (
    <span className={cx("font-medium", better ? "text-ok" : "text-crit")}>
      {delta > 0 ? "+" : "−"}
      {Math.abs(delta)}
      <span className="sr-only">{better ? " (better)" : " (worse)"}</span>
    </span>
  );
}

const splitLabel = { development: "Development events", validation: "Validation events" };

/** Confusion counts before and after the repair, per labeled split. */
export function CountsTable({ splits }: { splits: SplitCounts[] }) {
  const hasAfter = splits.some((s) => s.after);
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {splits.map(({ split, before, after }) => (
        <div key={split} className="overflow-x-auto rounded-lg border border-line bg-surface">
          <table className="data-table">
            <caption className="border-b border-line px-3 py-2 text-left text-[0.875rem] font-semibold text-ink">
              {splitLabel[split]}
              <span className="ml-2 font-normal text-ink-2">
                {before.scenarios_detected.length} of {before.scenarios_expected.length} attack scenarios caught before
                {after ? `, ${after.scenarios_detected.length} after` : ""}
              </span>
            </caption>
            <thead>
              <tr>
                <th scope="col">Measure</th>
                <th scope="col" className="num">
                  {hasAfter ? "Before" : "Result"}
                </th>
                {after ? (
                  <>
                    <th scope="col" className="num">
                      After
                    </th>
                    <th scope="col" className="num">
                      Change
                    </th>
                  </>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {metrics.map((m) => (
                <tr key={m.key}>
                  <th scope="row">
                    {m.label} <span className="font-mono text-xs text-ink-3">{m.code}</span>
                  </th>
                  <td className="num">{before.error ? "—" : before.counts[m.key]}</td>
                  {after ? (
                    <>
                      <td className="num font-medium">{after.error ? "—" : after.counts[m.key]}</td>
                      <td className="num">
                        {before.error || after.error ? (
                          "—"
                        ) : (
                          <Change before={before.counts[m.key]} after={after.counts[m.key]} higherIsBetter={m.higherIsBetter} />
                        )}
                      </td>
                    </>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
          {before.error ? <p className="px-3 py-2 text-[0.8125rem] text-crit">Replay error: {before.error}</p> : null}
        </div>
      ))}
    </div>
  );
}
