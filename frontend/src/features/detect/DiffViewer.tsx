// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { cx } from "../../components/ui";

export type DiffLineKind = "add" | "del" | "context" | "hunk" | "file";

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
  oldNo: number | null;
  newNo: number | null;
}

const HUNK = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

/** Parse a unified diff into numbered lines. Unknown lines are kept as context. */
export function parseDiff(diff: string): DiffLine[] {
  const lines: DiffLine[] = [];
  let oldNo = 0;
  let newNo = 0;
  for (const raw of diff.replace(/\n$/, "").split("\n")) {
    if (raw.startsWith("--- ") || raw.startsWith("+++ ")) {
      lines.push({ kind: "file", text: raw, oldNo: null, newNo: null });
      continue;
    }
    const hunk = HUNK.exec(raw);
    if (hunk) {
      oldNo = Number(hunk[1]);
      newNo = Number(hunk[2]);
      lines.push({ kind: "hunk", text: raw, oldNo: null, newNo: null });
    } else if (raw.startsWith("+")) {
      lines.push({ kind: "add", text: raw.slice(1), oldNo: null, newNo: newNo++ });
    } else if (raw.startsWith("-")) {
      lines.push({ kind: "del", text: raw.slice(1), oldNo: oldNo++, newNo: null });
    } else if (raw.startsWith("\\")) {
      lines.push({ kind: "hunk", text: raw, oldNo: null, newNo: null });
    } else {
      lines.push({ kind: "context", text: raw.slice(1), oldNo: oldNo++, newNo: newNo++ });
    }
  }
  return lines;
}

const marker: Record<DiffLineKind, string> = { add: "+", del: "−", context: " ", hunk: "", file: "" };
const spoken: Partial<Record<DiffLineKind, string>> = { add: "Added: ", del: "Removed: " };

export function DiffViewer({ diff, label }: { diff: string; label: string }) {
  const lines = parseDiff(diff);
  const added = lines.filter((l) => l.kind === "add").length;
  const removed = lines.filter((l) => l.kind === "del").length;
  return (
    <figure className="overflow-hidden rounded-lg border border-line bg-surface">
      <figcaption className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-rail px-3 py-2 text-[0.8125rem] text-ink-2">
        <span className="font-mono">{label}</span>
        <span>
          <span className="font-medium text-ok">{added} added</span> ·{" "}
          <span className="font-medium text-crit">{removed} removed</span>
        </span>
      </figcaption>
      <div className="overflow-x-auto" tabIndex={0} role="region" aria-label={`Changes to ${label}`}>
        <table className="w-full border-collapse font-mono text-[0.8125rem] leading-6">
          <tbody>
            {lines
              .filter((l) => l.kind !== "file")
              .map((line, i) => (
                <tr
                  key={i}
                  data-kind={line.kind}
                  className={cx(
                    line.kind === "add" && "bg-(--diff-add-bg)",
                    line.kind === "del" && "bg-(--diff-del-bg)",
                    line.kind === "hunk" && "bg-inset text-ink-3",
                  )}
                >
                  {line.kind === "hunk" ? (
                    <td colSpan={4} className="px-3 py-0.5 whitespace-pre">
                      {line.text}
                    </td>
                  ) : (
                    <>
                      <td className="w-10 px-2 text-right text-ink-3 select-none" aria-hidden="true">
                        {line.oldNo ?? ""}
                      </td>
                      <td className="w-10 px-2 text-right text-ink-3 select-none" aria-hidden="true">
                        {line.newNo ?? ""}
                      </td>
                      <td
                        className={cx(
                          "w-5 text-center select-none",
                          line.kind === "add" ? "text-ok" : line.kind === "del" ? "text-crit" : "text-ink-3",
                        )}
                        aria-hidden="true"
                      >
                        {marker[line.kind]}
                      </td>
                      <td className="pr-4 whitespace-pre text-ink">
                        {spoken[line.kind] ? <span className="sr-only">{spoken[line.kind]}</span> : null}
                        {line.text}
                      </td>
                    </>
                  )}
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </figure>
  );
}
