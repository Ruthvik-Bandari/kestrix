// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../components/Icon";
import { Badge, ErrorState, Skeleton, Spinner } from "../../components/ui";
import type { Tone } from "../../components/tone";
import { useCases } from "../../lib/queries";
import type { CaseManifest } from "../../lib/types";
import { outcomeMeta } from "./describe";

const faultMeta: Record<string, { label: string; tone: Tone }> = {
  none: { label: "Healthy control", tone: "ok" },
  mapping: { label: "Mapping drift", tone: "low" },
  noise: { label: "Noise", tone: "med" },
  missing_telemetry: { label: "Missing telemetry", tone: "high" },
  logic: { label: "Logic fault", tone: "med" },
  unsupported: { label: "Unsupported", tone: "neutral" },
};

/** Drop the "Kind: " prefix the case titles carry, since the badge already says it. */
function shortTitle(title: string): string {
  const i = title.indexOf(": ");
  return i > 0 && i < 24 ? title.slice(i + 2) : title;
}

function CaseItem({
  item,
  running,
  disabled,
  onRun,
}: {
  item: CaseManifest;
  running: boolean;
  disabled: boolean;
  onRun: () => void;
}) {
  const fault = faultMeta[item.fault?.kind ?? ""] ?? { label: item.fault?.kind ?? "Case", tone: "neutral" as const };
  const expected = item.expected?.outcome;
  return (
    <li className="flex flex-col rounded-xl border border-line bg-surface p-4 transition-colors duration-150 hover:border-line-strong">
      <div className="flex items-center justify-between gap-2">
        <Badge tone={fault.tone} icon={null}>
          {fault.label}
        </Badge>
        <code className="text-xs text-ink-3">{item.case_id.split("-")[0]}</code>
      </div>
      <h3 className="mt-3 text-[0.9375rem] leading-snug font-semibold">{shortTitle(item.title)}</h3>
      {item.fault?.detail ? <p className="mt-1 text-[0.875rem] text-ink-2">{item.fault.detail}</p> : null}
      <div className="mt-auto flex items-center justify-between gap-2 pt-4">
        <span className="text-[0.8125rem] text-ink-3">
          Expected: {expected ? outcomeMeta[expected].label.toLowerCase() : "—"}
        </span>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={onRun}
          disabled={disabled}
          aria-label={`Run case: ${item.title}`}
        >
          {running ? <Spinner /> : <Icon name="play" size={14} />}
          {running ? "Running" : "Run"}
        </button>
      </div>
    </li>
  );
}

export function CaseGallery({
  runningId,
  onRun,
}: {
  runningId: string | null;
  onRun: (id: string) => void;
}) {
  const cases = useCases();
  if (cases.isPending) {
    return (
      <ul className="grid gap-3 [grid-template-columns:repeat(auto-fill,minmax(16rem,1fr))]" aria-label="Loading cases">
        {Array.from({ length: 6 }, (_, i) => (
          <li key={i}>
            <Skeleton className="h-40" />
          </li>
        ))}
      </ul>
    );
  }
  if (cases.isError) return <ErrorState error={cases.error} />;
  return (
    <>
      <h2 className="sr-only">Sample cases</h2>
      <p className="mb-4 max-w-[68ch] text-ink-2">
        {cases.data.length} synthetic cases, each with a known fault and labeled attack and benign events. Run one to see the full
        diagnose, repair and validate loop. Nothing leaves this computer.
      </p>
      <ul className="grid gap-3 [grid-template-columns:repeat(auto-fill,minmax(16rem,1fr))]">
        {cases.data.map((item) => (
          <CaseItem
            key={item.case_id}
            item={item}
            running={runningId === item.case_id}
            disabled={runningId !== null}
            onRun={() => {
              onRun(item.case_id);
            }}
          />
        ))}
      </ul>
    </>
  );
}
