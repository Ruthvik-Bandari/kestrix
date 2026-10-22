// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Icon } from "../../components/Icon";
import { Badge, Button, ErrorState, Skeleton, Spinner } from "../../components/ui";
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
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 py-3">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Badge tone={fault.tone} icon={null}>
            {fault.label}
          </Badge>
          <code className="text-xs text-ink-3">{item.case_id.split("-")[0]}</code>
        </div>
        <p className="mt-1.5 text-[0.9375rem] leading-snug font-semibold">{shortTitle(item.title)}</p>
        <p className="mt-0.5 text-[0.8125rem] text-ink-3">Expected: {expected ? outcomeMeta[expected].label.toLowerCase() : "not stated"}</p>
      </div>
      <Button
        variant="secondary"
        size="sm"
        className="min-h-11 sm:min-h-9"
        onClick={onRun}
        disabled={disabled}
        aria-label={`Run case: ${item.title}`}
      >
        {running ? <Spinner /> : <Icon name="play" size={14} />}
        {running ? "Running" : "Run"}
      </Button>
    </li>
  );
}

/** The bundled synthetic cases as a compact list: pick one and run it. Used as the input column. */
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
      <ul className="space-y-3" aria-label="Loading cases">
        {Array.from({ length: 6 }, (_, i) => (
          <li key={i}>
            <Skeleton className="h-16" />
          </li>
        ))}
      </ul>
    );
  }
  if (cases.isError) return <ErrorState error={cases.error} />;
  return (
    <>
      <p className="text-[0.875rem] text-ink-2">
        {cases.data.length} synthetic cases, each with a known fault and labeled attack and benign events. Run one to see the
        diagnose, repair and validate loop. Nothing leaves this computer.
      </p>
      <ul className="mt-3 -mb-3 divide-y divide-line border-t border-line">
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
