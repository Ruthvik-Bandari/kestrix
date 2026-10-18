import { CopyButton } from "../../components/ui";

const COMMAND = "kestrix detect engine-up";

export function EngineHint() {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-line bg-surface px-4 py-3">
      <p className="text-ink-2">Start the pinned Elasticsearch engine (needs Docker), then refresh:</p>
      <code className="rounded bg-inset px-2 py-1 text-ink">{COMMAND}</code>
      <CopyButton text={COMMAND} label="Copy the engine start command" />
    </div>
  );
}
