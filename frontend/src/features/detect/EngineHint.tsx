// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { CopyButton } from "../../components/ui";

const COMMAND = "kestrix detect engine-up";
const STATUS = "kestrix detect engine-status";

/** How to start the pinned replay engine: the command, how to see that it is ready, and what to do next. */
export function EngineHint() {
  return (
    <div className="space-y-3 rounded-xl border border-line bg-surface-solid px-4 py-4 sm:px-5">
      <p className="text-ink-2">The replay engine is Elasticsearch 8.19.3 in Docker, started from a terminal on this computer.</p>
      <ol className="space-y-2.5 text-ink-2">
        <li className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span>1. Start it (needs Docker):</span>
          <code className="rounded-md bg-inset px-2 py-1 text-ink">{COMMAND}</code>
          <CopyButton text={COMMAND} label="Copy the engine start command" />
        </li>
        <li className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span>2. Wait until it reports ready:</span>
          <code className="rounded-md bg-inset px-2 py-1 text-ink">{STATUS}</code>
          <CopyButton text={STATUS} label="Copy the engine status command" />
        </li>
        <li>3. Come back here: the engine status at the top of the page refreshes on its own. Then run the repair again.</li>
      </ol>
    </div>
  );
}
