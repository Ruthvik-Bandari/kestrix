// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { FailedRequest, LiveStatus, PendingPanel, ToolLayout } from "../../components/report";
import { ReportOutline, stageOf, Workspace } from "../../components/toolframe";
import { Tabs } from "../../components/Tabs";
import { StatusPill, Verdict } from "../../components/ui";
import { api } from "../../lib/api";
import { keys, useEngine } from "../../lib/queries";
import type { DetectReport, RunBody } from "../../lib/types";
import { outlines } from "../tools/frame";
import { ToolFrame } from "../tools/ToolHeader";
import { CaseGallery } from "./CaseGallery";
import { CustomRuleForm } from "./CustomRuleForm";
import { EngineHint } from "./EngineHint";
import { ReportView } from "./ReportView";

type Tab = "cases" | "custom";

function EnginePill() {
  const engine = useEngine();
  if (engine.isPending) return <StatusPill tone="neutral">Checking engine…</StatusPill>;
  if (engine.isError || !engine.data.reachable) return <StatusPill tone="high">Engine off</StatusPill>;
  if (!engine.data.pinned)
    return (
      <StatusPill tone="med">
        Elasticsearch {engine.data.version}, expected {engine.data.pinned_version}
      </StatusPill>
    );
  return <StatusPill tone="ok">Engine ready · Elasticsearch {engine.data.version}</StatusPill>;
}

/** The engine is off: say so before a run is attempted, with the steps to start it. */
function EngineDown() {
  return (
    <section aria-label="Detection engine not running" className="space-y-3">
      <Verdict tone="high" icon="octagon" title="The pinned detection engine is not running">
        Repairs can&apos;t be replayed yet, so nothing is tested. Start the engine, then run again.
      </Verdict>
      <EngineHint />
    </section>
  );
}

function Before() {
  return (
    <ReportOutline sections={outlines.detect}>
      <div>
        <h3 className="font-semibold">Proof on labeled events</h3>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-2">
          <li>Replay counts before and after, on development events and on a held-out validation set.</li>
          <li>A failed replay shows &ldquo;not available&rdquo;, never zero.</li>
          <li>A repair proves only what your labeled events show. It does not prove the rule catches every attack.</li>
        </ul>
      </div>
    </ReportOutline>
  );
}

export default function DetectPage() {
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "custom" ? "custom" : "cases";
  const engine = useEngine();
  const queryClient = useQueryClient();
  const [runningCase, setRunningCase] = useState<string | null>(null);

  const run = useMutation<DetectReport, Error, { caseId: string } | { body: RunBody }>({
    mutationFn: (input) => ("caseId" in input ? api.runCase(input.caseId) : api.runRule(input.body)),
    onSettled: (report) => {
      setRunningCase(null);
      if (report?.outcome === "engine_unavailable") void queryClient.invalidateQueries({ queryKey: keys.engine });
    },
  });

  const engineDown = engine.isSuccess && !engine.data.reachable;

  const result = run.isPending ? (
    <PendingPanel title="Running the repair workflow">
      Diagnosing the rule, trying bounded changes and replaying them on the local engine. Nothing leaves this computer.
    </PendingPanel>
  ) : run.isError ? (
    <FailedRequest
      error={run.error}
      onRetry={() => {
        run.mutate(run.variables);
      }}
    />
  ) : run.data ? (
    <ReportView report={run.data} />
  ) : null;

  const stage = stageOf({ ready: false, pending: run.isPending, failed: run.isError, done: Boolean(run.data) });

  return (
    <ToolFrame page="detect" aside={<EnginePill />}>

      <LiveStatus
        pending={run.isPending}
        done={run.isSuccess}
        pendingText="Running the repair workflow…"
        doneText="Repair finished. The result is below."
      />

      <Tabs<Tab>
        label="Choose input"
        value={tab}
        onChange={(next) => {
          setParams(next === "custom" ? { tab: "custom" } : {}, { replace: true });
        }}
        items={[
          { key: "cases", label: "Sample cases" },
          { key: "custom", label: "Your own rule" },
        ]}
      >
        {tab === "cases" ? (
          <ToolLayout
            jump={false}
            stage={stage}
            input={
              <Workspace
                steps={[
                  {
                    key: "case",
                    title: "Pick a sample case",
                    children: (
                      <CaseGallery
                        runningId={runningCase}
                        onRun={(caseId) => {
                          setRunningCase(caseId);
                          run.mutate({ caseId });
                        }}
                      />
                    ),
                  },
                ]}
              />
            }
          >
            {engineDown && !run.data ? <EngineDown /> : null}
            {result ?? (
              // The case list is taller than a screen, so the explanation stays in view beside it.
              <div className="min-[1100px]:sticky min-[1100px]:top-6">
                <Before />
              </div>
            )}
          </ToolLayout>
        ) : (
          <div className="space-y-8">
            {engineDown && !run.data ? <EngineDown /> : null}
            <CustomRuleForm
              running={run.isPending}
              onRun={(body) => {
                run.mutate({ body });
              }}
            />
            {result ?? <Before />}
          </div>
        )}
      </Tabs>
    </ToolFrame>
  );
}
