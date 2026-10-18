// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { Tabs } from "../../components/Tabs";
import { ErrorState, PageHeader, StatusPill } from "../../components/ui";
import { api } from "../../lib/api";
import { keys, useEngine } from "../../lib/queries";
import type { DetectReport, RunBody } from "../../lib/types";
import { useTitle } from "../../lib/useTitle";
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

export default function DetectPage() {
  useTitle("Detection repair");
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

  return (
    <>
      <PageHeader
        title="Detection repair"
        lede="Find out why a Sigma detection rule stopped catching attacks, or catches too much, and get a fix that was replayed on labeled events before you see it."
        aside={<EnginePill />}
      />

      {engineDown ? (
        <div className="mb-6 space-y-2">
          <p className="font-medium">The pinned detection engine is not running, so repairs can't be replayed yet.</p>
          <EngineHint />
        </div>
      ) : null}

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
          <CaseGallery
            runningId={runningCase}
            onRun={(caseId) => {
              setRunningCase(caseId);
              run.mutate({ caseId });
            }}
          />
        ) : (
          <CustomRuleForm
            running={run.isPending}
            onRun={(body) => {
              run.mutate({ body });
            }}
          />
        )}
      </Tabs>

      <div aria-live="polite" className="sr-only">
        {run.isPending ? "Running the repair workflow…" : run.isSuccess ? "Repair finished. Results below." : ""}
      </div>

      {run.isError ? (
        <div className="mt-8">
          <ErrorState error={run.error} />
        </div>
      ) : null}
      {run.data ? <ReportView report={run.data} /> : null}
    </>
  );
}
