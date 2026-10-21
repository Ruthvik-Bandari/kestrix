// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { HowItWorks, type HowItWorksContent } from "../../components/HowItWorks";
import { Tabs } from "../../components/Tabs";
import { ErrorState, PageHeader, StatusPill } from "../../components/ui";
import { api } from "../../lib/api";
import { keys, useEngine } from "../../lib/queries";
import type { DetectReport, RunBody } from "../../lib/types";
import { isHosted } from "../../lib/mode";
import { CliGuide } from "../guides/CliGuide";
import { useTitle } from "../../lib/useTitle";
import { CaseGallery } from "./CaseGallery";
import { CustomRuleForm } from "./CustomRuleForm";
import { EngineHint } from "./EngineHint";
import { ReportView } from "./ReportView";

type Tab = "cases" | "custom";

const howItWorks: HowItWorksContent = {
  id: "detect",
  name: "Detection repair",
  purpose:
    "Find out why a Sigma detection rule misses attacks or fires on harmless activity, and get the smallest fix that replay on labeled events supports.",
  steps: [
    "Pick a bundled sample case, or give your own Sigma rule, an environment field mapping and labeled development events. Validation events are optional.",
    "Kestrix checks which fields the rule needs against what your events contain, then replays the rule on a pinned Elasticsearch 8.19.3 in a fresh, throwaway index.",
    "It diagnoses the cause (mapping drift, noise, a logic fault or missing telemetry) and screens up to four candidate fixes of at most three edits each.",
    "A fix is chosen on the development events, then checked on held-out validation events. You get the outcome, replay counts and a diff.",
  ],
  usefulWhen: [
    "A rule went quiet after a log pipeline or field-name change.",
    "A rule floods you with false alarms.",
    "You want to know whether the telemetry a rule needs is collected at all.",
  ],
  doesNot: [
    "It does not guess: unclear evidence gives abstained or insufficient evidence instead of a forced fix.",
    "It covers single-event Windows process_creation rules; anything else is reported as unsupported.",
    "It cannot replay without the engine, which needs Docker (kestrix detect engine-up).",
    "Without validation events a repair is only provisional, and the bundled cases are synthetic demonstrations, not a benchmark.",
  ],
};

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
      <HowItWorks content={howItWorks} />

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
      {isHosted() ? null : (
        <div className="mt-12">
          <CliGuide tool="detect" />
        </div>
      )}
    </>
  );
}
