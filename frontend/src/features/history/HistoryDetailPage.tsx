// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { dashboardPath } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { Badge, Button, ErrorState, PageHeader, Skeleton } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import { keys, useHistoryEntry } from "../../lib/queries";
import type { HistoryEntry } from "../../lib/types";
import { useTitle } from "../../lib/useTitle";
import { FileReportView } from "../forensics/FileAnalyzer";
import { UrlReportView } from "../forensics/UrlAnalyzer";
import { MailReportView } from "../mail/MailReportView";
import { WebReportView } from "../webcheck/WebcheckPage";
import { ConfirmDelete } from "./HistoryPage";
import { savedAt, toolMeta, verdictChip } from "./meta";

function SavedReport({ entry }: { entry: HistoryEntry }) {
  switch (entry.tool) {
    case "mail":
      return <MailReportView report={entry.report} />;
    case "webcheck":
      return <WebReportView report={entry.report} />;
    case "forensics_file":
      return <FileReportView report={entry.report} />;
    case "forensics_url":
      return <UrlReportView report={entry.report} />;
  }
}

function BackLink() {
  return (
    <Link to={dashboardPath("history")} className="link mb-5 inline-flex items-center gap-1.5 text-[0.875rem] font-semibold">
      <Icon name="arrowLeft" size={15} />
      Recent results
    </Link>
  );
}

export default function HistoryDetailPage() {
  const id = useParams().id ?? "";
  const entry = useHistoryEntry(id);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const remove = useMutation({
    mutationFn: () => api.deleteHistoryEntry(id),
    onSuccess: () => {
      queryClient.removeQueries({ queryKey: keys.historyEntry(id) });
      void queryClient.invalidateQueries({ queryKey: keys.history });
      void navigate(dashboardPath("history"), { replace: true });
    },
  });
  const data = entry.data;
  useTitle(data ? `${toolMeta[data.tool].name} result` : "Saved result");

  if (entry.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label="Loading the saved result">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }
  if (entry.isError || !data) {
    const missing = entry.error instanceof ApiError && entry.error.status === 404;
    return (
      <>
        <BackLink />
        {missing ? (
          <div className="panel max-w-[68ch] px-5 py-8">
            <h1 className="text-xl font-bold">Result not found</h1>
            <p className="mt-1 text-ink-2">It may have been deleted, or it is older than 30 days.</p>
          </div>
        ) : (
          <div className="max-w-[68ch]">
            <ErrorState error={entry.error}>
              <Button
                variant="secondary"
                size="sm"
                className="mt-1"
                onClick={() => {
                  void entry.refetch();
                }}
              >
                Try again
              </Button>
            </ErrorState>
          </div>
        )}
      </>
    );
  }

  const tool = toolMeta[data.tool];
  const when = savedAt(data.created_at);
  const chip = verdictChip(data);
  return (
    <>
      <BackLink />
      <PageHeader
        title={tool.name}
        lede={
          <>
            Saved <time dateTime={when.iso}>{when.text}</time>. This is the report as it was produced; the check is not
            run again.
          </>
        }
        aside={
          <>
            <Badge tone={chip.tone}>{chip.label}</Badge>
            <Link to={dashboardPath(tool.page)} className="btn btn-secondary btn-sm">
              <Icon name={tool.icon} size={15} />
              Run a new check
            </Link>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => {
                setConfirming(true);
              }}
            >
              <Icon name="trash" size={15} />
              Delete
            </button>
          </>
        }
      />
      <SavedReport entry={data} />
      {confirming ? (
        <ConfirmDelete
          title="Delete this result?"
          body={`The ${tool.name} report from ${when.text} is deleted permanently.`}
          action="Delete"
          pending={remove.isPending}
          error={remove.error}
          onConfirm={() => {
            remove.mutate();
          }}
          onClose={() => {
            setConfirming(false);
          }}
        />
      ) : null}
    </>
  );
}
