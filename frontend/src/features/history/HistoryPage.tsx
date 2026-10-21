// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { dashboardPath } from "../../app/paths";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { Badge, ErrorState, PageHeader, Skeleton, Spinner } from "../../components/ui";
import { api } from "../../lib/api";
import { plural } from "../../lib/format";
import { isHosted } from "../../lib/mode";
import { keys, useHistory } from "../../lib/queries";
import type { HistoryItem } from "../../lib/types";
import { useTitle } from "../../lib/useTitle";
import { savedAt, toolMeta, verdictChip } from "./meta";

/** Confirm before deleting: one result or all of them. */
export function ConfirmDelete({
  title,
  body,
  action,
  onConfirm,
  onClose,
  pending,
  error,
}: {
  title: string;
  body: string;
  action: string;
  onConfirm: () => void;
  onClose: () => void;
  pending: boolean;
  error: unknown;
}) {
  return (
    <Dialog title={title} onClose={onClose}>
      <div className="grid gap-4">
        <p className="text-ink-2">{body}</p>
        {error ? <ErrorState error={error} /> : null}
        <div className="flex flex-wrap justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-danger" disabled={pending} onClick={onConfirm}>
            {pending ? <Spinner /> : <Icon name="trash" size={16} />}
            {action}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

function Row({ item, onDelete }: { item: HistoryItem; onDelete: (item: HistoryItem) => void }) {
  const tool = toolMeta[item.tool];
  const chip = verdictChip(item);
  const when = savedAt(item.created_at);
  return (
    <li className="flex items-center gap-2 border-b border-line last:border-b-0">
      <Link
        to={dashboardPath(`history/${encodeURIComponent(item.id)}`)}
        className="flex min-h-16 min-w-0 flex-1 items-center gap-3 rounded-xl px-2 py-3 hover:bg-inset sm:gap-4 sm:px-3"
      >
        <span className="launcher-icon flex size-10 flex-none items-center justify-center rounded-xl">
          <Icon name={tool.icon} size={19} className="text-accent-text" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block font-semibold text-ink">{tool.name}</span>
          <span className="block text-[0.8125rem] text-ink-3">
            <time dateTime={when.iso}>{when.text}</time> · {plural(item.findings, "finding")}
          </span>
        </span>
        <Badge tone={chip.tone}>{chip.label}</Badge>
      </Link>
      <button
        type="button"
        className="btn btn-ghost btn-sm min-h-10 min-w-10 flex-none"
        aria-label={`Delete the ${tool.name} result from ${when.text}`}
        onClick={() => {
          onDelete(item);
        }}
      >
        <Icon name="trash" size={16} />
      </button>
    </li>
  );
}

export default function HistoryPage() {
  useTitle("Recent results");
  const [params, setParams] = useSearchParams();
  const page = Math.max(1, Number(params.get("page")) || 1);
  const history = useHistory(page);
  const queryClient = useQueryClient();
  const [deleting, setDeleting] = useState<HistoryItem | "all" | null>(null);
  const done = () => {
    setDeleting(null);
    void queryClient.invalidateQueries({ queryKey: keys.history });
  };
  const removeOne = useMutation({ mutationFn: api.deleteHistoryEntry, onSuccess: done });
  const removeAll = useMutation({ mutationFn: api.clearHistory, onSuccess: done });
  const data = history.data;
  const pages = data ? Math.max(1, Math.ceil(data.total / data.per_page)) : 1;
  const where = isHosted() ? "on Kestrix's server, encrypted" : "on this computer";

  return (
    <>
      <PageHeader
        title="Recent results"
        lede={`Reports from your email, web, file and link checks, kept ${where} for 30 days. Uploaded files and emails are never stored, only the reports.`}
        aside={
          data && data.total > 0 ? (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setDeleting("all");
              }}
            >
              <Icon name="trash" size={16} />
              Delete all
            </button>
          ) : undefined
        }
      />

      {history.isPending ? (
        <div className="space-y-3" role="status" aria-label="Loading your results">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      ) : history.isError ? (
        <ErrorState error={history.error} />
      ) : !data ? null : (
        <>
          <p className="mb-4 flex flex-wrap items-center gap-x-2 gap-y-1 text-[0.875rem] text-ink-2">
            <Icon name="clock" size={15} className="text-ink-3" />
            {data.enabled ? `History is on · results older than ${data.retention_days} days are deleted automatically.` : "History is off · new results are not saved."}
            <Link to={dashboardPath("settings")} className="link">
              {data.enabled ? "Turn it off in Settings" : "Turn it on in Settings"}
            </Link>
          </p>
          {data.items.length === 0 && data.total > 0 ? (
            <p className="panel px-5 py-6 text-ink-2">
              <span className="relative">
                Nothing on this page.{" "}
                <Link to={dashboardPath("history")} className="link">
                  Go to the newest results
                </Link>
              </span>
            </p>
          ) : data.items.length === 0 ? (
            <div className="panel px-5 py-10 text-center">
              <p className="relative font-semibold text-ink">No results yet</p>
              <p className="relative mt-1 text-ink-2">
                {data.enabled ? "Run an email, web, file or link check and its report appears here." : "Turn history on to keep your reports here."}
              </p>
              <Link to={dashboardPath()} className="btn btn-secondary relative mt-5">
                <Icon name="grid" size={16} />
                Choose a tool
              </Link>
            </div>
          ) : (
            <ul className="panel px-2 py-1 sm:px-3" aria-label="Saved results, newest first">
              {data.items.map((item) => (
                <Row key={item.id} item={item} onDelete={setDeleting} />
              ))}
            </ul>
          )}
          {pages > 1 ? (
            <nav aria-label="Result pages" className="mt-5 flex items-center justify-between gap-3">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={page <= 1}
                onClick={() => {
                  setParams({ page: String(page - 1) });
                }}
              >
                <Icon name="arrowLeft" size={15} />
                Newer
              </button>
              <span className="text-[0.875rem] text-ink-2">
                Page {page} of {pages}
              </span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={page >= pages}
                onClick={() => {
                  setParams({ page: String(page + 1) });
                }}
              >
                Older
                <Icon name="arrowRight" size={15} />
              </button>
            </nav>
          ) : null}
        </>
      )}

      {deleting === "all" ? (
        <ConfirmDelete
          title="Delete all results?"
          body={`This permanently deletes ${plural(data?.total ?? 0, "saved result")}. It cannot be undone.`}
          action="Delete all"
          pending={removeAll.isPending}
          error={removeAll.error}
          onConfirm={() => {
            removeAll.mutate();
          }}
          onClose={() => {
            setDeleting(null);
          }}
        />
      ) : deleting ? (
        <ConfirmDelete
          title="Delete this result?"
          body={`The ${toolMeta[deleting.tool].name} report from ${savedAt(deleting.created_at).text} is deleted permanently.`}
          action="Delete"
          pending={removeOne.isPending}
          error={removeOne.error}
          onConfirm={() => {
            removeOne.mutate(deleting.id);
          }}
          onClose={() => {
            setDeleting(null);
          }}
        />
      ) : null}
    </>
  );
}
