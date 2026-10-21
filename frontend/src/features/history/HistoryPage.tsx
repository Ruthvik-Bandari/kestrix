// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { dashboardPath } from "../../app/paths";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { Badge, Button, cx, ErrorState, PageHeader, Skeleton, Spinner } from "../../components/ui";
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

/** Column template shared by the header and every row, from 640px up: tool, result, findings, time. */
const COLUMNS = "sm:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_5.5rem_11rem]";

function Row({ item, onDelete }: { item: HistoryItem; onDelete: (item: HistoryItem) => void }) {
  const tool = toolMeta[item.tool];
  const chip = verdictChip(item);
  const when = savedAt(item.created_at);
  return (
    <li className="flex items-center gap-1 border-b border-line last:border-b-0">
      <Link
        to={dashboardPath(`history/${encodeURIComponent(item.id)}`)}
        className={cx("grid min-h-14 min-w-0 flex-1 grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 rounded-lg px-3 py-2.5 hover:bg-inset", COLUMNS)}
      >
        <span className="flex min-w-0 items-center gap-3">
          <Icon name={tool.icon} size={18} className="flex-none text-accent-text" />
          <span className="min-w-0 font-semibold break-words text-ink">{tool.name}</span>
        </span>
        <span>
          <Badge tone={chip.tone}>{chip.label}</Badge>
        </span>
        <span className="col-span-2 flex flex-wrap gap-x-2 text-[0.8125rem] text-ink-3 sm:contents sm:text-[0.875rem] sm:text-ink-2">
          <span className="num">{plural(item.findings, "finding")}</span>
          <span aria-hidden="true" className="sm:hidden">
            ·
          </span>
          <time dateTime={when.iso}>{when.text}</time>
        </span>
      </Link>
      <Button
        variant="ghost"
        size="sm"
        className="min-h-11 min-w-11 flex-none"
        aria-label={`Delete the ${tool.name} result from ${when.text}`}
        onClick={() => {
          onDelete(item);
        }}
      >
        <Icon name="trash" size={16} />
      </Button>
    </li>
  );
}

/** Retention and deletion beside the list (above it on narrow screens): what is kept, for how long, and where. */
function Retention({
  enabled,
  days,
  where,
  total,
  onDeleteAll,
}: {
  enabled: boolean;
  days: number;
  where: string;
  total: number;
  onDeleteAll: () => void;
}) {
  return (
    <aside aria-label="Retention" className="panel space-y-3 p-5 xl:sticky xl:top-6 xl:col-start-2 xl:row-start-1">
      <p className="flex items-center gap-2 font-semibold text-ink">
        <Icon name="clock" size={16} className="text-ink-3" />
        {enabled ? "History is on" : "History is off"}
      </p>
      <p className="text-[0.875rem] text-ink-2">
        {enabled
          ? `Reports are kept ${where}, and results older than ${days} days are deleted automatically.`
          : "New results are not saved. Reports saved earlier stay until you delete them or they pass the retention limit."}
      </p>
      <p>
        <Link to={dashboardPath("settings")} className="link text-[0.875rem]">
          {enabled ? "Turn it off in Settings" : "Turn it on in Settings"}
        </Link>
      </p>
      {total > 0 ? (
        <div className="border-t border-line pt-3">
          <Button variant="secondary" size="sm" onClick={onDeleteAll}>
            <Icon name="trash" size={15} />
            Delete all
          </Button>
        </div>
      ) : null}
    </aside>
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
      <PageHeader title="Recent results" lede={`Reports from your email, web, file and link checks, kept ${where} for 30 days.`} />

      {history.isPending ? (
        <div className="space-y-3" role="status" aria-label="Loading your results">
          <Skeleton className="h-14 w-full" />
          <Skeleton className="h-14 w-full" />
          <Skeleton className="h-14 w-full" />
        </div>
      ) : history.isError ? (
        <div className="max-w-[68ch] space-y-3">
          <ErrorState error={history.error}>
            <p className="text-[0.875rem]">Your saved results are not affected.</p>
            <Button
              variant="secondary"
              size="sm"
              className="mt-3"
              onClick={() => {
                void history.refetch();
              }}
            >
              Try again
            </Button>
          </ErrorState>
        </div>
      ) : !data ? null : (
        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_17rem] xl:gap-8">
          <Retention
            enabled={data.enabled}
            days={data.retention_days}
            where={where}
            total={data.total}
            onDeleteAll={() => {
              setDeleting("all");
            }}
          />
          <div className="min-w-0 xl:col-start-1 xl:row-start-1">
            {data.items.length === 0 && data.total > 0 ? (
              <p className="panel px-5 py-6 text-ink-2">
                Nothing on this page.{" "}
                <Link to={dashboardPath("history")} className="link">
                  Go to the newest results
                </Link>
              </p>
            ) : data.items.length === 0 ? (
              <div className="panel max-w-[68ch] px-5 py-8">
                <p className="font-semibold text-ink">No results yet</p>
                <p className="mt-1 text-ink-2">
                  {data.enabled
                    ? "Run an email, web, file or link check and its report appears here."
                    : "History is off, so reports are not kept. Turn it on in Settings to keep them here."}
                </p>
                <Link to={dashboardPath()} className="btn btn-secondary mt-5">
                  <Icon name="grid" size={16} />
                  Choose a tool
                </Link>
              </div>
            ) : (
              <div className="panel px-2 py-1 sm:px-3">
                <div aria-hidden="true" className={cx("hidden gap-x-4 border-b border-line px-3 py-2 pr-[3.75rem] text-[0.75rem] font-semibold tracking-[0.06em] text-ink-3 uppercase sm:grid", COLUMNS)}>
                  <span className="pl-[1.875rem]">Tool</span>
                  <span>Result</span>
                  <span>Findings</span>
                  <span>Time</span>
                </div>
                <ul aria-label="Saved results, newest first">
                  {data.items.map((item) => (
                    <Row key={item.id} item={item} onDelete={setDeleting} />
                  ))}
                </ul>
              </div>
            )}
            {pages > 1 ? (
              <nav aria-label="Result pages" className="mt-5 flex items-center justify-between gap-3">
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => {
                    setParams({ page: String(page - 1) });
                  }}
                >
                  <Icon name="arrowLeft" size={15} />
                  Newer
                </Button>
                <span className="text-[0.875rem] text-ink-2">
                  Page {page} of {pages}
                </span>
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={page >= pages}
                  onClick={() => {
                    setParams({ page: String(page + 1) });
                  }}
                >
                  Older
                  <Icon name="arrowRight" size={15} />
                </Button>
              </nav>
            ) : null}
          </div>
        </div>
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
