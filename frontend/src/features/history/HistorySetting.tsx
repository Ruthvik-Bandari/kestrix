// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { dashboardPath } from "../../app/paths";
import { Dialog } from "../../components/Dialog";
import { ErrorState, Skeleton, Spinner, Switch } from "../../components/ui";
import { api } from "../../lib/api";
import { plural } from "../../lib/format";
import { isHosted } from "../../lib/mode";
import { keys, useHistory } from "../../lib/queries";

/** Settings: keep a 30-day history of reports, or not. Turning it off deletes what is saved. */
export function HistorySetting() {
  const history = useHistory(1);
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const toggle = useMutation({
    mutationFn: api.setHistoryEnabled,
    onSuccess: () => {
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: keys.history });
    },
  });
  const data = history.data;
  const hosted = isHosted();

  return (
    <section aria-labelledby="history-title" className="panel mt-6 max-w-3xl p-5 sm:p-6">
      <div className="relative">
        <h2 id="history-title" className="mb-3 text-lg font-semibold">
          Results history
        </h2>
        {history.isPending ? (
          <Skeleton className="h-12 w-full max-w-md" />
        ) : history.isError ? (
          <ErrorState error={history.error} />
        ) : data ? (
          <Switch
            checked={data.enabled}
            label="Keep my reports for 30 days"
            description={
              hosted
                ? "Reports from the email, web, file and link checks are kept, encrypted, so you can open them again in Recent results. Uploaded files and emails are never stored. Turning this off deletes your saved reports."
                : "Reports from the email, web, file and link checks are kept in your Kestrix folder on this computer so you can open them again in Recent results. Turning this off deletes the saved reports."
            }
            onChange={(enabled) => {
              if (enabled) toggle.mutate(true);
              else setConfirming(true);
            }}
          />
        ) : null}
        {toggle.isPending && toggle.variables ? (
          <p className="mt-3">
            <Spinner label="Turning history on…" />
          </p>
        ) : null}
        {toggle.isError && !confirming ? (
          <div className="mt-4">
            <ErrorState error={toggle.error} />
          </div>
        ) : null}
        <p className="mt-4 text-[0.875rem] text-ink-2">
          <Link to={dashboardPath("history")} className="link">
            Open Recent results
          </Link>
        </p>
      </div>
      {confirming ? (
        <Dialog
          title="Turn off history?"
          onClose={() => {
            setConfirming(false);
          }}
        >
          <div className="grid gap-4">
            <p className="text-ink-2">
              New reports will not be saved, and {plural(data?.total ?? 0, "saved report")} will be deleted now. This
              cannot be undone.
            </p>
            {toggle.isError ? <ErrorState error={toggle.error} /> : null}
            <div className="flex flex-wrap justify-end gap-2">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setConfirming(false);
                }}
              >
                Keep history on
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={toggle.isPending}
                onClick={() => {
                  toggle.mutate(false);
                }}
              >
                {toggle.isPending ? <Spinner /> : null}
                Turn off and delete
              </button>
            </div>
          </div>
        </Dialog>
      ) : null}
    </section>
  );
}
