// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
import { dashboardPath } from "../../app/paths";
import { ErrorState, PageHeader, Panel, Spinner } from "../../components/ui";
import { api } from "../../lib/api";
import { keys } from "../../lib/queries";
import { useTitle } from "../../lib/useTitle";

/**
 * Where Google or Microsoft sends the browser after sign-in (local mode only, ADR 0009). The address holds a
 * one-time `code` and the `state`. This page removes them from the address bar at once, hands them to the local
 * server in a POST (which checks the state and that this browser started the sign-in), then opens the mailbox tab.
 */
export default function MailConnectPage() {
  useTitle("Connecting your mailbox");
  const navigate = useNavigate();
  const client = useQueryClient();
  const started = useRef(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const params = new URLSearchParams(window.location.search);
    window.history.replaceState(null, "", window.location.pathname);
    const state = params.get("state");
    (state
      ? api.mailboxCallback({ state, code: params.get("code"), error: params.get("error") })
      : Promise.reject(new Error("This address has no sign-in to finish. Start the connection again from the Email check page."))
    )
      .then((status) => {
        void client.invalidateQueries({ queryKey: keys.mailbox });
        void navigate(`${dashboardPath("mail")}?mailbox=${status.provider}`, { replace: true });
      })
      .catch((reason: unknown) => {
        setError(reason);
      });
  }, [client, navigate]);

  return (
    <div className="space-y-6">
      <PageHeader title="Connecting your mailbox" lede="Finishing the sign-in on this computer." />
      <Panel>
        {error ? (
          <div className="space-y-4">
            <ErrorState error={error} />
            <Link className="link" to={`${dashboardPath("mail")}?mailbox=gmail`}>
              Back to the Email check page
            </Link>
          </div>
        ) : (
          <p role="status" className="flex items-center gap-2 text-ink-2">
            <Spinner /> Checking the sign-in…
          </p>
        )}
      </Panel>
    </div>
  );
}
