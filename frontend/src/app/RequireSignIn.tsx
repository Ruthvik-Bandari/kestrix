// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";
import { ErrorState, Spinner } from "../components/ui";
import { useMe } from "../lib/queries";
import { signInPath } from "./paths";

/** Hosted mode: the dashboard needs a session; without one, go to /signin and come back after. */
export function RequireSignIn({ children }: { children: ReactNode }) {
  const me = useMe();
  const location = useLocation();
  if (me.isPending) {
    return (
      <div className="flex min-h-dvh items-center justify-center">
        <Spinner label="Checking your session…" />
      </div>
    );
  }
  if (me.isError) {
    return (
      <div className="mx-auto max-w-xl px-4 py-16">
        <ErrorState error={me.error} />
      </div>
    );
  }
  if (!me.data.signed_in) {
    return <Navigate to={signInPath(`${location.pathname}${location.search}`)} replace />;
  }
  return <>{children}</>;
}
