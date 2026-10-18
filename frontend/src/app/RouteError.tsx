// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { isRouteErrorResponse, Link, useRouteError } from "react-router";

/** Last-resort screen when a page fails to load or render. */
export function RouteError() {
  const error = useRouteError();
  const detail = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : error instanceof Error
      ? error.message
      : "Unknown error";
  return (
    <div className="mx-auto max-w-xl px-4 py-16">
      <h1 className="text-2xl font-semibold">This page couldn't load</h1>
      <p className="mt-2 text-ink-2">
        If you just upgraded Kestrix, reload the page to fetch the new dashboard files.
      </p>
      <p className="mt-3 rounded-lg bg-inset px-3 py-2 font-mono text-[0.8125rem] break-words">{detail}</p>
      <div className="mt-6 flex gap-2">
        <button type="button" className="btn btn-primary" onClick={() => { window.location.reload(); }}>
          Reload
        </button>
        <Link to="/" className="btn btn-secondary">
          Overview
        </Link>
      </div>
    </div>
  );
}
