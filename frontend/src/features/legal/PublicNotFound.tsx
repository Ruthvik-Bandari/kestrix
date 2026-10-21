// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Link } from "react-router";
import { landingPath } from "../../app/paths";
import { PublicShell } from "../../components/PublicShell";
import { useTitle } from "../../lib/useTitle";

/** Hosted mode: an unknown address outside the dashboard. */
export default function PublicNotFound() {
  useTitle("Page not found");
  return (
    <PublicShell>
      <div className="panel px-6 py-10 text-center">
        <h1 className="text-2xl font-bold tracking-[-0.02em]">Page not found</h1>
        <p className="mt-2 text-ink-2">There is nothing at this address.</p>
        <Link to={landingPath()} className="btn btn-primary mt-6">
          Go to the home page
        </Link>
      </div>
    </PublicShell>
  );
}
