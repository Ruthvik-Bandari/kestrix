// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

/**
 * Where the public landing page lives. In hosted mode this becomes "/" and the dashboard
 * moves; change it here and the router, sidebar link and landing links follow.
 */
export const LANDING_PATH = "/welcome";

/** The dashboard home (overview). */
export const DASHBOARD_PATH = "/";

/** A dashboard page path such as "mail", wherever the dashboard is mounted. */
export function dashboardPath(page: string): string {
  return `${DASHBOARD_PATH.replace(/\/$/, "")}/${page}`;
}
