// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

/**
 * A full page load. Used after sign-out and account deletion so nothing from the session
 * (reports in memory, cached queries, the CSRF token) survives into the next page.
 * An object so tests can spy on it; jsdom does not navigate.
 */
export const browser = {
  assign(url: string): void {
    window.location.assign(url);
  },
};
