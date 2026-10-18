// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

export const REPO_URL = "https://github.com/Ruthvik-Bandari/kestrix";

export const site = {
  repoUrl: REPO_URL,
  docsUrl: `${REPO_URL}/tree/main/docs`,
  licenseUrl: `${REPO_URL}/blob/main/LICENSE`,
  /**
   * Hosted accounts are coming (docs/adr/0004). When a sign-in URL is configured the landing
   * page shows a "Sign in" button; locally there is none.
   */
  signInUrl: null as string | null,
};
