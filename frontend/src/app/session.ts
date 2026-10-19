// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { QueryClient } from "@tanstack/react-query";
import type { createBrowserRouter } from "react-router";
import { onSignInRequired } from "../lib/api";
import { keys } from "../lib/queries";
import type { Me } from "../lib/types";
import { landingPath, SIGNIN_PATH, signInPath } from "./paths";

type AppRouter = Pick<ReturnType<typeof createBrowserRouter>, "state" | "navigate">;

/**
 * Hosted mode: when any API call answers 401 `sign_in_required` (the session expired or was
 * ended elsewhere), forget the user and go to /signin, returning to this page afterwards.
 */
export function redirectOnSignInRequired(router: AppRouter, queryClient: QueryClient): void {
  onSignInRequired(() => {
    queryClient.setQueryData<Me>(keys.me, { signed_in: false });
    const { pathname, search } = router.state.location;
    if (pathname === SIGNIN_PATH || pathname === landingPath()) return;
    void router.navigate(signInPath(`${pathname}${search}`), { replace: true });
  });
}
