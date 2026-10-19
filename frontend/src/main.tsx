// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";
import { createAppRouter } from "./app/router";
import { redirectOnSignInRequired } from "./app/session";
import { api, ApiError } from "./lib/api";
import { modeFromHealth, setMode } from "./lib/mode";
import { keys } from "./lib/queries";
import { applyTheme } from "./lib/theme";
import type { Health } from "./lib/types";
import "./index.css";

applyTheme();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      // Retry transient failures only; a 4xx/5xx with a reason is an answer, not a blip.
      retry: (count, error) => !(error instanceof ApiError && error.status > 0) && count < 2,
    },
    mutations: { retry: false },
  },
});

const root = document.getElementById("root");
if (!root) throw new Error("#root is missing from index.html");

/** The server says whether it is the hosted service; without an answer, behave as a local install. */
async function boot(mount: HTMLElement) {
  let health: Health | null = null;
  try {
    health = await api.health();
    queryClient.setQueryData(keys.health, health);
  } catch {
    // The dashboard's own pages show the connection error.
  }
  const mode = modeFromHealth(health);
  setMode(mode);
  const router = createAppRouter();
  if (mode === "hosted") redirectOnSignInRequired(router, queryClient);

  createRoot(mount).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </StrictMode>,
  );
}

void boot(root);
