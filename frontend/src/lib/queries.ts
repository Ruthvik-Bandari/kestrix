// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { isHosted } from "./mode";

export const keys = {
  health: ["health"] as const,
  settings: ["settings"] as const,
  engine: ["detect", "engine"] as const,
  cases: ["detect", "cases"] as const,
  migration: (type: string) => ["bitcoin", "migration", type] as const,
  mailbox: ["mail", "mailbox"] as const,
  me: ["auth", "me"] as const,
  providers: ["auth", "providers"] as const,
  history: ["history"] as const,
  historyPage: (page: number) => ["history", "page", page] as const,
  historyEntry: (id: string) => ["history", "entry", id] as const,
};

export const useHealth = () => useQuery({ queryKey: keys.health, queryFn: api.health, staleTime: 60_000 });
// The engine and the Anthropic-key settings exist only locally; the hosted service answers 404.
export const useSettings = () => useQuery({ queryKey: keys.settings, queryFn: api.settings, enabled: !isHosted() });
export const useEngine = () =>
  useQuery({
    queryKey: keys.engine,
    queryFn: api.engine,
    refetchInterval: 30_000,
    staleTime: 10_000,
    enabled: !isHosted(),
  });
/** Hosted mode: who is signed in. Fetching it also refreshes the CSRF token (lib/api.ts). */
export const useMe = (enabled = true) => useQuery({ queryKey: keys.me, queryFn: api.me, staleTime: 5 * 60_000, enabled });
export const useProviders = () => useQuery({ queryKey: keys.providers, queryFn: api.providers, staleTime: Infinity });
export const useCases = () => useQuery({ queryKey: keys.cases, queryFn: api.cases, staleTime: Infinity });
export const useHistory = (page = 1) => useQuery({ queryKey: keys.historyPage(page), queryFn: () => api.history(page) });
export const useHistoryEntry = (id: string) =>
  useQuery({ queryKey: keys.historyEntry(id), queryFn: () => api.historyEntry(id), staleTime: Infinity });
