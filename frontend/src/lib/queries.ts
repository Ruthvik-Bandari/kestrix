// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

export const keys = {
  health: ["health"] as const,
  settings: ["settings"] as const,
  engine: ["detect", "engine"] as const,
  cases: ["detect", "cases"] as const,
  migration: (type: string) => ["bitcoin", "migration", type] as const,
};

export const useHealth = () => useQuery({ queryKey: keys.health, queryFn: api.health, staleTime: 60_000 });
export const useSettings = () => useQuery({ queryKey: keys.settings, queryFn: api.settings });
export const useEngine = () =>
  useQuery({ queryKey: keys.engine, queryFn: api.engine, refetchInterval: 30_000, staleTime: 10_000 });
export const useCases = () => useQuery({ queryKey: keys.cases, queryFn: api.cases, staleTime: Infinity });
