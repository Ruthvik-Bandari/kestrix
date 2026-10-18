// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0

const units = ["bytes", "KB", "MB", "GB"];

export function formatBytes(n: number): string {
  if (n < 1024) return `${n.toLocaleString()} ${n === 1 ? "byte" : "bytes"}`;
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit] ?? "GB"}`;
}

export function compact(n: number): string {
  return Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

export function hexOffset(n: number): string {
  return `0x${n.toString(16).toUpperCase().padStart(6, "0")}`;
}

export function shortHash(hash: string): string {
  return hash.length > 16 ? `${hash.slice(0, 12)}…` : hash;
}

export function satsToBtc(sats: number): string {
  return `${(sats / 1e8).toLocaleString("en", { minimumFractionDigits: 0, maximumFractionDigits: 8 })} BTC`;
}
