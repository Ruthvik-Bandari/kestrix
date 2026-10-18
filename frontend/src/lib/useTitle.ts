// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect } from "react";

export function useTitle(title: string): void {
  useEffect(() => {
    document.title = title ? `${title} · Kestrix` : "Kestrix";
  }, [title]);
}
