// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { AuthProvider } from "../../lib/types";

export const providerName: Record<AuthProvider, string> = { google: "Google", github: "GitHub" };

/**
 * A plain monogram for each provider, drawn here rather than copied from brand assets.
 * Decorative: the button text names the provider.
 */
export function ProviderMark({ provider }: { provider: AuthProvider }) {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true" className="flex-none">
      <circle cx="10" cy="10" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.55" />
      {provider === "google" ? (
        // A "G": an open ring with a bar into the centre.
        <path d="M14 7.2A4.6 4.6 0 1 0 14.6 10.6H10.4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      ) : (
        // Angle brackets: code.
        <path d="M8 7 5.2 10 8 13M12 7l2.8 3-2.8 3" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      )}
    </svg>
  );
}
