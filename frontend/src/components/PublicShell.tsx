// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Link } from "react-router";
import { dashboardPath, landingPath, PRIVACY_PATH, TERMS_PATH } from "../app/paths";
import { site } from "../lib/site";
import { BrandMark } from "./BrandMark";
import { Icon } from "./Icon";
import { ThemeSwitch } from "./ThemeSwitch";
import { ThreatField } from "./ThreatField";
import { cx } from "./ui";

/** Links to the privacy notice and terms, shown in every footer. */
export function LegalLinks({ className }: { className?: string }) {
  return (
    <ul className={cx("flex flex-wrap gap-x-5 gap-y-2", className)}>
      <li>
        <Link className="link" to={PRIVACY_PATH}>
          Privacy
        </Link>
      </li>
      <li>
        <Link className="link" to={TERMS_PATH}>
          Terms
        </Link>
      </li>
    </ul>
  );
}

/** Chrome for pages outside the dashboard: sign-in, the legal pages and unknown addresses. */
export function PublicShell({ children, width = "narrow" }: { children: ReactNode; width?: "narrow" | "wide" }) {
  return (
    <div className="relative isolate flex min-h-dvh flex-col">
      <ThreatField />
      <a
        href="#public-main"
        className="sr-only rounded-lg bg-accent px-4 py-2 font-medium text-on-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50"
      >
        Skip to content
      </a>
      <header className="veil-rail sticky top-0 z-40 border-b border-line">
        <div className="mx-auto flex h-16 max-w-[80rem] items-center justify-between gap-4 px-4 sm:px-6">
          <Link to={landingPath()} className="flex items-center gap-2.5 rounded-md" aria-label="Kestrix home">
            <BrandMark size={28} />
            <span className="text-lg font-bold tracking-[-0.02em] text-ink">Kestrix</span>
          </Link>
          <Link to={dashboardPath()} className="btn btn-secondary btn-sm min-h-10">
            Open the dashboard
            <Icon name="arrowRight" size={15} />
          </Link>
        </div>
      </header>
      <main
        id="public-main"
        tabIndex={-1}
        className={cx(
          "relative z-10 mx-auto w-full flex-1 px-4 py-10 outline-none sm:px-6 sm:py-14",
          width === "narrow" ? "max-w-[34rem]" : "max-w-[52rem]",
        )}
      >
        {children}
      </main>
      <footer className="veil-rail relative z-10 border-t border-line">
        <div className="mx-auto grid max-w-[80rem] gap-6 px-4 py-8 text-[0.875rem] sm:px-6 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
          <div>
            <p className="flex items-center gap-2.5">
              <BrandMark size={22} />
              <span className="font-bold tracking-[-0.02em]">Kestrix by Ruthvik Bandari</span>
            </p>
            <LegalLinks className="mt-3" />
            <p className="mt-3 text-ink-3">
              Open source under the{" "}
              <a className="link" href={site.licenseUrl}>
                Apache License 2.0
              </a>
              .
            </p>
          </div>
          <div className="w-full max-w-[16rem]">
            <ThemeSwitch />
          </div>
        </div>
      </footer>
    </div>
  );
}
