// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { Link } from "react-router";
import { dashboardPath, docsPath, landingPath, PRIVACY_PATH, SIGNIN_PATH, SIGNUP_PATH, TERMS_PATH } from "../app/paths";
import { isHosted } from "../lib/mode";
import { useMe } from "../lib/queries";
import { site } from "../lib/site";
import { BrandMark } from "./BrandMark";
import { Icon } from "./Icon";
import { ThemeSwitch } from "./ThemeSwitch";
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

function DashboardLink() {
  return (
    <Link to={dashboardPath()} className="btn btn-primary btn-sm min-h-10">
      <span className="hidden sm:inline">{isHosted() ? "Open workbench" : "Open the dashboard"}</span>
      <span className="sm:hidden">{isHosted() ? "Workbench" : "Dashboard"}</span>
      <Icon name="arrowRight" size={15} />
    </Link>
  );
}

/** Hosted: "Log in" and "Sign up" while signed out, as on the landing page (the dashboard would only send you to sign-in), the dashboard once signed in. */
function HostedAction() {
  const me = useMe();
  if (me.isPending) return null;
  if (me.data?.signed_in === true) return <DashboardLink />;
  return (
    <div className="flex items-center gap-2">
      <Link to={SIGNIN_PATH} className="btn btn-secondary btn-sm min-h-10">
        Log in
      </Link>
      <Link to={SIGNUP_PATH} className="btn btn-primary btn-sm min-h-10">
        Sign up
      </Link>
    </div>
  );
}

/** The one header action on public pages. Local mode has no accounts, so it is always the dashboard. */
export function HeaderAction() {
  return isHosted() ? <HostedAction /> : <DashboardLink />;
}

/** The footer of every public page: the attribution, the legal and project links, and the theme. */
export function SiteFooter() {
  return (
    <footer className="bg-rail relative z-10 border-t border-line">
      <div className="mx-auto grid max-w-[80rem] gap-6 px-4 py-8 text-[0.875rem] sm:px-6 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
        <div>
          <p className="flex items-center gap-2.5">
            <BrandMark size={22} />
            <span className="font-bold tracking-[-0.02em]">Kestrix by Ruthvik Bandari</span>
          </p>
          <p className="mt-3 max-w-[60ch] text-ink-2">
            Use Kestrix only on systems, files and websites you own or are authorized to assess.
          </p>
          <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-2">
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
            <li>
              <a className="link" href={site.repoUrl}>
                GitHub repository
              </a>
            </li>
            <li>
              <Link className="link" to={docsPath()}>
                Documentation
              </Link>
            </li>
            <li>
              <a className="link" href={site.licenseUrl}>
                License (Apache-2.0)
              </a>
            </li>
          </ul>
        </div>
        <div className="w-full max-w-[16rem]">
          <ThemeSwitch />
        </div>
      </div>
    </footer>
  );
}

/** Chrome for pages outside the dashboard: sign-in, the legal pages and unknown addresses. */
export function PublicShell({
  children,
  width = "narrow",
  action = true,
  backdrop,
}: {
  children: ReactNode;
  width?: "narrow" | "wide" | "article" | "docs";
  /** False on the sign-in page, whose card is the action. */
  action?: boolean;
  /** Decorative layer behind the page content (the sign-in rain); it fills the band between header and footer. */
  backdrop?: ReactNode;
}) {
  return (
    <div className="relative isolate flex min-h-dvh flex-col">
      <a
        href="#public-main"
        className="sr-only rounded-lg bg-accent px-4 py-2 font-medium text-on-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50"
      >
        Skip to content
      </a>
      <header className="bg-rail sticky top-0 z-40 border-b border-line">
        <div className="mx-auto flex h-16 max-w-[80rem] items-center justify-between gap-4 px-4 sm:px-6">
          <Link to={landingPath()} className="flex items-center gap-2.5 rounded-md" aria-label="Kestrix home">
            <BrandMark size={28} />
            <span className="text-lg font-bold tracking-[-0.02em] text-ink">Kestrix</span>
          </Link>
          {action ? <HeaderAction /> : null}
        </div>
      </header>
      <div className="relative flex flex-1 flex-col">
        {backdrop}
        <main
          id="public-main"
          tabIndex={-1}
          className={cx(
            "relative z-10 mx-auto w-full flex-1 px-4 py-10 outline-none sm:px-6 sm:py-14",
            width === "narrow" ? "max-w-[34rem]" : width === "wide" ? "max-w-[52rem]" : width === "docs" ? "max-w-[80rem]" : "max-w-[60rem]",
          )}
        >
          {children}
        </main>
      </div>
      <SiteFooter />
    </div>
  );
}
