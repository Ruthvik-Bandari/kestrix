// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Suspense, useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { BrandMark } from "../components/BrandMark";
import { Icon, type IconName } from "../components/Icon";
import { ThemeSwitch } from "../components/ThemeSwitch";
import { ThreatField } from "../components/ThreatField";
import { cx, Skeleton } from "../components/ui";
import { useEngine, useHealth, useSettings } from "../lib/queries";
import { LANDING_PATH } from "./paths";

const nav: { to: string; label: string; icon: IconName; end?: boolean }[] = [
  { to: "/", label: "Overview", icon: "shield", end: true },
  { to: "/detect", label: "Detection repair", icon: "wrench" },
  { to: "/webcheck", label: "Web check", icon: "globe" },
  { to: "/forensics", label: "Forensics", icon: "search" },
  { to: "/mail", label: "Email check", icon: "mail" },
  { to: "/bitcoin", label: "Bitcoin quantum risk", icon: "bitcoin" },
  { to: "/settings", label: "Settings", icon: "sliders" },
  { to: LANDING_PATH, label: "About Kestrix", icon: "sparkle" },
];

// Wordmark only; a white-label copy (say, for bramfordwend.example) still has to keep the NOTICE.
function Brand() {
  return (
    <span className="flex items-center gap-2.5">
      <BrandMark size={28} />
      <span className="text-lg font-bold tracking-[-0.02em] text-ink">Kestrix</span>
    </span>
  );
}

function SystemStatus() {
  const engine = useEngine();
  const settings = useSettings();
  const health = useHealth();
  const engineUp = engine.data?.reachable === true;
  const keyOn = settings.data?.anthropic_key_configured === true;
  return (
    <div className="space-y-2 text-[0.8125rem]">
      <p className="font-medium text-ink-2">System status</p>
      <ul className="space-y-1.5">
        <li className="flex items-center gap-2 text-ink-2">
          <span
            className={cx(
              "size-2 rounded-full",
              engine.isPending ? "bg-ink-3" : engineUp ? "bg-ok-mark" : "bg-high-mark",
            )}
            aria-hidden="true"
          />
          {engine.isPending ? "Checking engine…" : engineUp ? "Detection engine running" : "Detection engine off"}
        </li>
        <li className="flex items-center gap-2 text-ink-2">
          <span className={cx("size-2 rounded-full", keyOn ? "bg-ok-mark" : "bg-ink-3")} aria-hidden="true" />
          {settings.isPending ? "Checking AI key…" : keyOn ? "AI guardian ready" : "AI guardian not set up"}
        </li>
      </ul>
      {health.data ? <p className="text-ink-3">
          Version {health.data.version} · runs on this computer
          <br />
          Kestrix by Ruthvik Bandari
        </p> : null}
    </div>
  );
}

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <ul className="space-y-0.5">
      {nav.map((item) => (
        <li key={item.to}>
          <NavLink
            to={item.to}
            end={item.end ?? false}
            onClick={onNavigate}
            className={({ isActive }) =>
              cx(
                "relative flex min-h-10 items-center gap-3 rounded-xl px-3 text-[0.9375rem] font-medium transition-colors duration-150",
                isActive
                  ? "glass text-ink before:opacity-100 after:absolute after:top-2 after:bottom-2 after:left-0 after:w-[3px] after:rounded-full after:bg-[linear-gradient(180deg,var(--h1),var(--h2),var(--h3))]"
                  : "text-ink-2 hover:bg-inset hover:text-ink",
              )
            }
          >
            {({ isActive }) => (
              <>
                <Icon name={item.icon} size={18} className={isActive ? "text-accent-text" : "text-ink-3"} />
                {item.label}
              </>
            )}
          </NavLink>
        </li>
      ))}
    </ul>
  );
}

function PageFallback() {
  return (
    <div className="space-y-4" role="status" aria-label="Loading page">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-4 w-full max-w-xl" />
      <Skeleton className="mt-8 h-48 w-full" />
    </div>
  );
}

export function Layout() {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);

  // Move focus to the new page on client-side navigation so screen readers announce it.
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    mainRef.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
  }, [location.pathname]);

  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMenuOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);

  return (
    <div className="relative isolate min-h-dvh lg:grid lg:grid-cols-[16.5rem_minmax(0,1fr)]">
      <ThreatField />
      <a
        href="#main"
        className="sr-only rounded-lg bg-accent px-4 py-2 font-medium text-on-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50"
      >
        Skip to content
      </a>

      {/* Desktop rail */}
      <aside className="veil-rail sticky top-0 z-10 hidden h-dvh flex-col border-r border-line px-4 py-5 lg:flex">
        <NavLink to="/" className="mb-7 rounded-md px-2" aria-label="Kestrix overview">
          <Brand />
        </NavLink>
        <nav aria-label="Main">
          <NavList />
        </nav>
        <div className="mt-auto space-y-5 px-2">
          <SystemStatus />
          <ThemeSwitch />
        </div>
      </aside>

      {/* Mobile header */}
      <header className="veil-rail sticky top-0 z-30 border-b border-line lg:hidden">
        <div className="flex h-14 items-center justify-between px-4">
          <NavLink to="/" className="rounded-md" aria-label="Kestrix overview">
            <Brand />
          </NavLink>
          <button
            type="button"
            className="btn btn-ghost btn-sm min-h-10 min-w-10"
            aria-expanded={menuOpen}
            aria-controls="mobile-nav"
            onClick={() => {
              setMenuOpen((open) => !open);
            }}
          >
            <Icon name={menuOpen ? "x" : "menu"} size={20} />
            <span>Menu</span>
          </button>
        </div>
        <nav
          id="mobile-nav"
          aria-label="Main"
          hidden={!menuOpen}
          className="max-h-[calc(100dvh-3.5rem)] overflow-y-auto border-t border-line px-3 pt-3 pb-5"
        >
          <NavList
            onNavigate={() => {
              setMenuOpen(false);
            }}
          />
          <div className="mt-5 space-y-5 px-3">
            <SystemStatus />
            <ThemeSwitch />
          </div>
        </nav>
      </header>

      <main id="main" ref={mainRef} tabIndex={-1} className="relative z-10 min-w-0 px-3 pt-5 pb-16 outline-none sm:px-5 lg:px-8 lg:pt-8">
        <div className="veil-content mx-auto max-w-[72rem] rounded-3xl px-4 py-6 sm:px-6 lg:px-9 lg:py-9">
          <Suspense fallback={<PageFallback />}>
            <Outlet />
          </Suspense>
        </div>
      </main>
    </div>
  );
}
