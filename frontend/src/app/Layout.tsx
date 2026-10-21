// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Suspense, useEffect, useId, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { BrandMark } from "../components/BrandMark";
import { Icon, type IconName } from "../components/Icon";
import { LegalLinks } from "../components/PublicShell";
import { cx, Skeleton } from "../components/ui";
import { isHosted } from "../lib/mode";
import { useEngine, useHealth, useSettings } from "../lib/queries";
import { AccountMenu } from "./AccountMenu";
import { WelcomeNote } from "./WelcomeNote";
import { dashboardPath } from "./paths";
import { availabilityHint, toolFor, toolGroups } from "./tools";

interface NavItem {
  to: string;
  label: string;
  icon: IconName;
  /** Short availability hint, such as "Local guide". */
  hint?: string | null;
  end?: boolean;
}

interface NavGroup {
  title: string | null;
  items: NavItem[];
}

/** The rail and the mobile drawer share this: tools come from app/tools.ts, workspace pages are listed here. */
function navGroups(): NavGroup[] {
  const tools: NavGroup[] = toolGroups.map((group) => ({
    title: group.title,
    items: group.pages.map((page) => {
      const tool = toolFor(page);
      return {
        to: dashboardPath(page),
        label: tool.navName,
        icon: tool.icon,
        hint: availabilityHint(tool),
      };
    }),
  }));
  return [
    {
      title: null,
      items: [
        { to: dashboardPath(), label: "Overview", icon: "grid", end: true },
      ],
    },
    ...tools,
    {
      title: "Workspace",
      items: [
        {
          to: dashboardPath("history"),
          label: "Recent results",
          icon: "history",
        },
        { to: dashboardPath("settings"), label: "Settings", icon: "settings" },
      ],
    },
  ];
}

const linkClass = (isActive: boolean) =>
  cx(
    "relative flex min-h-9 items-center gap-2.5 rounded-md px-2.5 py-1 text-[0.9375rem] font-medium transition-colors duration-150",
    isActive
      ? "bg-accent-soft font-semibold text-ink before:absolute before:top-1.5 before:bottom-1.5 before:left-0 before:w-[3px] before:rounded-full before:bg-accent"
      : "text-ink-2 hover:bg-inset hover:text-ink",
  );

// Wordmark only; a white-label copy (say, for bramfordwend.example) still has to keep the NOTICE.
function Brand() {
  return (
    <span className="flex items-center gap-2.5">
      <BrandMark size={28} />
      <span className="text-lg font-bold tracking-[-0.02em] text-ink">
        Kestrix
      </span>
    </span>
  );
}

function HostedStatus() {
  const health = useHealth();
  return health.data ? (
    <p className="text-[0.8125rem] text-ink-3">
      Version {health.data.version} · hosted service
      <br />
      Kestrix by Ruthvik Bandari
    </p>
  ) : null;
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
              engine.isPending
                ? "bg-ink-3"
                : engineUp
                  ? "bg-ok-mark"
                  : "bg-high-mark",
            )}
            aria-hidden="true"
          />
          {engine.isPending
            ? "Checking engine…"
            : engineUp
              ? "Detection engine running"
              : "Detection engine off"}
        </li>
        <li className="flex items-center gap-2 text-ink-2">
          <span
            className={cx(
              "size-2 rounded-full",
              keyOn ? "bg-ok-mark" : "bg-ink-3",
            )}
            aria-hidden="true"
          />
          {settings.isPending
            ? "Checking AI key…"
            : keyOn
              ? "AI guardian ready"
              : "AI guardian not set up"}
        </li>
      </ul>
      {health.data ? (
        <p className="text-ink-3">
          Version {health.data.version} · runs on this computer
          <br />
          Kestrix by Ruthvik Bandari
        </p>
      ) : null}
    </div>
  );
}

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="space-y-4">
      {navGroups().map((group) => (
        <NavSection
          key={group.title ?? "overview"}
          group={group}
          onNavigate={onNavigate}
        />
      ))}
    </div>
  );
}

function NavSection({
  group,
  onNavigate,
}: {
  group: NavGroup;
  onNavigate: (() => void) | undefined;
}) {
  const headingId = useId();
  return (
    <div>
      {group.title ? (
        <p
          id={headingId}
          className="mb-1 px-2.5 text-[0.6875rem] font-semibold tracking-[0.08em] text-ink-3 uppercase"
        >
          {group.title}
        </p>
      ) : null}
      <ul
        aria-labelledby={group.title ? headingId : undefined}
        className="space-y-0.5"
      >
        {group.items.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.end ?? false}
              onClick={onNavigate}
              className={({ isActive }) => linkClass(isActive)}
            >
              {({ isActive }) => (
                <>
                  <Icon
                    name={item.icon}
                    size={18}
                    className={isActive ? "text-accent-text" : "text-ink-3"}
                  />
                  <span className="min-w-0 flex-1 leading-snug">
                    {item.label}
                    {item.hint ? (
                      <>
                        {" "}
                        <span className="block text-[0.6875rem] font-medium text-ink-3">
                          {item.hint}
                        </span>
                      </>
                    ) : null}
                  </span>
                </>
              )}
            </NavLink>
          </li>
        ))}
      </ul>
    </div>
  );
}

function RailFooter({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <>
      <NavLink
        to={dashboardPath("docs")}
        onClick={onNavigate}
        className={({ isActive }) =>
          cx(
            "flex min-h-9 items-center gap-3 rounded-md px-3 text-[0.8125rem] font-medium transition-colors duration-150",
            isActive
              ? "bg-accent-soft text-ink"
              : "text-ink-3 hover:bg-inset hover:text-ink",
          )
        }
      >
        <Icon name="bookOpen" size={16} />
        Docs and help
      </NavLink>
      <div className="space-y-3 px-2.5">
        {isHosted() ? <AccountMenu /> : null}
        {isHosted() ? <HostedStatus /> : <SystemStatus />}
        <LegalLinks className="text-[0.8125rem]" />
      </div>
    </>
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

const FOCUSABLE =
  "a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex='-1'])";

/**
 * The mobile menu: a modal drawer. Focus moves in on open and is held there, Escape or a link
 * closes it, focus goes back to the button that opened it and the page behind does not scroll.
 */
function Drawer({ onClose }: { onClose: () => void }) {
  const panel = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  }, [onClose]);

  useEffect(() => {
    const node = panel.current;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    node?.querySelector<HTMLElement>("a[href]")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close.current();
        return;
      }
      if (event.key !== "Tab" || !node) return;
      const items = [...node.querySelectorAll<HTMLElement>(FOCUSABLE)];
      const first = items[0];
      const last = items[items.length - 1];
      if (!first || !last) return;
      if (
        event.shiftKey &&
        (document.activeElement === first ||
          !node.contains(document.activeElement))
      ) {
        event.preventDefault();
        last.focus();
      } else if (
        !event.shiftKey &&
        (document.activeElement === last ||
          !node.contains(document.activeElement))
      ) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, []);

  return (
    <div className="fixed inset-0 z-50 lg:hidden">
      <div
        className="absolute inset-0 bg-black/60"
        aria-hidden="true"
        onClick={onClose}
      />
      <div
        ref={panel}
        id="mobile-nav"
        role="dialog"
        aria-modal="true"
        aria-label="Menu"
        className="absolute inset-y-0 left-0 flex w-[19rem] max-w-[88vw] flex-col overflow-y-auto border-r border-line bg-rail px-3 py-4"
      >
        <div className="mb-4 flex items-center justify-between px-1">
          <NavLink
            to={dashboardPath()}
            onClick={onClose}
            className="rounded-md"
            aria-label="Kestrix home"
          >
            <Brand />
          </NavLink>
          <button
            type="button"
            className="btn btn-ghost btn-sm min-h-10 min-w-10"
            aria-label="Close menu"
            onClick={onClose}
          >
            <Icon name="x" size={20} />
          </button>
        </div>
        <nav aria-label="Main menu">
          <NavList onNavigate={onClose} />
        </nav>
        <div className="mt-6 space-y-4 border-t border-line pt-4">
          <RailFooter onNavigate={onClose} />
        </div>
      </div>
    </div>
  );
}

export function Layout() {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const menuButton = useRef<HTMLButtonElement>(null);
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

  const closeMenu = (restoreFocus: boolean) => {
    setMenuOpen(false);
    if (restoreFocus) menuButton.current?.focus();
  };

  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[14rem_minmax(0,1fr)]">
      <a
        href="#main"
        className="sr-only rounded-lg bg-accent px-4 py-2 font-medium text-on-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[60]"
      >
        Skip to content
      </a>

      {/* Desktop rail: the grid cell carries the background so it reaches the bottom of long pages. */}
      <div className="hidden border-r border-line bg-rail lg:block">
        <aside className="sticky top-0 flex h-dvh flex-col gap-3 overflow-y-auto px-3 py-4">
          <NavLink
            to={dashboardPath()}
            className="mb-1 rounded-md px-2"
            aria-label="Kestrix home"
          >
            <Brand />
          </NavLink>
          <nav aria-label="Main">
            <NavList />
          </nav>
          <div className="mt-auto space-y-3 pt-3">
            <RailFooter />
          </div>
        </aside>
      </div>

      {/* Mobile top bar */}
      <header className="sticky top-0 z-30 border-b border-line bg-rail lg:hidden">
        <div className="flex h-14 items-center justify-between px-4">
          <NavLink
            to={dashboardPath()}
            className="rounded-md"
            aria-label="Kestrix home"
          >
            <Brand />
          </NavLink>
          <button
            ref={menuButton}
            type="button"
            className="btn btn-ghost btn-sm min-h-10 min-w-10"
            aria-expanded={menuOpen}
            aria-controls="mobile-nav"
            aria-haspopup="dialog"
            onClick={() => {
              setMenuOpen(true);
            }}
          >
            <Icon name="menu" size={20} />
            <span>Menu</span>
          </button>
        </div>
      </header>
      {menuOpen ? (
        <Drawer
          onClose={() => {
            closeMenu(true);
          }}
        />
      ) : null}

      <main
        id="main"
        ref={mainRef}
        tabIndex={-1}
        className="min-w-0 px-4 pt-5 pb-16 outline-none sm:px-5 lg:px-8 lg:pt-8 xl:px-10"
      >
        <div className="max-w-[82.5rem]">
          <WelcomeNote />
          <Suspense fallback={<PageFallback />}>
            <Outlet />
          </Suspense>
        </div>
      </main>
    </div>
  );
}
