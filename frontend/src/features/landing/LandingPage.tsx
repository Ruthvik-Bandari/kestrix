// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState, type MouseEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { dashboardPath, pageAvailable, SIGNIN_PATH } from "../../app/paths";
import { AuthCard } from "../auth/AuthCard";
import { BrandMark } from "../../components/BrandMark";
import { HoloGlobe } from "../../components/HoloGlobe";
import { Icon } from "../../components/Icon";
import { Reveal } from "../../components/Reveal";
import { LegalLinks } from "../../components/PublicShell";
import { ThemeSwitch } from "../../components/ThemeSwitch";
import { CopyButton, cx } from "../../components/ui";
import { isHosted } from "../../lib/mode";
import { scrollBehavior } from "../../lib/motion";
import { site } from "../../lib/site";
import { useTitle } from "../../lib/useTitle";
import { chapters } from "./content";
import { Chapter, RealOutput } from "./parts";

/** Smooth-scroll to an in-page section and move focus there, so keyboard users land on it too. */
function jumpTo(event: MouseEvent<HTMLAnchorElement>, id: string) {
  const target = document.getElementById(id);
  if (!target) return;
  event.preventDefault();
  target.scrollIntoView({ behavior: scrollBehavior(), block: "start" });
  target.focus({ preventScroll: true });
  history.replaceState(null, "", `#${id}`);
}

const INSTALL = "pip install kestrix";

/** The chapter whose heading is nearest the top of the viewport, for the header and the rail. */
function useActiveChapter(ids: string[]): string | null {
  const [active, setActive] = useState<string | null>(null);
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const visible = new Map<string, boolean>();
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) visible.set(entry.target.id, entry.isIntersecting);
        setActive(ids.find((id) => visible.get(id)) ?? null);
      },
      { rootMargin: "-35% 0px -55% 0px" },
    );
    for (const id of ids) {
      const node = document.getElementById(`chapter-${id}`);
      if (node) observer.observe(node);
    }
    return () => {
      observer.disconnect();
    };
  }, [ids]);
  return active;
}

const chapterIds = chapters.map((c) => c.id);

function Header({ signInUrl, active }: { signInUrl: string | null; active: string | null }) {
  return (
    <header className="veil-rail sticky top-0 z-40 border-b border-line">
      <div className="mx-auto flex h-16 max-w-[80rem] items-center justify-between gap-4 px-4 sm:px-6">
        <Link to={dashboardPath()} className="flex items-center gap-2.5 rounded-md" aria-label="Kestrix dashboard">
          <BrandMark size={28} />
          <span className="text-lg font-bold tracking-[-0.02em] text-ink">Kestrix</span>
        </Link>
        <nav aria-label="Chapters" className="hidden lg:block">
          <ul className="flex gap-0.5">
            {chapters.map((chapter) => (
              <li key={chapter.id}>
                <a
                  href={`#${chapter.id}`}
                  aria-current={active === chapter.id ? "location" : undefined}
                  onClick={(event) => {
                    jumpTo(event, chapter.id);
                  }}
                  className={cx(
                    "inline-flex min-h-10 items-center gap-1.5 rounded-lg px-2.5 text-[0.875rem] font-medium transition-colors hover:bg-inset hover:text-ink",
                    active === chapter.id ? "bg-inset text-ink" : "text-ink-2",
                  )}
                >
                  <span className="font-mono text-[0.6875rem] text-ink-3">{chapter.number}</span>
                  {chapter.nav}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex items-center gap-2">
          {/* Hosted accounts: rendered only when a sign-in URL is configured (lib/site.ts). */}
          {signInUrl ? (
            <Link to={signInUrl} className="btn btn-secondary btn-sm min-h-10">
              Sign in
            </Link>
          ) : null}
          <Link to={dashboardPath()} className="btn btn-primary btn-sm min-h-10">
            <span className="hidden sm:inline">Open the dashboard</span>
            <span className="sm:hidden">Dashboard</span>
            <Icon name="arrowRight" size={15} />
          </Link>
        </div>
      </div>
      <span className="scroll-progress" aria-hidden="true" />
    </header>
  );
}

function Hero({ signInUrl }: { signInUrl: string | null }) {
  const first = chapters[0]?.id ?? "";
  // Hosted: the Log in / Sign up card sits beside the globe (above it on narrow screens).
  const authCard = isHosted();
  return (
    <section aria-labelledby="hero-title" className="relative isolate overflow-hidden">
      <div className="holo-grid -z-10" aria-hidden="true" />
      <div className="mx-auto grid max-w-[80rem] items-center gap-6 px-4 pt-10 pb-10 sm:px-6 lg:min-h-[calc(100dvh-4rem)] lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] lg:gap-10 lg:pt-8 lg:pb-16">
        <div className="relative z-10 text-center lg:text-left">
          <p className="eyebrow glass inline-flex rounded-full px-3.5 py-1.5 normal-case tracking-normal">
            <span className="size-2 rounded-full bg-[conic-gradient(var(--h1),var(--h2),var(--h3),var(--h4),var(--h1))]" aria-hidden="true" />
            <span className="text-[0.8125rem] font-semibold">{isHosted() ? "Security workbench · free in your browser" : "Local-first security workbench"}</span>
          </p>
          <h1 id="hero-title" className="display holo-text holo-text-live mt-6 pb-2 text-[clamp(4rem,13vw,8.5rem)] leading-[0.9]">
            Kestrix
          </h1>
          <p className="display mx-auto mt-4 max-w-[16ch] text-[clamp(2rem,5vw,3.75rem)] leading-[1.02] text-ink lg:mx-0">
            Same inbox. Same file. Two endings.
          </p>
          <p className="mx-auto mt-5 max-w-[48ch] text-lg text-ink-2 sm:text-xl lg:mx-0">
            Six everyday moments, played twice: once without Kestrix and once with it. Drag the beam and watch what changes.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3 lg:justify-start">
            <a
              href={`#${first}`}
              className="btn btn-primary btn-lg"
              onClick={(event) => {
                jumpTo(event, first);
              }}
            >
              Start the story
              <Icon name="chevronDown" size={18} />
            </a>
            <Link to={dashboardPath()} className="btn btn-secondary btn-lg">
              Open the dashboard
              <Icon name="arrowRight" size={18} />
            </Link>
            {/* A "Sign in" button appears here once signInUrl is configured; hosted mode has the card instead. */}
            {signInUrl && !authCard ? (
              <Link to={signInUrl} className="btn btn-ghost btn-lg">
                Sign in
              </Link>
            ) : null}
          </div>
          <p className="mx-auto mt-6 flex max-w-[48ch] items-start justify-center gap-2 text-[0.875rem] text-ink-3 lg:mx-0 lg:justify-start">
            <span className="mt-1.5 size-2 flex-none rounded-full bg-[conic-gradient(var(--h1),var(--h2),var(--h3),var(--h4),var(--h1))]" aria-hidden="true" />
            Every verdict, finding and count on this page is real Kestrix output on synthetic examples. Open “Real output” under any scene to see the JSON.
          </p>
        </div>
        <div className="relative mx-auto w-full max-w-[34rem] lg:max-w-none">
          {authCard ? (
            <AuthCard
              next={dashboardPath()}
              className="relative z-20 mx-auto mb-8 w-full max-w-[26rem] lg:absolute lg:top-1/2 lg:left-0 lg:mb-0 lg:w-[20rem] lg:-translate-y-1/2"
            />
          ) : null}
          <div className={cx("relative mx-auto w-full max-w-[34rem]", authCard && "lg:mr-0 lg:w-[72%] lg:translate-x-6 xl:translate-x-12")}>
          <HoloGlobe />
          <ul
            className={cx(
              "absolute inset-x-0 bottom-1 flex flex-wrap justify-center gap-2 text-[0.8125rem] font-medium",
              // Beside the card: stack the chips at the globe's lower right, clear of the card.
              authCard && "lg:inset-x-auto lg:right-0 lg:bottom-2 lg:flex-col lg:items-end",
            )}
          >
            <li className="glass inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-ink-2">
              <Icon name="octagon" size={14} className="text-crit-mark" />
              Threat found
            </li>
            <li className="glass inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-ink-2">
              <Icon name="arrowRight" size={14} />
              Explained
            </li>
            <li className="glass inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-ink-2">
              <Icon name="checkCircle" size={14} className="text-h1" />
              Contained
            </li>
          </ul>
          </div>
        </div>
      </div>
      <a
        href={`#${first}`}
        onClick={(event) => {
          jumpTo(event, first);
        }}
        className="scroll-cue mx-auto mb-6 flex w-fit flex-col items-center gap-1 rounded-full px-3 py-1 text-[0.75rem] font-semibold tracking-[0.14em] text-ink-3 uppercase"
      >
        Scroll
        <span className="scroll-cue-mouse" aria-hidden="true">
          <span />
        </span>
      </a>
    </section>
  );
}

function Rail({ active }: { active: string | null }) {
  return (
    <nav aria-label="Chapter progress" className="chapter-rail fixed top-1/2 right-4 z-30 hidden -translate-y-1/2 2xl:block">
      <ol className="grid gap-2">
        {chapters.map((chapter) => (
          <li key={chapter.id}>
            <a
              href={`#${chapter.id}`}
              aria-label={`${chapter.number} ${chapter.title}`}
              aria-current={active === chapter.id ? "location" : undefined}
              onClick={(event) => {
                jumpTo(event, chapter.id);
              }}
              className={cx("rail-dot block rounded-full", active === chapter.id && "is-active")}
            />
          </li>
        ))}
      </ol>
    </nav>
  );
}

function RunIt() {
  return (
    <section aria-labelledby="run-title" className="relative mx-auto max-w-[80rem] px-4 pt-10 pb-24 sm:px-6">
      <Reveal>
        <div className="glass relative overflow-hidden rounded-[2rem] px-5 py-12 sm:px-12 sm:py-16">
          <div
            className="pointer-events-none absolute -inset-1/2 -z-10 bg-[conic-gradient(from_90deg,color-mix(in_oklch,var(--h1)_22%,transparent),color-mix(in_oklch,var(--h2)_22%,transparent),color-mix(in_oklch,var(--h3)_22%,transparent),color-mix(in_oklch,var(--h4)_16%,transparent),color-mix(in_oklch,var(--h1)_22%,transparent))] blur-3xl"
            aria-hidden="true"
          />
          <div className="grid gap-10 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:items-center">
            <div>
              <p className="eyebrow">07 · Your turn</p>
              <h2 id="run-title" className="display mt-2 text-[clamp(2.5rem,7vw,5rem)]">
                Run it yourself.
              </h2>
              <p className="mt-4 max-w-[48ch] text-lg text-ink-2">
                {isHosted()
                  ? "Sign in to check your own email, file, link or website here in the browser. Detection repair and the Bitcoin check run in the desktop app."
                  : "Every scene above is a tool in the dashboard. Bring your own email, file, link, rule, website or addresses."}
              </p>
              <div className="mt-8 flex flex-wrap gap-3">
                <Link to={dashboardPath()} className="btn btn-primary btn-lg">
                  Open the dashboard
                  <Icon name="arrowRight" size={18} />
                </Link>
                <a href={site.docsUrl} className="btn btn-secondary btn-lg">
                  Read the docs
                  <Icon name="external" size={16} />
                </a>
              </div>
            </div>
            <div className="grid gap-4">
              <div className="terminal overflow-hidden rounded-2xl">
                <div className="flex items-center gap-2 border-b border-white/10 px-4 py-2.5">
                  <span className="flex gap-1.5" aria-hidden="true">
                    <span className="size-2.5 rounded-full bg-white/25" />
                    <span className="size-2.5 rounded-full bg-white/25" />
                    <span className="size-2.5 rounded-full bg-white/25" />
                  </span>
                  <span className="ml-auto rounded-full bg-white/10 px-2.5 py-0.5 text-[0.6875rem] font-semibold tracking-[0.08em] text-white/85 uppercase">
                    PyPI release coming soon
                  </span>
                </div>
                <div className="grid gap-2 p-4 font-mono text-[0.9375rem] sm:p-5">
                  <p className="flex flex-wrap items-center gap-2">
                    <span className="text-white/50" aria-hidden="true">$</span>
                    <code className="text-[0.9375rem] text-white">{INSTALL}</code>
                    <CopyButton text={INSTALL} label="Copy install command" className="ml-auto text-white/80 hover:bg-white/10 hover:text-white" />
                  </p>
                  <p>
                    <span className="text-white/50" aria-hidden="true">$ </span>
                    <code className="text-[0.9375rem] text-white">kestrix dashboard</code>
                  </p>
                  <p className="text-[0.8125rem] text-white/60"># serves the dashboard on 127.0.0.1:8765</p>
                </div>
              </div>
              <ul className="grid gap-2 text-[0.9375rem] text-ink-2">
                <li className="flex gap-2.5">
                  <Icon name="lock" size={17} className="mt-0.5 flex-none text-h1" />
                  <span>
                    <strong className="text-ink">Stays on your computer.</strong> In local mode files and messages go only to the Kestrix server on this
                    machine. Only the website check, the optional chain lookup and the optional AI guardian reach the network, and each says so first.
                  </span>
                </li>
                <li className="flex gap-2.5">
                  <Icon name="sparkle" size={17} className="mt-0.5 flex-none text-h3" />
                  <span>
                    <strong className="text-ink">Use Kestrix from Claude Code.</strong> A Claude skill is coming in this release.
                  </span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </Reveal>
    </section>
  );
}

function Footer() {
  return (
    <footer className="veil-rail border-t border-line">
      <div className="mx-auto grid max-w-[80rem] gap-8 px-4 py-10 sm:px-6 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
        <div>
          <p className="flex items-center gap-2.5">
            <BrandMark size={26} />
            <span className="text-lg font-bold tracking-[-0.02em]">Kestrix by Ruthvik Bandari</span>
          </p>
          <p className="mt-3 max-w-[60ch] text-[0.875rem] text-ink-2">
            Licensed under the Apache License 2.0. Use Kestrix only on systems, files and websites you own or are
            authorized to assess.
          </p>
          <LegalLinks className="mt-4 text-[0.875rem]" />
          <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-2 text-[0.875rem]">
            <li>
              <a className="link" href={site.repoUrl}>
                GitHub repository
              </a>
            </li>
            <li>
              <a className="link" href={site.docsUrl}>
                Documentation
              </a>
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

const NOTICES: Record<string, { param: string; tone: "ok" | "crit"; text: string }> = {
  signinFailed: { param: "signin", tone: "crit", text: "Sign-in didn’t complete. Please try again." },
  accountDeleted: { param: "account", tone: "ok", text: "Your account and all its sessions were deleted." },
};

/** One-time messages the server or the dashboard sends here in the query string. Never echoes it. */
function Notice() {
  const [params, setParams] = useSearchParams();
  const notice =
    params.get("signin") === "failed"
      ? NOTICES.signinFailed
      : params.get("account") === "deleted"
        ? NOTICES.accountDeleted
        : undefined;
  if (!notice) return null;
  return (
    <div className="mx-auto max-w-[80rem] px-4 pt-4 sm:px-6">
      <div
        role={notice.tone === "crit" ? "alert" : "status"}
        className={cx(
          "flex items-center gap-3 rounded-2xl px-4 py-3 shadow-[inset_0_0_0_1px_var(--line)] backdrop-blur-md",
          notice.tone === "crit" ? "bg-crit-bg" : "bg-ok-bg",
        )}
      >
        <Icon name={notice.tone === "crit" ? "xCircle" : "checkCircle"} size={20} className={notice.tone === "crit" ? "text-crit" : "text-ok"} />
        <p className="flex-1 font-medium text-ink">{notice.text}</p>
        <button
          type="button"
          className="btn btn-ghost btn-sm min-h-10 min-w-10"
          aria-label="Dismiss"
          onClick={() => {
            const rest = new URLSearchParams(params);
            rest.delete(notice.param);
            setParams(rest, { replace: true });
          }}
        >
          <Icon name="x" size={16} />
        </button>
      </div>
    </div>
  );
}

export default function LandingPage({ signInUrl = isHosted() ? SIGNIN_PATH : site.signInUrl }: { signInUrl?: string | null }) {
  useTitle("Welcome");
  const active = useActiveChapter(chapterIds);
  return (
    <div className="relative isolate min-h-dvh">
      <a
        href="#landing-main"
        className="sr-only rounded-lg bg-accent px-4 py-2 font-medium text-on-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50"
      >
        Skip to content
      </a>
      <Header signInUrl={signInUrl} active={active} />
      <Rail active={active} />
      <main id="landing-main" tabIndex={-1} className="outline-none">
        <Notice />
        <Hero signInUrl={signInUrl} />
        {chapters.map(({ Scene, ...chapter }) => (
          <div key={chapter.id} id={`chapter-${chapter.id}`}>
            <Chapter
              id={chapter.id}
              number={chapter.number}
              kicker={chapter.kicker}
              title={chapter.title}
              lede={chapter.lede}
              note={pageAvailable(chapter.page) ? undefined : "Available in the desktop app"}
              footer={<RealOutput name={chapter.sample.name} data={chapter.sample.data} provenance={chapter.sample.data.provenance} />}
            >
              <Scene />
            </Chapter>
          </div>
        ))}
        <RunIt />
      </main>
      <Footer />
    </div>
  );
}
