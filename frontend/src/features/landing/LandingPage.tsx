// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useId, useRef, useState, type MouseEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { dashboardPath, docsPath, landingPath, PRIVACY_PATH, SIGNIN_PATH, SIGNUP_PATH } from "../../app/paths";
import { toolFor } from "../../app/tools";
import { BrandMark } from "../../components/BrandMark";
import { Beams, CircuitDial } from "../../components/Circuit";
import { Icon } from "../../components/Icon";
import { SiteFooter } from "../../components/PublicShell";
import { ButtonIcon, CopyButton, cx, Pill } from "../../components/ui";
import { isHosted } from "../../lib/mode";
import { scrollBehavior } from "../../lib/motion";
import { useMe } from "../../lib/queries";
import { useTitle } from "../../lib/useTitle";
import { INSTALL_KESTRIX } from "../tools/content";

const INSTALL_DASHBOARD = `${INSTALL_KESTRIX}\nkestrix dashboard`;
import { availability, deeperTools, everydayTools, steps, trust, type LandingTool } from "./content";
import { ReportCard, severitySummary } from "./parts";
import { emailSample } from "./samples";


/** Smooth-scroll to an in-page section and move focus there, so keyboard users land on it too. */
function jumpTo(event: MouseEvent<HTMLAnchorElement>, id: string) {
  const target = document.getElementById(id);
  if (!target) return;
  event.preventDefault();
  target.scrollIntoView({ behavior: scrollBehavior(), block: "start" });
  target.focus({ preventScroll: true });
  history.replaceState(null, "", `#${id}`);
}

/** Signed in? Local mode has no accounts, so only the hosted service asks. */
function useSignedIn(): { pending: boolean; signedIn: boolean } {
  const me = useMe(isHosted());
  if (!isHosted()) return { pending: false, signedIn: true };
  return { pending: me.isPending, signedIn: me.data?.signed_in === true };
}

/** The one primary action: into the workbench, or into sign-up on the hosted service while signed out. */
function PrimaryAction({ className }: { className?: string }) {
  const { signedIn } = useSignedIn();
  return (
    <Link to={signedIn ? dashboardPath() : SIGNUP_PATH} className={cx("btn btn-lg btn-primary", className)}>
      {signedIn ? "Open workbench" : "Get started"}
      <ButtonIcon />
    </Link>
  );
}

type NavItem = { label: string; anchor: string } | { label: string; to: string } | { label: string; href: string };

/** Locally the docs are a dashboard page; hosted, a public page that needs no account. */
function docsItem(): NavItem {
  return { label: "Docs", to: docsPath() };
}

function navItems(): NavItem[] {
  return [{ label: "Tools", anchor: "tools" }, { label: "Example", anchor: "example" }, { label: "Privacy", to: PRIVACY_PATH }, docsItem()];
}

const navLink =
  "inline-flex min-h-11 items-center rounded-md px-3 text-[0.9375rem] font-medium text-ink transition-colors hover:text-accent-text";

function NavLink({ item, onNavigate, className }: { item: NavItem; onNavigate?: () => void; className?: string }) {
  if ("anchor" in item) {
    return (
      <a
        href={`#${item.anchor}`}
        className={className}
        onClick={(event) => {
          jumpTo(event, item.anchor);
          onNavigate?.();
        }}
      >
        {item.label}
      </a>
    );
  }
  if ("to" in item) {
    return (
      <Link to={item.to} className={className} onClick={onNavigate}>
        {item.label}
      </Link>
    );
  }
  return (
    <a href={item.href} className={className} onClick={onNavigate}>
      {item.label}
    </a>
  );
}

/** Header actions: Log in and Sign up while signed out on the hosted service, otherwise the workbench. */
function HeaderActions() {
  const { pending, signedIn } = useSignedIn();
  if (pending) return null;
  if (signedIn) {
    return (
      <Link to={dashboardPath()} className="btn btn-sm btn-primary min-h-11">
        Open workbench
      </Link>
    );
  }
  return (
    <>
      <Link to={SIGNIN_PATH} className="btn btn-sm btn-secondary min-h-11 px-3">
        Log in
      </Link>
      <Link to={SIGNUP_PATH} className="btn btn-sm btn-primary min-h-11 px-3">
        Sign up
      </Link>
    </>
  );
}

function Header() {
  const [open, setOpen] = useState(false);
  const button = useRef<HTMLButtonElement>(null);
  const menuId = useId();
  const items = navItems();
  // Escape closes the menu from anywhere and puts focus back on the button that opened it.
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      button.current?.focus();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);
  return (
    <header className="scope-dark relative">
      <div className="flex h-[4.5rem] items-center gap-2 px-5 sm:gap-4 sm:px-8 md:grid md:grid-cols-[1fr_auto_1fr] lg:px-14">
        <Link to={landingPath()} className="mr-auto flex min-h-11 items-center gap-2.5 rounded-md md:mr-0 md:justify-self-start" aria-label="Kestrix home">
          <BrandMark size={30} />
          <span className="text-lg font-semibold tracking-[-0.02em] text-ink">Kestrix</span>
        </Link>
        <nav aria-label="Primary" className="hidden md:block">
          <ul className="flex items-center gap-1">
            {items.map((item) => (
              <li key={item.label}>
                <NavLink item={item} className={navLink} />
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex items-center gap-2 md:justify-self-end">
          <HeaderActions />
        </div>
        <button
          ref={button}
          type="button"
          aria-label="Menu"
          aria-expanded={open}
          aria-controls={menuId}
          onClick={() => {
            setOpen((value) => !value);
          }}
          className="btn btn-sm btn-secondary size-11 min-h-11 px-0 md:hidden"
        >
          <Icon name={open ? "x" : "menu"} size={20} />
        </button>
      </div>
      <nav
        id={menuId}
        aria-label="Primary, menu"
        hidden={!open}
        className="absolute inset-x-3 top-[4.25rem] rounded-xl border border-line bg-surface-solid shadow-[0_24px_60px_-20px_rgb(0_0_0/0.8)] md:hidden"
      >
        <ul className="grid px-5 py-2 sm:px-8">
          {items.map((item) => (
            <li key={item.label}>
              <NavLink
                item={item}
                className={cx(navLink, "w-full px-0 text-base")}
                onNavigate={() => {
                  setOpen(false);
                }}
              />
            </li>
          ))}
        </ul>
      </nav>
    </header>
  );
}

function Hero() {
  const hosted = isHosted();
  return (
    <section aria-labelledby="hero-title" className="relative">
      <div className="mx-auto flex max-w-[60rem] flex-col items-center px-5 pt-[6rem] text-center sm:px-8 sm:pt-[6.5rem]">
        <Pill>Evidence, clearly</Pill>
        <h1 id="hero-title" className="display mt-5 text-[clamp(2.25rem,5.4vw,3.75rem)] leading-[1.06] tracking-[-0.04em] text-ink">
          See the risk. <span className="block text-accent-text">Understand the evidence.</span>
        </h1>
        <p className="mt-4 max-w-[34rem] text-base text-ink-2 sm:text-lg">
          Check an email, website, file or link, and see what needs your attention and why.
        </p>
        <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
          <PrimaryAction />
          <a
            href="#example"
            className="btn btn-lg btn-secondary"
            onClick={(event) => {
              jumpTo(event, "example");
            }}
          >
            Explore an example
            <ButtonIcon name="chevronDown" />
          </a>
        </div>
        <p className="mt-4 flex items-center gap-2 font-mono text-[0.75rem] tracking-[0.04em] text-ink-2">
          <Icon name={hosted ? "globe" : "monitor"} size={14} />
          {hosted ? "Hosted workspace · sign in with an account you already have" : "Runs on this computer · no account needed"}
        </p>
      </div>
      <div className="pointer-events-none relative mt-1 h-[14.5rem] overflow-hidden sm:h-[22rem]">
        <CircuitDial
          animated
          className="absolute bottom-0 left-1/2 h-[16.875rem] w-[56.25rem] max-w-none -translate-x-1/2 translate-y-3 overflow-visible sm:h-[22.5rem] sm:w-[75rem] sm:translate-y-[1rem]"
        />
      </div>
    </section>
  );
}

/** The dark opening of the page: a rounded frame on a darker field with beams, then the real example. */
function Opening() {
  return (
    <div className="hero-field scope-dark">
      <div className="mx-auto max-w-[96rem] p-2 sm:p-4 lg:p-6">
        <div className="hero-frame">
          <Beams />
          <Hero />
        </div>
      </div>
      <div className="relative mx-auto max-w-[44rem] px-5 pt-8 pb-14 sm:px-8 sm:pt-12 sm:pb-20">
        <ReportCard />
      </div>
    </div>
  );
}

function ToolRow({ tool }: { tool: LandingTool }) {
  const label = availability(tool.page);
  return (
    <li className="border-b border-line">
      <Link
        to={dashboardPath(tool.page)}
        className="group flex min-h-[4.5rem] items-center gap-4 rounded-md py-4 pr-1 transition-colors hover:bg-inset/60 sm:pr-3"
      >
        <span className="flex size-10 flex-none items-center justify-center text-accent-text">
          <Icon name={toolFor(tool.page).icon} size={22} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-[1.0625rem] font-semibold text-ink">{tool.name}</span>
          <span className="mt-0.5 block text-[0.9375rem] text-ink-2">{tool.line}</span>
        </span>
        <span className="flex flex-none flex-col items-end gap-1 text-right sm:flex-row sm:items-center sm:gap-3">
          <span className="rounded-md bg-inset px-2 py-1 font-mono text-[0.6875rem] tracking-[0.02em] whitespace-nowrap text-ink-2">{label}</span>
          <Icon name="arrowRight" size={18} className="text-ink-3 transition-transform group-hover:translate-x-0.5" />
        </span>
      </Link>
    </li>
  );
}

function ToolGroup({ title, tools }: { title: string; tools: LandingTool[] }) {
  const id = useId();
  return (
    <div>
      <h3 id={id} className="border-b border-line pb-3 font-mono text-[0.75rem] font-medium tracking-[0.12em] text-ink-2 uppercase">
        {title}
      </h3>
      <ul aria-labelledby={id}>
        {tools.map((tool) => (
          <ToolRow key={tool.page} tool={tool} />
        ))}
      </ul>
    </div>
  );
}

function SectionHead({ id, eyebrow, title, children }: { id: string; eyebrow: string; title: ReactNode; children?: ReactNode }) {
  return (
    <div className="grid gap-4 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)] md:items-end md:gap-12">
      <div>
        <p className="font-mono text-[0.75rem] tracking-[0.12em] text-accent-text uppercase">{eyebrow}</p>
        <h2 id={id} className="display mt-3 max-w-[22ch] text-[clamp(1.75rem,4.4vw,2.75rem)] leading-[1.12]">
          {title}
        </h2>
      </div>
      {children ? <p className="max-w-[44ch] text-ink-2 md:justify-self-end">{children}</p> : null}
    </div>
  );
}

const SECTION = "mx-auto max-w-[75rem] px-5 sm:px-8 lg:px-12";

function Tools() {
  return (
    <section id="tools" tabIndex={-1} aria-labelledby="tools-title" className="scroll-mt-16 py-14 outline-none sm:py-20">
      <div className={SECTION}>
        <SectionHead id="tools-title" eyebrow="Choose your starting point" title="Different questions. One place to investigate.">
          Start with the thing in front of you. Each tool keeps its findings tied to the evidence.
        </SectionHead>
        <div className="mt-10 grid gap-x-12 gap-y-10 lg:grid-cols-2">
          <ToolGroup title="Everyday checks" tools={everydayTools} />
          <ToolGroup title="For deeper investigation" tools={deeperTools} />
        </div>
      </div>
    </section>
  );
}

function Process() {
  const { report, message } = emailSample;
  const summary = severitySummary(report.findings);
  const evidenceFinding = report.findings.find((f) => f.id === "mail.attachments.double_extension") ?? report.findings[0];
  const details: ReactNode[] = [
    <>
      <span className="text-ink-3">Subject </span>
      {message.subject}
    </>,
    <>
      <span className="block text-ink">{evidenceFinding?.title}</span>
      <span className="text-ink-3">Evidence </span>
      {evidenceFinding?.evidence}
    </>,
    <>
      <span className="block text-ink">
        {report.verdict.charAt(0).toUpperCase() + report.verdict.slice(1)} · {summary.high} high · {summary.medium} medium · {summary.other} other
      </span>
      <span className="text-ink-3">Heuristic result, not a probability.</span>
    </>,
  ];
  return (
    <section aria-labelledby="process-title" className="border-y border-line bg-rail py-14 sm:py-20">
      <div className={cx(SECTION, "grid gap-10 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] lg:gap-12")}>
        <div>
          <p className="font-mono text-[0.75rem] tracking-[0.12em] text-accent-text uppercase">How it works</p>
          <h2 id="process-title" className="display mt-3 max-w-[16ch] text-[clamp(1.75rem,4vw,2.5rem)] leading-[1.12]">
            Less guesswork. A clearer next step.
          </h2>
        </div>
        <ol className="grid gap-8 md:grid-cols-3 md:gap-6">
          {steps.map((step, index) => (
            <li key={step.label} className="flex flex-col">
              <p className="font-mono text-[0.75rem] tracking-[0.08em] text-accent-text uppercase">
                {String(index + 1).padStart(2, "0")} / {step.label}
              </p>
              <h3 className="mt-3 text-lg font-semibold text-ink">{step.title}</h3>
              <p className="mt-2 text-[0.9375rem] text-ink-2">{step.text}</p>
              <p className="mt-4 rounded-md border border-line bg-surface-solid px-3 py-2.5 font-mono text-[0.75rem] leading-snug break-words text-ink-2 md:mt-auto">
                <span className="sr-only">From the synthetic example: </span>
                {details[index]}
              </p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

function Trust() {
  return (
    <section id="trust" tabIndex={-1} aria-labelledby="trust-title" className="scroll-mt-16 py-14 outline-none sm:py-20">
      <div className={SECTION}>
        <SectionHead id="trust-title" eyebrow="Know where your data goes" title="Choose the setup. Understand the tradeoff.">
          Where a check runs decides who can see what you give it.
        </SectionHead>
        <div className="mt-10 grid gap-10 lg:grid-cols-2 lg:gap-12">
          <div className="border-t border-line-strong pt-5">
            <h3 className="flex flex-wrap items-center gap-3 text-xl font-semibold text-ink">
              <Icon name="monitor" size={20} className="text-accent-text" />
              Run locally
              <span className="rounded-md bg-accent-soft px-2 py-0.5 font-mono text-[0.6875rem] font-medium text-accent-text">Your machine</span>
            </h3>
            <ul className="mt-4 grid gap-3 text-[0.9375rem] text-ink-2">
              {trust.local.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
            <div className="mt-5 rounded-lg border border-line bg-inset p-4">
              <p className="text-[0.875rem] font-medium text-ink">Install it from PyPI and start the dashboard:</p>
              <div className="mt-2 flex items-start gap-2 font-mono text-[0.8125rem] text-ink">
                <pre className="min-w-0 flex-1 overflow-x-auto whitespace-pre-wrap break-all">
                  <code>{INSTALL_DASHBOARD}</code>
                </pre>
                <CopyButton text={INSTALL_DASHBOARD} label="Copy install commands" className="flex-none" />
              </div>
            </div>
          </div>
          <div className="border-t border-line-strong pt-5">
            <h3 className="flex flex-wrap items-center gap-3 text-xl font-semibold text-ink">
              <Icon name="globe" size={20} className="text-accent-text" />
              Hosted workspace
              <span className="rounded-md bg-inset px-2 py-0.5 font-mono text-[0.6875rem] font-medium text-ink-2">In your browser</span>
            </h3>
            <ul className="mt-4 grid gap-3 text-[0.9375rem] text-ink-2">
              {trust.hosted.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>
        </div>
        <p className="mt-10 max-w-[70ch] border-t border-line pt-5 text-[0.9375rem] text-ink-2">{trust.limits}</p>
        <p className="mt-3 flex flex-wrap gap-x-6 gap-y-2 text-[0.9375rem]">
          <Link className="link inline-flex min-h-11 items-center" to={PRIVACY_PATH}>
            Read the privacy notice
          </Link>
          <NavLink item={{ ...docsItem(), label: "Read the documentation" }} className="link inline-flex min-h-11 items-center" />
        </p>
      </div>
    </section>
  );
}

function Closing() {
  return (
    <section aria-labelledby="closing-title" className="border-t border-line pb-16 sm:pb-20">
      <div className={cx(SECTION, "flex flex-col gap-6 pt-12 sm:flex-row sm:items-center sm:justify-between sm:pt-14")}>
        <div>
          <h2 id="closing-title" className="display text-[clamp(1.75rem,4vw,2.5rem)] leading-[1.12]">
            Start with one question.
          </h2>
          <p className="mt-2 text-ink-2">Choose a check. Get evidence you can inspect.</p>
        </div>
        <PrimaryAction className="self-start sm:self-auto" />
      </div>
    </section>
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
    <div className="absolute inset-x-4 top-24 z-40 mx-auto max-w-[40rem]">
      <div role={notice.tone === "crit" ? "alert" : "status"} className={cx("flex items-center gap-3 rounded-xl border border-line px-4 py-3 shadow-[0_16px_40px_-12px_rgb(0_0_0/0.6)]", notice.tone === "crit" ? "bg-crit-bg" : "bg-ok-bg")}>
        <Icon name={notice.tone === "crit" ? "xCircle" : "checkCircle"} size={20} className={notice.tone === "crit" ? "text-crit" : "text-ok"} />
        <p className="flex-1 font-medium text-ink">{notice.text}</p>
        <button
          type="button"
          className="btn btn-ghost btn-sm min-h-11 min-w-11"
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

export default function LandingPage() {
  useTitle("Welcome");
  return (
    <div className="relative min-h-dvh">
      <a
        href="#landing-main"
        className="sr-only rounded-lg bg-accent px-4 py-2 font-medium text-on-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50"
      >
        Skip to content
      </a>
      {/* The header is drawn over the top of the hero frame; it comes first in the document. */}
      <div className="absolute inset-x-0 top-0 z-30">
        <div className="mx-auto max-w-[96rem] p-2 sm:p-4 lg:p-6">
          <Header />
        </div>
      </div>
      <main id="landing-main" tabIndex={-1} className="outline-none">
        <Notice />
        <Opening />
        <Tools />
        <Process />
        <Trust />
        <Closing />
      </main>
      <SiteFooter />
    </div>
  );
}
