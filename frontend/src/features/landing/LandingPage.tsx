// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import type { MouseEvent } from "react";
import { Link } from "react-router";
import { DASHBOARD_PATH } from "../../app/paths";
import { BrandMark } from "../../components/BrandMark";
import { HoloGlobe } from "../../components/HoloGlobe";
import { Icon } from "../../components/Icon";
import { Reveal } from "../../components/Reveal";
import { ThemeSwitch } from "../../components/ThemeSwitch";
import { TiltCard } from "../../components/TiltCard";
import { tones } from "../../components/tone";
import { cx } from "../../components/ui";
import { scrollBehavior } from "../../lib/motion";
import { site } from "../../lib/site";
import { useTitle } from "../../lib/useTitle";
import { features, flows, principles, type Flow } from "./content";

/** Smooth-scroll to an in-page section and move focus there, so keyboard users land on it too. */
function jumpTo(event: MouseEvent<HTMLAnchorElement>, id: string) {
  const target = document.getElementById(id);
  if (!target) return;
  event.preventDefault();
  target.scrollIntoView({ behavior: scrollBehavior(), block: "start" });
  target.focus({ preventScroll: true });
  history.replaceState(null, "", `#${id}`);
}

function SectionHeading({ id, eyebrow, title, lede }: { id: string; eyebrow: string; title: string; lede: string }) {
  return (
    <Reveal className="mx-auto mb-10 max-w-3xl text-center sm:mb-14">
      <p className="eyebrow justify-center">{eyebrow}</p>
      <h2 id={id} tabIndex={-1} className="display mt-3 text-[clamp(2rem,5.2vw,3.5rem)] outline-none">
        {title}
      </h2>
      <p className="mx-auto mt-4 max-w-[60ch] text-lg text-ink-2">{lede}</p>
    </Reveal>
  );
}

function Header({ signInUrl }: { signInUrl: string | null }) {
  const links = [
    { id: "features", label: "What you get" },
    { id: "how-it-works", label: "How it works" },
    { id: "trust", label: "Why trust it" },
  ];
  return (
    <header className="veil-rail sticky top-0 z-30 border-b border-line">
      <div className="mx-auto flex h-16 max-w-[76rem] items-center justify-between gap-4 px-4 sm:px-6">
        <Link to={DASHBOARD_PATH} className="flex items-center gap-2.5 rounded-md" aria-label="Kestrix dashboard">
          <BrandMark size={28} />
          <span className="text-lg font-bold tracking-[-0.02em] text-ink">Kestrix</span>
        </Link>
        <nav aria-label="Sections" className="hidden md:block">
          <ul className="flex gap-1">
            {links.map((link) => (
              <li key={link.id}>
                <a
                  href={`#${link.id}`}
                  onClick={(event) => {
                    jumpTo(event, link.id);
                  }}
                  className="inline-flex min-h-10 items-center rounded-lg px-3 text-[0.9375rem] font-medium text-ink-2 transition-colors hover:bg-inset hover:text-ink"
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex items-center gap-2">
          {/* Hosted accounts: rendered only when a sign-in URL is configured (lib/site.ts). */}
          {signInUrl ? (
            <a href={signInUrl} className="btn btn-secondary btn-sm min-h-10">
              Sign in
            </a>
          ) : null}
          <Link to={DASHBOARD_PATH} className="btn btn-primary btn-sm min-h-10">
            <span className="hidden sm:inline">Open the dashboard</span>
            <span className="sm:hidden">Dashboard</span>
            <Icon name="arrowRight" size={15} />
          </Link>
        </div>
      </div>
    </header>
  );
}

function Hero({ signInUrl }: { signInUrl: string | null }) {
  return (
    <section aria-labelledby="hero-title" className="relative isolate overflow-hidden">
      <div className="holo-grid -z-10" aria-hidden="true" />
      <div className="mx-auto grid max-w-[76rem] items-center gap-6 px-4 pt-10 pb-16 sm:px-6 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] lg:gap-10 lg:pt-16 lg:pb-24">
        <div className="relative z-10 text-center lg:text-left">
          <p className="eyebrow glass inline-flex rounded-full px-3.5 py-1.5 normal-case tracking-normal">
            <span className="size-2 rounded-full bg-[conic-gradient(var(--h1),var(--h2),var(--h3),var(--h4),var(--h1))]" aria-hidden="true" />
            <span className="text-[0.8125rem] font-semibold">Local-first security workbench</span>
          </p>
          <h1 id="hero-title" className="display holo-text holo-text-live mt-6 pb-2 text-[clamp(4.25rem,15vw,10rem)] leading-[0.9]">
            Kestrix
          </h1>
          <p className="display mx-auto mt-4 max-w-[18ch] text-[clamp(1.75rem,4.2vw,3rem)] leading-[1.05] text-ink lg:mx-0">
            Security checks that show their work.
          </p>
          <p className="mx-auto mt-5 max-w-[46ch] text-lg text-ink-2 sm:text-xl lg:mx-0">
            A security workbench that explains every answer. Runs on your computer.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3 lg:justify-start">
            <Link to={DASHBOARD_PATH} className="btn btn-primary btn-lg">
              Open the dashboard
              <Icon name="arrowRight" size={18} />
            </Link>
            <a
              href="#how-it-works"
              className="btn btn-secondary btn-lg"
              onClick={(event) => {
                jumpTo(event, "how-it-works");
              }}
            >
              How it works
            </a>
            {/* Hosted accounts: a "Sign in" button appears here once signInUrl is configured. */}
            {signInUrl ? (
              <a href={signInUrl} className="btn btn-ghost btn-lg">
                Sign in
              </a>
            ) : null}
          </div>
          <dl className="mx-auto mt-10 grid max-w-xl grid-cols-3 gap-3 text-left lg:mx-0">
            {[
              { k: "Tools", v: "5", d: "in one workbench" },
              { k: "Uploads", v: "0", d: "in local mode" },
              { k: "License", v: "Apache", d: "2.0, open source" },
            ].map((fact) => (
              <div key={fact.k} className="glass rounded-xl px-3 py-3 sm:px-4">
                <dt className="text-[0.75rem] font-semibold tracking-[0.08em] text-ink-3 uppercase">{fact.k}</dt>
                <dd className="mt-1">
                  <span className="display holo-text block text-2xl sm:text-3xl">{fact.v}</span>
                  <span className="block text-[0.8125rem] text-ink-2">{fact.d}</span>
                </dd>
              </div>
            ))}
          </dl>
        </div>
        <div className="relative mx-auto w-full max-w-[34rem]">
          <HoloGlobe />
          <ul className="absolute inset-x-0 bottom-1 flex flex-wrap justify-center gap-2 text-[0.8125rem] font-medium">
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
    </section>
  );
}

function Features() {
  return (
    <section aria-labelledby="features" className="mx-auto max-w-[76rem] scroll-mt-20 px-4 py-20 sm:px-6">
      <SectionHeading
        id="features"
        eyebrow="What you get"
        title="Five tools. A plain answer from each."
        lede="Every result starts with what it means for you, and the technical evidence is always one click away."
      />
      <ul className="grid gap-4 md:grid-cols-6">
        {features.map((feature, index) => (
          <li key={feature.name} className={cx("flex", index < 2 ? "md:col-span-3" : "md:col-span-2")}>
            <Reveal className="flex w-full" delay={index * 70}>
              <TiltCard className="flex w-full flex-col rounded-2xl p-6 sm:p-7">
                <span className="relative flex size-12 items-center justify-center rounded-xl bg-[linear-gradient(135deg,var(--btn-a),var(--btn-b))] text-white shadow-[0_8px_24px_-8px_var(--glow)]">
                  <Icon name={feature.icon} size={24} />
                </span>
                <h3 className="relative mt-5 text-xl font-bold tracking-[-0.02em]">{feature.name}</h3>
                <p className="relative mt-1 text-[0.75rem] font-semibold tracking-[0.1em] text-accent-text uppercase">
                  Protects you from
                </p>
                <p className="relative mt-2 flex-1 text-ink-2">{feature.protects}</p>
                <Link to={feature.path} className="link relative mt-5 inline-flex w-fit items-center gap-1.5 font-semibold">
                  Open {feature.name}
                  <Icon name="arrowRight" size={15} />
                </Link>
              </TiltCard>
            </Reveal>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Animated arrow between two steps: above the step on phones, to its left from md up. */
function Connector() {
  return (
    <div
      className="absolute -top-7 left-1/2 flex h-6 w-12 -translate-x-1/2 items-center justify-center text-ink-3 md:top-1/2 md:-left-8 md:h-4 md:w-8 md:translate-x-0 md:-translate-y-1/2"
      aria-hidden="true"
    >
      <svg viewBox="0 0 48 16" className="h-4 w-10 rotate-90 md:w-8 md:rotate-0">
        <line
          x1="2"
          y1="8"
          x2="40"
          y2="8"
          stroke="currentColor"
          strokeWidth="2"
          strokeDasharray="4 4"
          strokeLinecap="round"
          className="[animation:flow-dash_1.2s_linear_infinite]"
        />
        <path d="M38 3l7 5-7 5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

function StepLabel({ n, children }: { n: number; children: string }) {
  return (
    <p className="flex items-center gap-2 text-[0.75rem] font-semibold tracking-[0.1em] text-ink-3 uppercase">
      <span className="step-dot size-6 text-[0.75rem]" aria-hidden="true">
        {n}
      </span>
      {children}
    </p>
  );
}

function FlowRow({ flow, index }: { flow: Flow; index: number }) {
  const tone = tones[flow.verdict.tone];
  return (
    <Reveal delay={60}>
      <article className="glass rounded-2xl p-5 sm:p-7" aria-labelledby={`flow-${String(index)}`}>
        <header className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <h3 id={`flow-${String(index)}`} className="flex items-center gap-3 text-xl font-bold tracking-[-0.02em]">
            <span className="flex size-10 items-center justify-center rounded-xl bg-accent-soft text-accent-text">
              <Icon name={flow.icon} size={20} />
            </span>
            {flow.name}
          </h3>
          <p className="flex items-center gap-2 text-[0.875rem] text-ink-2">
            <Icon name={flow.note.icon} size={16} className="flex-none text-ink-3" />
            {flow.note.text}
          </p>
        </header>
        <ol className="grid gap-8 md:grid-cols-[minmax(0,0.9fr)_minmax(0,1.25fr)_minmax(0,1fr)] md:items-stretch">
          <li className="rounded-xl border border-line bg-inset p-4">
            <StepLabel n={1}>Input</StepLabel>
            <div className="mt-4 flex items-center gap-4">
              <span className="relative flex size-14 flex-none items-center justify-center rounded-2xl border border-line bg-surface text-accent-text [animation:drop-in_3.6s_var(--ease-out-expo)_infinite]">
                <Icon name={flow.icon} size={26} />
                <span className="absolute -right-2 -bottom-2 rounded-md bg-[linear-gradient(120deg,var(--btn-a),var(--btn-b))] px-1.5 py-0.5 font-mono text-[0.6875rem] text-white">
                  {flow.input.token}
                </span>
              </span>
              <div className="min-w-0">
                <p className="font-semibold text-ink">{flow.input.title}</p>
                <p className="text-[0.875rem] text-ink-2">{flow.input.text}</p>
              </div>
            </div>
          </li>
          <li className="relative rounded-xl border border-line bg-inset p-4">
            <Connector />
            <span className="pointer-events-none absolute inset-0 overflow-hidden rounded-xl" aria-hidden="true">
              <span className="absolute inset-x-0 top-0 h-1/3 bg-[linear-gradient(180deg,transparent,color-mix(in_oklch,var(--h1)_16%,transparent),transparent)] opacity-0 motion-safe:opacity-100 motion-safe:[animation:scan-beam_3.2s_linear_infinite]" />
            </span>
            <StepLabel n={2}>Checks</StepLabel>
            <ul className="mt-3 flex flex-wrap gap-1.5">
              {flow.checks.map((check, k) => (
                <li
                  key={check}
                  className="inline-flex items-center gap-1.5 rounded-full bg-surface px-2.5 py-1 text-[0.8125rem] text-ink shadow-[inset_0_0_0_1px_var(--line)] [animation:chip-scan_3.2s_ease-in-out_infinite]"
                  style={{ animationDelay: `${String(k * 380)}ms` }}
                >
                  <Icon name="check" size={13} className="text-ok" />
                  {check}
                </li>
              ))}
            </ul>
          </li>
          <li className="relative rounded-xl border border-line bg-inset p-4">
            <Connector />
            <StepLabel n={3}>Explained verdict</StepLabel>
            <div className="mt-3">
              <span className={cx("inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[0.8125rem] font-semibold", tone.soft)}>
                <Icon name={tone.icon} size={14} />
                {flow.verdict.label}
              </span>
              <ul className="mt-2.5 space-y-1.5">
                {flow.verdict.lines.map((line) => (
                  <li key={line} className="flex gap-2 text-[0.875rem] text-ink-2">
                    <Icon name="info" size={14} className="mt-1 flex-none text-ink-3" />
                    {line}
                  </li>
                ))}
              </ul>
              <p className="mt-2.5 text-[0.75rem] text-ink-3">Example result</p>
            </div>
          </li>
        </ol>
      </article>
    </Reveal>
  );
}

function HowItWorksSection() {
  return (
    <section aria-labelledby="how-it-works" className="mx-auto max-w-[76rem] scroll-mt-20 px-4 py-20 sm:px-6">
      <SectionHeading
        id="how-it-works"
        eyebrow="How it works"
        title="Input, checks, an answer you can verify."
        lede="Each tool runs a fixed set of checks you can read in the docs, and every finding tells you which check raised it and why."
      />
      <div className="space-y-5">
        {flows.map((flow, index) => (
          <FlowRow key={flow.name} flow={flow} index={index} />
        ))}
      </div>
    </section>
  );
}

function Trust() {
  return (
    <section aria-labelledby="trust" className="mx-auto max-w-[76rem] scroll-mt-20 px-4 py-20 sm:px-6">
      <SectionHeading
        id="trust"
        eyebrow="Why trust it"
        title="Built so you can check it."
        lede="These are properties of the code today, each documented in the security model. No certifications or accuracy figures are claimed."
      />
      <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {principles.map((principle, index) => (
          <li key={principle.title} className="flex">
            <Reveal className="flex w-full" delay={(index % 4) * 70}>
              <div className="glass w-full rounded-2xl p-5">
                <span className="flex size-10 items-center justify-center rounded-xl bg-accent-soft text-accent-text">
                  <Icon name={principle.icon} size={20} />
                </span>
                <h3 className="mt-4 text-base font-bold">{principle.title}</h3>
                <p className="mt-1.5 text-[0.9375rem] text-ink-2">{principle.text}</p>
              </div>
            </Reveal>
          </li>
        ))}
      </ul>
    </section>
  );
}

function FinalCta() {
  return (
    <section aria-labelledby="start-title" className="mx-auto max-w-[76rem] px-4 pb-20 sm:px-6">
      <Reveal>
        <div className="glass relative overflow-hidden rounded-3xl px-6 py-12 text-center sm:px-12 sm:py-16">
          <div
            className="pointer-events-none absolute -inset-1/2 -z-10 bg-[conic-gradient(from_90deg,color-mix(in_oklch,var(--h1)_22%,transparent),color-mix(in_oklch,var(--h2)_22%,transparent),color-mix(in_oklch,var(--h3)_22%,transparent),color-mix(in_oklch,var(--h4)_16%,transparent),color-mix(in_oklch,var(--h1)_22%,transparent))] blur-3xl"
            aria-hidden="true"
          />
          <h2 id="start-title" className="display text-[clamp(2rem,5vw,3.25rem)]">
            Start with one command.
          </h2>
          <p className="mx-auto mt-4 max-w-[52ch] text-lg text-ink-2">
            Install the package, run <code className="rounded-md bg-inset px-2 py-0.5 text-[0.95em] text-ink">kestrix dashboard</code>, and
            everything runs on this computer.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link to={DASHBOARD_PATH} className="btn btn-primary btn-lg">
              Open the dashboard
              <Icon name="arrowRight" size={18} />
            </Link>
            <a href={site.docsUrl} className="btn btn-secondary btn-lg">
              Read the docs
              <Icon name="external" size={16} />
            </a>
          </div>
        </div>
      </Reveal>
    </section>
  );
}

function Footer() {
  return (
    <footer className="veil-rail border-t border-line">
      <div className="mx-auto grid max-w-[76rem] gap-8 px-4 py-10 sm:px-6 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
        <div>
          <p className="flex items-center gap-2.5">
            <BrandMark size={26} />
            <span className="text-lg font-bold tracking-[-0.02em]">Kestrix by Ruthvik Bandari</span>
          </p>
          <p className="mt-3 max-w-[60ch] text-[0.875rem] text-ink-2">
            Licensed under the Apache License 2.0. Use Kestrix only on systems, files and websites you own or are
            authorized to assess.
          </p>
          <ul className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-[0.875rem]">
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

export default function LandingPage({ signInUrl = site.signInUrl }: { signInUrl?: string | null }) {
  useTitle("Welcome");
  return (
    <div className="relative isolate min-h-dvh">
      <a
        href="#landing-main"
        className="sr-only rounded-lg bg-accent px-4 py-2 font-medium text-on-accent focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50"
      >
        Skip to content
      </a>
      <Header signInUrl={signInUrl} />
      <main id="landing-main" tabIndex={-1} className="outline-none">
        <Hero signInUrl={signInUrl} />
        <Features />
        <HowItWorksSection />
        <Trust />
        <FinalCta />
      </main>
      <Footer />
    </div>
  );
}
