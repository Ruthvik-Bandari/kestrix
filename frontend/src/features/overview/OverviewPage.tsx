import type { ReactNode } from "react";
import { Link } from "react-router";
import { Icon, type IconName } from "../../components/Icon";
import { PageHeader, StatusPill } from "../../components/ui";
import type { Tone } from "../../components/tone";
import { useEngine, useSettings } from "../../lib/queries";
import { useTitle } from "../../lib/useTitle";

interface Module {
  name: string;
  icon: IconName;
  protects: string;
  status: { tone: Tone; text: string };
  actions: { to: string; label: string; primary?: boolean }[];
}

function ModuleRow({ module }: { module: Module }) {
  return (
    <li className="grid gap-4 py-6 first:pt-0 last:pb-0 md:grid-cols-[minmax(0,1fr)_auto] md:items-center md:gap-8">
      <div className="flex gap-4">
        <span className="flex size-10 flex-none items-center justify-center rounded-lg border border-line bg-rail text-ink-2">
          <Icon name={module.icon} size={20} />
        </span>
        <div className="min-w-0">
          <h3 className="text-base font-semibold">{module.name}</h3>
          <p className="mt-1 max-w-[62ch] text-ink-2">{module.protects}</p>
          <div className="mt-3">
            <StatusPill tone={module.status.tone}>{module.status.text}</StatusPill>
          </div>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 pl-14 md:justify-end md:pl-0">
        {module.actions.map((action) => (
          <Link key={action.to} to={action.to} className={action.primary ? "btn btn-primary" : "btn btn-secondary"}>
            {action.label}
            {action.primary ? <Icon name="arrowRight" size={16} /> : null}
          </Link>
        ))}
      </div>
    </li>
  );
}

function Credit({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <dt className="font-medium text-ink">{title}</dt>
      <dd className="mt-0.5 text-ink-2">{children}</dd>
    </div>
  );
}

export default function OverviewPage() {
  useTitle("");
  const engine = useEngine();
  const settings = useSettings();
  const engineUp = engine.data?.reachable === true;
  const keyOn = settings.data?.anthropic_key_configured === true;

  const engineStatus: Module["status"] = engine.isPending
    ? { tone: "neutral", text: "Checking the detection engine…" }
    : engineUp
      ? { tone: "ok", text: `Engine running · Elasticsearch ${engine.data?.version ?? ""}` }
      : { tone: "high", text: "Engine off · start it to run repairs" };

  const modules: Module[] = [
    {
      name: "Detection repair",
      icon: "wrench",
      protects:
        "Protects you from detection rules that silently stop catching attacks, or bury your team in false alarms. It finds the cause and proposes a fix that has been tested on labeled events.",
      status: engineStatus,
      actions: [
        { to: "/detect", label: "Try a sample case", primary: true },
        { to: "/detect?tab=custom", label: "Repair your own rule" },
      ],
    },
    {
      name: "Web check",
      icon: "globe",
      protects:
        "Protects you from running a website with missing HTTPS protections, an expiring certificate or unsafe browser security headers.",
      status: { tone: "ok", text: "Ready · sends one request to the site you choose" },
      actions: [{ to: "/webcheck", label: "Check a website", primary: true }],
    },
    {
      name: "Forensics",
      icon: "search",
      protects:
        "Protects you from files that are not what their name claims, hidden encrypted payloads, photos that reveal where they were taken, and look-alike phishing links.",
      status: { tone: "ok", text: "Ready · works offline" },
      actions: [
        { to: "/forensics", label: "Analyze a file", primary: true },
        { to: "/forensics?tab=url", label: "Check a link" },
      ],
    },
    {
      name: "Bitcoin quantum risk",
      icon: "bitcoin",
      protects:
        "Protects your coins from future quantum computers by flagging addresses whose public key is already visible on the blockchain, with a step-by-step plan to move them.",
      status: keyOn
        ? { tone: "ok", text: "Ready · AI guardian set up" }
        : { tone: "ok", text: "Ready · works offline unless you turn on lookups" },
      actions: [{ to: "/bitcoin", label: "Scan addresses", primary: true }],
    },
  ];

  return (
    <>
      <PageHeader
        title="Your security workbench"
        lede="Four tools that run on this computer. Each result starts with a plain answer, and the technical evidence is always one click away."
        aside={
          <>
            <StatusPill tone={engine.isPending ? "neutral" : engineUp ? "ok" : "high"}>
              {engine.isPending ? "Engine…" : engineUp ? "Engine running" : "Engine off"}
            </StatusPill>
            <StatusPill tone={keyOn ? "ok" : "neutral"}>{keyOn ? "AI key set" : "No AI key"}</StatusPill>
          </>
        }
      />

      <section aria-labelledby="modules-title">
        <h2 id="modules-title" className="sr-only">
          Modules
        </h2>
        <ul className="divide-y divide-line">
          {modules.map((module) => (
            <ModuleRow key={module.name} module={module} />
          ))}
        </ul>
      </section>

      {!engineUp && !engine.isPending ? (
        <p className="mt-8 rounded-lg bg-inset px-4 py-3 text-ink-2">
          To run detection repairs, start the pinned engine with{" "}
          <code className="rounded bg-surface px-1.5 py-0.5 text-ink">kestrix detect engine-up</code> (needs Docker).
          Everything else works without it.
        </p>
      ) : null}

      <section aria-labelledby="about-title" className="mt-14 border-t border-line pt-8">
        <h2 id="about-title" className="text-lg font-semibold">
          About Kestrix
        </h2>
        <p className="mt-2 max-w-[68ch] text-ink-2">
          Kestrix is local-first: the dashboard and its API run on your machine and only reach the network when a tool
          says so. Results are deterministic and come with the evidence that produced them.
        </p>
        <dl className="mt-6 grid gap-5 sm:grid-cols-3">
          <Credit title="Detection repair">
            Research workbench by <span className="text-ink">Ruthvik Bandari</span>.
          </Credit>
          <Credit title="Forensics">Adapted from the CyberSafeX Detection Suite.</Credit>
          <Credit title="Bitcoin quantum risk">Adapted from BitShield (MIT Bitcoin Expo 2026, Team ACE).</Credit>
        </dl>
        <p className="mt-6 text-[0.8125rem] text-ink-3">
          API schema for scripting: <a className="link" href="/api/openapi.json">/api/openapi.json</a>
        </p>
      </section>
    </>
  );
}
