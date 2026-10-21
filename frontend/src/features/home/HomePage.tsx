// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Link } from "react-router";
import { dashboardPath, landingPath } from "../../app/paths";
import { runsLocallyOnly, tools, workspace } from "../../app/tools";
import { Icon, type IconName } from "../../components/Icon";
import { PageHeader } from "../../components/ui";
import { isHosted } from "../../lib/mode";
import { useEngine } from "../../lib/queries";
import { useTitle } from "../../lib/useTitle";

function Tile({ to, name, icon, badge }: { to: string; name: string; icon: IconName; badge?: string | undefined }) {
  return (
    <li className="flex">
      <Link
        to={to}
        className="launcher-tile glass group flex w-full flex-col items-center justify-center gap-3.5 rounded-2xl px-3 pt-7 pb-6 text-center"
      >
        <span className="launcher-icon relative flex size-16 items-center justify-center rounded-2xl sm:size-[4.5rem]">
          <Icon name={icon} size={30} className="text-accent-text" />
        </span>
        <span className="relative text-[0.9375rem] leading-snug font-semibold text-ink sm:text-base">{name}</span>
        {badge ? " " : null}
        {badge ? (
          <span className="absolute top-2.5 right-2.5 z-10 inline-flex items-center gap-1 rounded-full border border-line bg-inset px-2 py-0.5 text-[0.6875rem] leading-4 font-medium text-ink-2">
            <Icon name="terminal" size={11} />
            {badge}
          </span>
        ) : null}
      </Link>
    </li>
  );
}

export default function HomePage() {
  useTitle("");
  const hosted = isHosted();
  const engine = useEngine();
  const engineOff = !hosted && engine.data?.reachable === false;

  return (
    <>
      <PageHeader
        title="Your security workbench"
        lede={
          hosted
            ? "Pick a tool. The email, web and file checks run right here; tools marked Run locally come with a step-by-step guide for your own computer."
            : "Pick a tool. Everything runs on this computer, and every result starts with a plain answer with the evidence one click away."
        }
      />

      <section aria-labelledby="launcher-title">
        <h2 id="launcher-title" className="sr-only">
          Tools
        </h2>
        <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3 sm:gap-4">
          {tools.map((tool) => (
            <Tile
              key={tool.page}
              to={dashboardPath(tool.page)}
              name={tool.name}
              icon={tool.icon}
              badge={hosted && runsLocallyOnly(tool) ? "Run locally" : undefined}
            />
          ))}
          {workspace.map((item) => (
            <Tile key={item.page} to={dashboardPath(item.page)} name={item.name} icon={item.icon} />
          ))}
        </ul>
      </section>

      {engineOff ? (
        <p className="mt-8 rounded-xl border border-line bg-inset px-4 py-3 text-ink-2">
          Detection repair needs the pinned engine: start it with{" "}
          <code className="rounded bg-surface px-1.5 py-0.5 text-ink">kestrix detect engine-up</code> (needs Docker).
          Everything else works without it.
        </p>
      ) : null}

      <p className="mt-12 border-t border-line pt-5 text-[0.8125rem] text-ink-3">
        Detection repair is a research workbench by Ruthvik Bandari. Forensics is adapted from the CyberSafeX Detection
        Suite; Bitcoin quantum risk from BitShield (MIT Bitcoin Expo 2026, Team ACE).{" "}
        <Link to={landingPath()} className="link">
          How Kestrix works
        </Link>
      </p>
    </>
  );
}
