// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { dashboardPath } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { ErrorState, PageHeader, Panel, Skeleton, Verdict } from "../../components/ui";
import { api } from "../../lib/api";
import { keys } from "../../lib/queries";
import { useTitle } from "../../lib/useTitle";

export default function MigrationPage() {
  const { addressType = "" } = useParams();
  useTitle(`${addressType.toUpperCase()} migration plan`);
  const plan = useQuery({ queryKey: keys.migration(addressType), queryFn: () => api.migration(addressType) });

  return (
    <>
      <Link to={dashboardPath("bitcoin")} className="link mb-4 inline-flex items-center gap-1 text-[0.875rem]">
        <Icon name="arrowLeft" size={14} />
        Bitcoin quantum risk
      </Link>
      <PageHeader
        title={`Migration plan: ${addressType.toUpperCase()}`}
        lede="How to move coins from this address type to one whose public key stays hidden until you spend."
      />
      {plan.isPending ? (
        <div className="space-y-3">
          <Skeleton className="h-16" />
          <Skeleton className="h-40" />
        </div>
      ) : plan.isError ? (
        <ErrorState error={plan.error} />
      ) : (
        <div className="grid items-start gap-x-10 gap-y-8 xl:grid-cols-[minmax(0,40rem)_minmax(0,1fr)]">
          <div className="min-w-0 max-w-[68ch] space-y-8">
            <Verdict
              tone={plan.data.urgency === "now" ? "crit" : "med"}
              title={plan.data.urgency === "now" ? "Move these coins now" : "Move these coins before you next spend from the address"}
            >
              <p>{plan.data.summary}</p>
            </Verdict>
            <section aria-labelledby="steps-title">
              <h2 id="steps-title" className="mb-3 text-xl font-semibold tracking-[-0.015em]">
                Steps
              </h2>
              <ol className="space-y-3">
                {plan.data.steps.map((step, i) => (
                  <li key={i} className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-3">
                    <span className="flex size-7 items-center justify-center rounded-full border border-line bg-surface text-[0.8125rem] font-semibold text-accent-text">
                      {i + 1}
                    </span>
                    <p className="pt-0.5">{step}</p>
                  </li>
                ))}
              </ol>
            </section>
          </div>
          <div className="min-w-0 space-y-6 xl:sticky xl:top-6">
            {plan.data.cautions.length > 0 ? (
              <Panel as="section" className="space-y-3">
                <h2 id="cautions-title" className="text-lg font-semibold tracking-[-0.01em]">
                  Be careful
                </h2>
                <ul className="space-y-2" aria-labelledby="cautions-title">
                  {plan.data.cautions.map((caution, i) => (
                    <li key={i} className="flex gap-2 text-ink-2">
                      <Icon name="alert" size={16} className="mt-1 flex-none text-high" />
                      {caution}
                    </li>
                  ))}
                </ul>
              </Panel>
            ) : null}
            <p className="rounded-xl bg-inset px-4 py-3 text-ink-2">
              Do every step in your own wallet software. Kestrix never needs, and will never ask for, your seed phrase or
              private keys.
            </p>
          </div>
        </div>
      )}
    </>
  );
}
