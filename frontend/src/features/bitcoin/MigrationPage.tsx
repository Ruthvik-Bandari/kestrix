import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { Icon } from "../../components/Icon";
import { ErrorState, PageHeader, Skeleton, Verdict } from "../../components/ui";
import { api } from "../../lib/api";
import { keys } from "../../lib/queries";
import { useTitle } from "../../lib/useTitle";

export default function MigrationPage() {
  const { addressType = "" } = useParams();
  useTitle(`${addressType.toUpperCase()} migration plan`);
  const plan = useQuery({ queryKey: keys.migration(addressType), queryFn: () => api.migration(addressType) });

  return (
    <>
      <Link to="/bitcoin" className="link mb-4 inline-flex items-center gap-1 text-[0.875rem]">
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
        <div className="max-w-3xl space-y-8">
          <Verdict
            tone={plan.data.urgency === "now" ? "crit" : "med"}
            title={plan.data.urgency === "now" ? "Move these coins now" : "Move these coins before you next spend from the address"}
          >
            <p>{plan.data.summary}</p>
          </Verdict>
          <section aria-labelledby="steps-title">
            <h2 id="steps-title" className="mb-3 text-lg font-semibold">
              Steps
            </h2>
            <ol className="space-y-3">
              {plan.data.steps.map((step, i) => (
                <li key={i} className="flex gap-3">
                  <span className="flex size-7 flex-none items-center justify-center rounded-full bg-inset text-[0.8125rem] font-semibold text-ink-2">
                    {i + 1}
                  </span>
                  <p className="pt-0.5">{step}</p>
                </li>
              ))}
            </ol>
          </section>
          {plan.data.cautions.length > 0 ? (
            <section aria-labelledby="cautions-title">
              <h2 id="cautions-title" className="mb-3 text-lg font-semibold">
                Be careful
              </h2>
              <ul className="space-y-2">
                {plan.data.cautions.map((caution, i) => (
                  <li key={i} className="flex gap-2 text-ink-2">
                    <Icon name="alert" size={16} className="mt-1 flex-none text-high" />
                    {caution}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
          <p className="rounded-lg bg-inset px-4 py-3 text-ink-2">
            Do every step in your own wallet software. Kestrix never needs, and will never ask for, your seed phrase or
            private keys.
          </p>
        </div>
      )}
    </>
  );
}
