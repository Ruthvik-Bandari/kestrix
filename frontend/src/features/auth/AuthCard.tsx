// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useId, useRef, useState, type KeyboardEvent } from "react";
import { Link } from "react-router";
import { PRIVACY_PATH, TERMS_PATH } from "../../app/paths";
import { Icon } from "../../components/Icon";
import { cx, ErrorState, Skeleton } from "../../components/ui";
import { useMe, useProviders } from "../../lib/queries";
import type { AuthProvider } from "../../lib/types";
import { ProviderMark, providerName } from "./providers";

export type Intent = "login" | "signup";

/** The server's sign-in start; a full page load, since it redirects to the provider. */
export function loginHref(provider: AuthProvider, next: string, intent: Intent = "login"): string {
  const params = new URLSearchParams({ next });
  if (intent === "signup") params.set("intent", "signup");
  return `/api/auth/login/${provider}?${params.toString()}`;
}

const TABS: { intent: Intent; label: string }[] = [
  { intent: "login", label: "Log in" },
  { intent: "signup", label: "Sign up" },
];

function ProviderButtons({ next, intent, enabled }: { next: string; intent: Intent; enabled: boolean }) {
  const providers = useProviders();
  if (providers.isPending) {
    return (
      <div className="grid gap-3" aria-hidden="true">
        <Skeleton className="h-12 w-full rounded-xl" />
        <Skeleton className="h-12 w-full rounded-xl" />
      </div>
    );
  }
  if (providers.isError) return <ErrorState error={providers.error} />;
  if (providers.data.providers.length === 0) {
    return <p className="rounded-xl bg-inset px-4 py-3 text-ink-2">Sign-in is not available on this server yet.</p>;
  }
  return (
    <ul className="grid gap-3">
      {providers.data.providers.map((provider) => {
        const label = `Continue with ${providerName[provider]}`;
        return (
          <li key={provider}>
            {enabled ? (
              <a href={loginHref(provider, next, intent)} className="btn btn-secondary btn-lg w-full justify-center">
                <ProviderMark provider={provider} />
                {label}
              </a>
            ) : (
              // Disabled until the terms are accepted; a link cannot be disabled, a button can.
              <button type="button" disabled className="btn btn-secondary btn-lg w-full justify-center">
                <ProviderMark provider={provider} />
                {label}
              </button>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/**
 * Hosted mode: Log in / Sign up with Google or GitHub, on the landing hero and on /signin.
 * Sign up needs the terms checkbox first and tells the server (`intent=signup`), which records when
 * the terms were accepted. A signed-in visitor sees a way into the dashboard instead.
 */
export function AuthCard({ next, className }: { next: string; className?: string }) {
  const me = useMe();
  const [intent, setIntent] = useState<Intent>("login");
  const [agreed, setAgreed] = useState(false);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const id = useId();
  const tabId = (value: Intent) => `${id}-tab-${value}`;
  const panelId = `${id}-panel`;
  const checkboxId = `${id}-terms`;

  function select(index: number) {
    const tab = TABS[(index + TABS.length) % TABS.length];
    if (!tab) return;
    setIntent(tab.intent);
    tabRefs.current[TABS.indexOf(tab)]?.focus();
  }

  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    const current = TABS.findIndex((tab) => tab.intent === intent);
    const moves: Record<string, number> = { ArrowRight: current + 1, ArrowLeft: current - 1, Home: 0, End: TABS.length - 1 };
    const target = moves[event.key];
    if (target === undefined) return;
    event.preventDefault();
    select(target);
  }

  const user = me.data?.signed_in ? me.data.user : null;

  return (
    <section aria-labelledby={`${id}-title`} className={cx("glass rounded-3xl p-5 sm:p-6", className)}>
      <div className="relative">
        {me.isPending ? (
          <div className="grid gap-3" aria-hidden="true">
            <Skeleton className="h-7 w-2/3 rounded-lg" />
            <Skeleton className="h-12 w-full rounded-xl" />
            <Skeleton className="h-12 w-full rounded-xl" />
          </div>
        ) : user ? (
          <div className="grid gap-4">
            <h2 id={`${id}-title`} className="text-xl font-semibold text-ink">
              Welcome back
            </h2>
            <p className="text-ink-2">
              You are signed in as <span className="font-semibold text-ink">{user.display_name || user.email}</span>.
            </p>
            <Link to={next} className="btn btn-primary btn-lg w-full justify-center">
              Open the dashboard
              <Icon name="arrowRight" size={18} />
            </Link>
          </div>
        ) : (
          <>
            <h2 id={`${id}-title`} className="text-xl font-semibold text-ink">
              Use Kestrix in your browser
            </h2>
            <p className="mt-1 text-[0.9375rem] text-ink-2">Free. Sign in with an account you already have.</p>
            <div
              role="tablist"
              aria-label="Log in or sign up"
              className="mt-5 grid grid-cols-2 gap-1 rounded-xl bg-inset p-1"
            >
              {TABS.map((tab, index) => {
                const selected = tab.intent === intent;
                return (
                  <button
                    key={tab.intent}
                    ref={(node) => {
                      tabRefs.current[index] = node;
                    }}
                    type="button"
                    role="tab"
                    id={tabId(tab.intent)}
                    aria-selected={selected}
                    aria-controls={panelId}
                    tabIndex={selected ? 0 : -1}
                    onClick={() => {
                      setIntent(tab.intent);
                    }}
                    onKeyDown={onKeyDown}
                    className={cx(
                      "min-h-10 rounded-lg px-3 text-[0.9375rem] font-semibold transition-colors",
                      selected ? "bg-surface-solid text-ink shadow-[0_1px_2px_rgb(0_0_0/0.12)]" : "text-ink-2 hover:text-ink",
                    )}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </div>
            <div role="tabpanel" id={panelId} aria-labelledby={tabId(intent)} className="mt-5 grid gap-4">
              {intent === "signup" ? (
                <div className="flex items-start gap-3 rounded-xl bg-inset px-3.5 py-3">
                  <input
                    id={checkboxId}
                    type="checkbox"
                    required
                    checked={agreed}
                    onChange={(event) => {
                      setAgreed(event.target.checked);
                    }}
                    className="check mt-0.5 flex-none"
                  />
                  <label htmlFor={checkboxId} className="text-[0.9375rem] text-ink-2">
                    I agree to the{" "}
                    <Link className="link" to={TERMS_PATH}>
                      Terms of use
                    </Link>{" "}
                    and have read the{" "}
                    <Link className="link" to={PRIVACY_PATH}>
                      Privacy notice
                    </Link>
                  </label>
                </div>
              ) : null}
              <ProviderButtons next={next} intent={intent} enabled={intent === "login" || agreed} />
              <p className="text-[0.8125rem] text-ink-3">
                {intent === "login"
                  ? "New here? Choose Sign up. Files and emails you check are never stored."
                  : "Already have an account? Signing up again just signs you in."}
              </p>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
