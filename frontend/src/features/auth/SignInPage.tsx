// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { Link, useSearchParams } from "react-router";
import { dashboardPath, PRIVACY_PATH, safeNext, TERMS_PATH } from "../../app/paths";
import { BrandMark } from "../../components/BrandMark";
import { Icon } from "../../components/Icon";
import { PublicShell } from "../../components/PublicShell";
import { ErrorState, Skeleton } from "../../components/ui";
import { useMe, useProviders } from "../../lib/queries";
import type { AuthProvider } from "../../lib/types";
import { useTitle } from "../../lib/useTitle";
import { ProviderMark, providerName } from "./providers";

/** The server's sign-in start; a full page load, since it redirects to the provider. */
export function loginHref(provider: AuthProvider, next: string): string {
  return `/api/auth/login/${provider}?next=${encodeURIComponent(next)}`;
}

function ProviderButtons({ next }: { next: string }) {
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
      {providers.data.providers.map((provider) => (
        <li key={provider}>
          <a href={loginHref(provider, next)} className="btn btn-secondary btn-lg w-full justify-center">
            <ProviderMark provider={provider} />
            Continue with {providerName[provider]}
          </a>
        </li>
      ))}
    </ul>
  );
}

export default function SignInPage() {
  useTitle("Sign in");
  const [params] = useSearchParams();
  const next = safeNext(params.get("next")) ?? dashboardPath();
  const me = useMe();
  const user = me.data?.signed_in ? me.data.user : null;

  return (
    <PublicShell>
      <div className="glass rounded-3xl px-6 py-9 sm:px-9">
        <div className="relative">
          <BrandMark size={40} />
          <h1 className="display mt-5 text-[clamp(2rem,6vw,2.75rem)]">Sign in to Kestrix</h1>
          <p className="mt-2 text-ink-2">Use the website check, file and link forensics, and the email check in your browser. Free.</p>

          <div className="mt-7">
            {user ? (
              <div className="grid gap-3">
                <p className="text-ink-2">
                  You are signed in as <span className="font-semibold text-ink">{user.display_name || user.email}</span>.
                </p>
                <Link to={next} className="btn btn-primary btn-lg w-full justify-center">
                  Open the dashboard
                  <Icon name="arrowRight" size={18} />
                </Link>
              </div>
            ) : (
              <ProviderButtons next={next} />
            )}
          </div>

          <section aria-labelledby="signin-privacy" className="mt-8 border-t border-line pt-6">
            <h2 id="signin-privacy" className="flex items-center gap-2 font-semibold">
              <Icon name="lock" size={17} className="text-h1" />
              Your privacy, in short
            </h2>
            <ul className="mt-3 grid gap-2 text-[0.9375rem] text-ink-2">
              <li>Files and emails you upload are analyzed in memory and never stored.</li>
              <li>We keep only your email address and display name from your sign-in.</li>
              <li>You can delete your account, and everything we hold about you, at any time.</li>
            </ul>
            <p className="mt-4 text-[0.875rem] text-ink-3">
              By continuing you agree to the{" "}
              <Link className="link" to={TERMS_PATH}>
                terms of use
              </Link>
              . Read the{" "}
              <Link className="link" to={PRIVACY_PATH}>
                privacy notice
              </Link>
              .
            </p>
          </section>
        </div>
      </div>
    </PublicShell>
  );
}
