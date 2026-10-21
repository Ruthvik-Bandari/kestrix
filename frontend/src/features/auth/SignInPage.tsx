// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useSearchParams } from "react-router";
import { dashboardPath, safeNext } from "../../app/paths";
import { BrandMark } from "../../components/BrandMark";
import { Icon } from "../../components/Icon";
import { PublicShell } from "../../components/PublicShell";
import { useTitle } from "../../lib/useTitle";
import { AuthCard } from "./AuthCard";

export default function SignInPage() {
  useTitle("Sign in");
  const [params] = useSearchParams();
  const next = safeNext(params.get("next")) ?? dashboardPath();

  return (
    <PublicShell>
      <BrandMark size={40} />
      <h1 className="display mt-5 text-[clamp(2rem,6vw,2.75rem)]">Sign in to Kestrix</h1>
      <p className="mt-2 text-ink-2">Use the website check, file and link forensics, and the email check in your browser. Free.</p>

      <AuthCard next={next} className="mt-7" />

      <section aria-labelledby="signin-privacy" className="glass mt-6 rounded-3xl px-5 py-5 sm:px-6">
        <div className="relative">
          <h2 id="signin-privacy" className="flex items-center gap-2 font-semibold">
            <Icon name="lock" size={17} className="text-h1" />
            Your privacy, in short
          </h2>
          <ul className="mt-3 grid gap-2 text-[0.9375rem] text-ink-2">
            <li>Uploaded files and emails are never stored; your reports are kept for 30 days so you can see your history, and you can turn this off.</li>
            <li>We keep only your email address and display name from your sign-in.</li>
            <li>You can delete your account at any time; it is removed right away, and backup snapshots expire within 14 days.</li>
          </ul>
        </div>
      </section>
    </PublicShell>
  );
}
