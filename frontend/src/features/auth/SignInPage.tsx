// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useSearchParams } from "react-router";
import { dashboardPath, safeNext } from "../../app/paths";
import { BrandMark } from "../../components/BrandMark";
import { Beams, CircuitDial } from "../../components/Circuit";
import { PublicShell } from "../../components/PublicShell";
import { useTitle } from "../../lib/useTitle";
import { AuthCard } from "./AuthCard";

export default function SignInPage() {
  useTitle("Sign in");
  const [params] = useSearchParams();
  const next = safeNext(params.get("next")) ?? dashboardPath();
  const intent = params.get("intent") === "signup" ? "signup" : "login";

  return (
    <PublicShell action={false} backdrop={
        <div className="pointer-events-none absolute inset-2 sm:inset-4 lg:inset-6" aria-hidden="true">
          <div className="frame-soft h-full">
            <Beams />
            <CircuitDial className="absolute bottom-0 left-1/2 h-[16.875rem] w-[56.25rem] max-w-none -translate-x-1/2 overflow-visible opacity-70 sm:h-[22.5rem] sm:w-[75rem]" />
          </div>
        </div>
      }>
      <BrandMark size={40} />
      <h1 className="display mt-5 text-[clamp(2rem,6vw,2.75rem)]">Sign in to Kestrix</h1>
      <AuthCard next={next} initialIntent={intent} className="mt-7" />
    </PublicShell>
  );
}
