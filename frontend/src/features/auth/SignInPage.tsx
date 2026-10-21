// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useSearchParams } from "react-router";
import { dashboardPath, safeNext } from "../../app/paths";
import { BrandMark } from "../../components/BrandMark";
import { CodeRain } from "../../components/CodeRain";
import { PublicShell } from "../../components/PublicShell";
import { useTitle } from "../../lib/useTitle";
import { AuthCard } from "./AuthCard";

export default function SignInPage() {
  useTitle("Sign in");
  const [params] = useSearchParams();
  const next = safeNext(params.get("next")) ?? dashboardPath();
  const intent = params.get("intent") === "signup" ? "signup" : "login";

  return (
    <PublicShell action={false} backdrop={<CodeRain />}>
      <BrandMark size={40} />
      <h1 className="display mt-5 text-[clamp(2rem,6vw,2.75rem)]">Sign in to Kestrix</h1>
      <AuthCard next={next} initialIntent={intent} className="mt-7" />
    </PublicShell>
  );
}
